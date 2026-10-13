"""Rooms: the in-process replica of one design's Y document and everything that happens around it.

A `Room` is an actor: connections and the channel layer put work in its inbox and one task processes it in
order, so no two operations on the same document ever overlap. Updates are durable (appended to the database)
before they are relayed.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import logging
import os
import re
import socket
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, TypeVar

from asgiref.sync import sync_to_async
from channels.layers import BaseChannelLayer, InMemoryChannelLayer, get_channel_layer
from django.conf import settings
from django.db import close_old_connections, connection

from . import crdt, engine, protocol, store
from .limits import block_user

log = logging.getLogger("doory.collab")

T = TypeVar("T")

WRITER_ROLES = frozenset({"owner", "edit"})
MAX_CONTROLLED_CLIENTS = 4
MAX_AWARENESS_BYTES = 2048
OUTBOX_LIMIT = 512
INBOX_LIMIT = 2000
HEARTBEAT_SECONDS = 10.0
AWARENESS_EXPIRY_SECONDS = 60.0
COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}$")
PALETTE = (
    "#e11d48", "#2563eb", "#059669", "#d97706", "#7c3aed", "#0891b2",
    "#db2777", "#4d7c0f", "#c2410c", "#4338ca", "#0f766e", "#a21caf",
)  # fmt: skip

CLOSE_FOR_REASON = {
    "link_revoked": 4403,
    "link_expired": 4403,
    "role_changed": 4403,
    "account_disabled": 4403,
    "session_ended": 4401,
    "design_trashed": 4404,
    "design_deleted": 4404,
}


def db(function: Callable[..., T]) -> Callable[..., Awaitable[T]]:
    """Run a synchronous store function on the shared database thread with a usable connection."""

    @functools.wraps(function)
    def fresh(*args: Any) -> T:
        if not connection.in_atomic_block:
            close_old_connections()
        return function(*args)

    return sync_to_async(fresh, thread_sensitive=True)


class RoomUnavailable(Exception):
    """The room cannot be served by this process right now; `reason` goes into the close frame."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class Transport(Protocol):
    """What a room needs from a connection."""

    async def send_bytes(self, data: bytes) -> None: ...

    async def send_text(self, text: str) -> None: ...

    async def close(self, code: int, reason: str) -> None: ...


@dataclass(eq=False)
class Member:
    """One live connection inside a room."""

    id: str
    user_id: uuid.UUID
    name: str
    avatar_url: str | None
    role: str
    link_id: uuid.UUID | None
    session_key: str | None
    connection_id: uuid.UUID
    transport: Transport
    last_seen: float = 0.0
    controlled: set[int] = field(default_factory=set)
    outbox: asyncio.Queue = field(default_factory=lambda: asyncio.Queue(maxsize=OUTBOX_LIMIT))
    pump: asyncio.Task | None = None
    notified_read_only: bool = False
    closing: bool = False
    introduced: set[int] = field(default_factory=set)  # client ids this connection has put into the document

    @property
    def can_write(self) -> bool:
        return self.role in WRITER_ROLES


@dataclass
class AwarenessSlot:
    clock: int
    state: str
    owner: str | None  # member id; None for a client connected to another process
    seen: float


@dataclass
class Item:
    kind: str
    member: Member | None = None
    payload: Any = None


class VersionTracker:
    """Which update batches this replica applied: `contiguous` is the highest v with 1..v all applied."""

    def __init__(self, loaded: int) -> None:
        self.contiguous = loaded
        self.latest = loaded
        self._ahead: set[int] = set()

    def add(self, version: int) -> None:
        self.latest = max(self.latest, version)
        if version > self.contiguous:
            self._ahead.add(version)
        while self.contiguous + 1 in self._ahead:
            self.contiguous += 1
            self._ahead.discard(self.contiguous)

    def reset(self, version: int) -> None:
        self.contiguous = self.latest = version
        self._ahead.clear()


def color_for(user_id: uuid.UUID) -> str:
    return PALETTE[int(hashlib.sha256(user_id.bytes).hexdigest(), 16) % len(PALETTE)]


def _text(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


class Room:
    def __init__(
        self,
        registry: RoomRegistry,
        design_id: uuid.UUID,
        opened: engine.OpenedDoc,
        loaded: store.LoadedState,
    ) -> None:
        self.registry = registry
        self.design_id = design_id
        self.doc = opened.doc
        self.sv = opened.sv
        self.size = opened.size
        self.title = loaded.title
        self.revision = loaded.revision
        self.versions = VersionTracker(loaded.version)
        self.rows_since_compact = len(loaded.updates)
        self.members: dict[str, Member] = {}
        self.awareness: dict[int, AwarenessSlot] = {}
        self.inbox: asyncio.Queue[Item] = asyncio.Queue(maxsize=INBOX_LIMIT)
        self.group = f"doory.collab.design.{design_id}"
        self.channel = ""
        self.closing = False
        self.closed = asyncio.Event()
        self.dirty = loaded.version > loaded.flushed_version
        self.last_editor_id: uuid.UUID | None = None
        self._tasks: list[asyncio.Task] = []
        self._background: set[asyncio.Future] = set()
        self._flush_task: asyncio.Task | None = None
        self._last_flush = 0.0
        self._last_recheck = 0.0
        self._behind = 0
        self._warned: set[str] = set()
        self.budget = engine.UpdateBudget()

    # ------------------------------------------------------------------ lifecycle

    @property
    def layer(self) -> BaseChannelLayer:
        return self.registry.layer

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._last_flush = self._last_recheck = loop.time()
        self.channel = await self.layer.new_channel()
        await self.layer.group_add(self.group, self.channel)
        self._tasks = [
            asyncio.create_task(self._run(), name=f"room-{self.design_id}"),
            asyncio.create_task(self._listen(), name=f"room-listen-{self.design_id}"),
            asyncio.create_task(self._ticker(), name=f"room-tick-{self.design_id}"),
        ]
        await self._publish("collab.awareness_query")

    def join(self, member: Member) -> bool:
        """Add a connection. False when the room is just closing (the caller opens a fresh one)."""
        if self.closing:
            return False
        self.members[member.id] = member
        member.last_seen = asyncio.get_running_loop().time()
        member.pump = asyncio.create_task(self._pump(member), name=f"member-{member.id}")
        self._enqueue(Item("welcome", member))
        return True

    def leave(self, member: Member) -> None:
        if self.members.pop(member.id, None) is None:
            return
        member.closing = True
        if member.pump is not None:
            member.pump.cancel()
        removed = [client for client in member.controlled if client in self.awareness]
        for client in removed:
            slot = self.awareness.pop(client)
            self._enqueue(Item("awareness_gone", member, (client, slot.clock + 1)))
        if not self.members:
            self.closing = True
            self._enqueue(Item("shutdown"))

    def submit(self, member: Member, frame: protocol.Frame) -> Awaitable[None]:
        return self.inbox.put(Item("frame", member, frame))

    def request_flush(self, member: Member) -> None:
        """A writer asked for the design to be saved now (before it creates a version, for example)."""
        self._enqueue(Item("flush", member))

    def _enqueue(self, item: Item) -> None:
        """Queue work from synchronous code; when the inbox is full the item waits in a task instead."""
        try:
            self.inbox.put_nowait(item)
        except asyncio.QueueFull:
            self.registry.counters["inbox_full"] += 1
            self._spawn(self.inbox.put(item))

    def _spawn(self, work: Awaitable[Any]) -> None:
        """Run `work` in the background, keeping a reference so it is not collected half-way."""
        task = asyncio.ensure_future(work)
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    def close_all(self, code: int, reason: str) -> None:
        for member in list(self.members.values()):
            self.kick(member, code, reason)

    # ------------------------------------------------------------------ outgoing

    def kick(self, member: Member, code: int, reason: str) -> None:
        if member.closing:
            return
        log.info("kick design=%s user=%s code=%s reason=%s", self.design_id, member.user_id, code, reason)
        self.registry.counters[f"closed_{code}"] += 1
        self.leave(member)
        self._spawn(self._close(member, code, reason))

    @staticmethod
    async def _close(member: Member, code: int, reason: str) -> None:
        try:
            await member.transport.close(code, reason)
        except Exception:  # the socket is already gone
            log.debug("close failed", exc_info=True)

    def _send(self, member: Member, kind: str, payload: bytes | str) -> None:
        if member.closing:
            return
        try:
            member.outbox.put_nowait((kind, payload))
        except asyncio.QueueFull:
            self.registry.counters["slow_consumers"] += 1
            self.kick(member, 1013, "slow_consumer")

    def _send_bytes_others(self, sender: Member | None, frame: bytes) -> None:
        for member in list(self.members.values()):
            if member is not sender:
                self._send(member, "b", frame)

    def _send_text_all(self, payload: dict, *, writers_only: bool = False) -> None:
        text = _text(payload)
        for member in list(self.members.values()):
            if member.can_write or not writers_only:
                self._send(member, "t", text)

    async def _pump(self, member: Member) -> None:
        try:
            while True:
                kind, payload = await member.outbox.get()
                if kind == "b":
                    await member.transport.send_bytes(payload)
                else:
                    await member.transport.send_text(payload)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.debug("send failed design=%s member=%s", self.design_id, member.id, exc_info=True)
            self.leave(member)

    async def _publish(self, message_type: str, **payload: Any) -> None:
        try:
            await self.layer.group_send(
                self.group, {"type": message_type, "origin": self.registry.instance, **payload}
            )
        except Exception:
            self.registry.counters["publish_failed"] += 1
            log.warning("publish failed design=%s type=%s", self.design_id, message_type, exc_info=True)

    # ------------------------------------------------------------------ tasks

    async def _listen(self) -> None:
        try:
            while True:
                message = await self.layer.receive(self.channel)
                if message.get("origin") != self.registry.instance:
                    await self.inbox.put(Item("remote", payload=message))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("layer listener stopped design=%s", self.design_id)
            self.registry.counters["layer_failed"] += 1

    async def _ticker(self) -> None:
        interval = min(
            1.0, settings.REALTIME_RECHECK_SECONDS / 2, settings.REALTIME_FLUSH_INTERVAL_SECONDS / 2
        )
        try:
            while True:
                await asyncio.sleep(max(interval, 0.01))
                self._enqueue(Item("tick"))
        except asyncio.CancelledError:
            raise

    async def _run(self) -> None:
        try:
            while True:
                first = await self.inbox.get()
                items = [first]
                while len(items) < 200:
                    try:
                        items.append(self.inbox.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                if await self._process(items):
                    return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("room crashed design=%s", self.design_id)
            await self._fail("internal_error")

    # ------------------------------------------------------------------ processing

    async def _process(self, items: list[Item]) -> bool:
        """Handle a batch in order; consecutive writer updates share one apply and one database write."""
        pending: list[tuple[Member, bytes]] = []
        for item in items:
            if self.closed.is_set():
                return True
            if (
                item.kind == "frame"
                and isinstance(item.payload, protocol.SyncFrame)
                and item.payload.kind != protocol.SYNC_STEP1
            ):
                member = item.member
                if member is None or member.closing:
                    continue
                if not member.can_write:
                    self._deny_write(member)
                    continue
                pending.append((member, item.payload.payload))
                continue
            if pending:
                await self._commit(pending)
                pending = []
            if await self._dispatch(item):
                return True
        if pending:
            await self._commit(pending)
        return False

    async def _dispatch(self, item: Item) -> bool:
        member = item.member
        if item.kind == "welcome" and member is not None:
            await self._welcome(member)
        elif item.kind == "frame" and member is not None and not member.closing:
            await self._frame(member, item.payload)
        elif item.kind == "awareness_gone" and member is not None:
            await self._announce_gone(*item.payload)
        elif item.kind == "remote":
            await self._remote(item.payload)
        elif item.kind == "tick":
            await self._tick()
        elif item.kind == "flush":
            await self._flush_now()
        elif item.kind == "repair":
            await self._repair()
        elif item.kind == "shutdown":
            await self._shutdown()
            return True
        return False

    def _deny_write(self, member: Member) -> None:
        self.registry.counters["dropped_read_only"] += 1
        if not member.notified_read_only:
            member.notified_read_only = True
            self._send(member, "b", protocol.permission_denied_frame("read_only"))
        log.info("drop design=%s user=%s role=%s", self.design_id, member.user_id, member.role)

    async def _welcome(self, member: Member) -> None:
        if member.closing:
            return
        vector = await crdt.run(engine.state_vector, self.doc)
        self._send(member, "b", protocol.sync_frame(protocol.SYNC_STEP1, vector))
        entries = self._awareness_entries()
        if entries:
            self._send(member, "b", protocol.awareness_frame(protocol.encode_awareness(entries)))

    async def _frame(self, member: Member, frame: protocol.Frame) -> None:
        if isinstance(frame, protocol.SyncFrame):  # only step 1 reaches here; updates are batched
            try:
                protocol.decode_state_vector(frame.payload)
                diff = await crdt.run(engine.diff_since, self.doc, frame.payload)
            except (protocol.ProtocolError, ValueError):
                self.kick(member, 4400, "bad_frame")
                return
            except crdt.EngineFailure:
                log.exception("engine failure design=%s", self.design_id)
                await self._fail("internal_error")
                return
            self._send(member, "b", protocol.sync_frame(protocol.SYNC_STEP2, diff))
        elif isinstance(frame, protocol.AwarenessFrame):
            await self._client_awareness(member, frame.payload)
        else:
            entries = self._awareness_entries()
            if entries:
                self._send(member, "b", protocol.awareness_frame(protocol.encode_awareness(entries)))

    # ------------------------------------------------------------------ updates

    async def _commit(self, pending: list[tuple[Member, bytes]]) -> None:
        updates = [data for _, data in pending]
        try:
            result = await crdt.run(
                engine.apply_client_updates,
                self.doc,
                self.sv,
                updates,
                self.size,
                self.budget,
                [member.introduced for member, _ in pending],
            )
        except crdt.EngineFailure:
            log.exception("engine failure design=%s", self.design_id)
            await self._fail("internal_error")
            return
        self.sv, self.size = result.sv, result.size
        applied: list[tuple[Member, bytes]] = []
        for (member, data), outcome in zip(pending, result.outcomes, strict=True):
            if outcome.kind == "rejected":
                self.registry.counters[f"rejected_{outcome.reason}"] += 1
                log.warning(
                    "reject design=%s user=%s reason=%s detail=%s",
                    self.design_id,
                    member.user_id,
                    outcome.reason,
                    outcome.detail,
                )
                if outcome.reason == "update_too_costly":
                    await db(block_user)(member.user_id)
                self.kick(member, 4413 if outcome.reason == "document_too_large" else 4400, outcome.reason)
            elif outcome.kind == "applied":
                applied.append((member, data))
        if applied and result.merged is not None:
            await self._persist(applied, result.merged, applied[-1][0].user_id)
        if result.poisoned:
            # What was stored before this batch is clean; the live state is not, so rebuild it from the store.
            await self._fail("update_too_costly")
            return
        if result.pages_gone:
            self._enqueue(Item("repair"))

    async def _persist(
        self, applied: list[tuple[Member | None, bytes]], merged: bytes, editor: uuid.UUID | None
    ) -> None:
        try:
            version = await db(store.append_update)(self.design_id, merged, editor)
        except Exception:
            log.exception("persist failed design=%s", self.design_id)
            await self._fail("persist_failed")
            return
        self.versions.add(version)
        self.dirty = True
        self.rows_since_compact += 1
        if editor is not None:
            self.last_editor_id = editor
        for sender, data in applied:
            self._send_bytes_others(sender, protocol.sync_frame(protocol.SYNC_UPDATE, data))
            await self._publish("collab.update", update=data, version=version)
        if self.rows_since_compact >= settings.REALTIME_COMPACT_AFTER_UPDATES:
            await self._compact()

    async def _remote(self, message: dict) -> None:
        kind = message.get("type")
        if kind == "collab.update":
            try:
                self.sv = await crdt.run(engine.apply_trusted, self.doc, message["update"])
            except (ValueError, TypeError, RuntimeError, crdt.EngineFailure):
                log.warning("remote update failed design=%s", self.design_id, exc_info=True)
                await self._resync()
                return
            self.versions.add(int(message.get("version", 0)))
            self.dirty = True
            self._send_bytes_others(None, protocol.sync_frame(protocol.SYNC_UPDATE, message["update"]))
        elif kind == "collab.awareness":
            try:
                entries = protocol.decode_awareness(message["payload"])
            except protocol.ProtocolError:
                return
            self._apply_remote_awareness(entries)
        elif kind == "collab.awareness_query":
            own = [e for e in self._awareness_entries() if self.awareness[e.client_id].owner is not None]
            if own:
                await self._publish("collab.awareness", payload=protocol.encode_awareness(own))
        elif kind == "collab.replaced":
            self.revision = int(message.get("revision", self.revision))
            self._send_text_all({"type": "replaced", "reason": "version_restored", "revision": self.revision})
        elif kind == "collab.title":
            self.title = str(message.get("title", self.title))
            self._send_text_all({"type": "title", "title": self.title})
        elif kind == "collab.recheck":
            await self._recheck()

    # ------------------------------------------------------------------ awareness

    def _awareness_entries(self) -> list[protocol.AwarenessEntry]:
        return [
            protocol.AwarenessEntry(client, slot.clock, slot.state) for client, slot in self.awareness.items()
        ]

    def _identity(self, member: Member, state: dict) -> dict:
        claimed = state.get("user") if isinstance(state.get("user"), dict) else {}
        color = claimed.get("color")
        return {
            **state,
            "user": {
                "id": str(member.user_id),
                "name": member.name,
                "avatarUrl": member.avatar_url,
                "color": color
                if isinstance(color, str) and COLOR_PATTERN.match(color)
                else color_for(member.user_id),
                "role": member.role,
            },
        }

    async def _client_awareness(self, member: Member, payload: bytes) -> None:
        try:
            entries = protocol.decode_awareness(payload)
            now = asyncio.get_running_loop().time()
            accepted: list[protocol.AwarenessEntry] = []
            for entry in entries:
                slot = self.awareness.get(entry.client_id)
                if slot is not None and slot.owner != member.id:
                    continue
                if (
                    slot is None
                    and entry.client_id not in member.controlled
                    and len(member.controlled) >= MAX_CONTROLLED_CLIENTS
                ):
                    continue
                state = protocol.parse_awareness_state(entry.state)
                if state is None:
                    if slot is not None and entry.clock >= slot.clock:
                        del self.awareness[entry.client_id]
                        member.controlled.discard(entry.client_id)
                        accepted.append(protocol.AwarenessEntry(entry.client_id, entry.clock, "null"))
                    continue
                if slot is not None and entry.clock <= slot.clock:
                    continue
                text = _text(self._identity(member, state))
                if len(text.encode("utf-8")) > MAX_AWARENESS_BYTES:
                    self.registry.counters["awareness_dropped"] += 1
                    continue
                member.controlled.add(entry.client_id)
                self.awareness[entry.client_id] = AwarenessSlot(entry.clock, text, member.id, now)
                accepted.append(protocol.AwarenessEntry(entry.client_id, entry.clock, text))
        except (protocol.ProtocolError, RecursionError):
            self.kick(member, 4400, "bad_frame")
            return
        if accepted:
            encoded = protocol.encode_awareness(accepted)
            self._send_bytes_others(member, protocol.awareness_frame(encoded))
            await self._publish("collab.awareness", payload=encoded)

    def _apply_remote_awareness(self, entries: list[protocol.AwarenessEntry]) -> None:
        now = asyncio.get_running_loop().time()
        accepted: list[protocol.AwarenessEntry] = []
        for entry in entries:
            slot = self.awareness.get(entry.client_id)
            if slot is not None and slot.owner is not None:
                continue
            if entry.state == "null":
                if slot is not None:
                    del self.awareness[entry.client_id]
                    accepted.append(entry)
                continue
            if slot is not None and entry.clock < slot.clock:
                continue
            self.awareness[entry.client_id] = AwarenessSlot(entry.clock, entry.state, None, now)
            accepted.append(entry)
        if accepted:
            self._send_bytes_others(None, protocol.awareness_frame(protocol.encode_awareness(accepted)))

    async def _announce_gone(self, client: int, clock: int) -> None:
        encoded = protocol.encode_awareness([protocol.AwarenessEntry(client, clock, "null")])
        self._send_bytes_others(None, protocol.awareness_frame(encoded))
        await self._publish("collab.awareness", payload=encoded)

    # ------------------------------------------------------------------ periodic work

    async def _tick(self) -> None:
        loop = asyncio.get_running_loop()
        now = loop.time()
        for member in list(self.members.values()):
            if now - member.last_seen > settings.REALTIME_IDLE_TIMEOUT_SECONDS:
                self.kick(member, 4408, "idle")
        for client, slot in list(self.awareness.items()):
            if slot.owner is None and now - slot.seen > AWARENESS_EXPIRY_SECONDS:
                del self.awareness[client]
        if now - self._last_recheck >= settings.REALTIME_RECHECK_SECONDS:
            self._last_recheck = now
            await self._recheck()
        if self.dirty and now - self._last_flush >= settings.REALTIME_FLUSH_INTERVAL_SECONDS:
            self._last_flush = now
            await self._start_flush()

    async def _recheck(self) -> None:
        checks = [
            store.MemberCheck(m.id, m.user_id, m.role, m.link_id, m.session_key)
            for m in self.members.values()
            if not m.closing
        ]
        report = await db(store.check_access)(self.design_id, checks)
        for member_id, reason in report.closed.items():
            member = self.members.get(member_id)
            if member is not None:
                self.registry.counters[f"access_{reason}"] += 1
                self.kick(member, CLOSE_FOR_REASON.get(reason, 4403), reason)
        if report.title and report.title != self.title:
            self.title = report.title
            self._send_text_all({"type": "title", "title": self.title})
        if not self.members:
            return
        await self._maybe_replace()
        await self._maybe_resync()

    async def _maybe_replace(self) -> None:
        ticket = await db(store.read_replacement)(self.design_id)
        if ticket is None:
            return
        try:
            delta = await crdt.run(engine.make_replacement, self.doc, ticket.document)
        except (ValueError, TypeError, RuntimeError, crdt.EngineFailure):
            log.exception("replacement failed design=%s", self.design_id)
            return
        version = await db(store.commit_replacement)(self.design_id, ticket, delta)
        if version is None:
            return
        self.sv, self.size = await crdt.run(engine.apply_replacement, self.doc, delta)
        self.versions.add(version)
        self.dirty = False
        self.revision = ticket.revision
        self.registry.counters["replaced"] += 1
        log.info("replace design=%s revision=%s", self.design_id, ticket.revision)
        self._send_bytes_others(None, protocol.sync_frame(protocol.SYNC_UPDATE, delta))
        self._send_text_all({"type": "replaced", "reason": "version_restored", "revision": ticket.revision})
        await self._publish("collab.update", update=delta, version=version)
        await self._publish("collab.replaced", revision=ticket.revision)

    async def _maybe_resync(self) -> None:
        stored = await db(store.current_version)(self.design_id)
        if stored is not None and stored > self.versions.contiguous:
            self._behind += 1
            if self._behind >= 2:
                self._behind = 0
                await self._resync()
        else:
            self._behind = 0

    async def _resync(self) -> None:
        """Re-read the stored state (a layer message was lost), merge it in and relay the difference."""
        current = await db(store.load_current)(self.design_id)
        version = await db(store.current_version)(self.design_id)
        if current is None or version is None:
            return
        before = await crdt.run(engine.state_vector, self.doc)
        delta, self.sv, self.size = await crdt.run(engine.resync, self.doc, current[0], current[1], before)
        self.versions.reset(version)
        self.registry.counters["resyncs"] += 1
        log.warning("resync design=%s version=%s", self.design_id, version)
        if delta:
            self._send_bytes_others(None, protocol.sync_frame(protocol.SYNC_UPDATE, delta))
        self.dirty = True

    async def _compact(self) -> None:
        source = await db(store.read_for_compaction)(self.design_id)
        if source is None:
            self.rows_since_compact = 0
            return
        merged = await crdt.run(engine.merge_state, source.snapshot, source.updates, kind=crdt.READ)
        if await db(store.apply_compaction)(self.design_id, source, merged):
            self.registry.counters["compactions"] += 1
            log.info("compact design=%s rows=%s", self.design_id, len(source.updates))
        self.rows_since_compact = 0

    # ------------------------------------------------------------------ saving

    async def _flush_now(self) -> None:
        if self._flush_task is not None and not self._flush_task.done():
            await asyncio.gather(self._flush_task, return_exceptions=True)
        if self.dirty:
            await self._start_flush()
            if self._flush_task is not None:
                await asyncio.gather(self._flush_task, return_exceptions=True)
        else:
            self._send_text_all({"type": "saved", "revision": self.revision, "at": _now_iso()})

    async def _start_flush(self) -> None:
        if self._flush_task is not None and not self._flush_task.done():
            return
        state = await crdt.run(engine.full_state, self.doc)
        version, editor = self.versions.latest, self.last_editor_id
        self.dirty = False
        self._flush_task = asyncio.create_task(self._flush(state, version, editor))

    async def _flush(self, state: bytes, version: int, editor: uuid.UUID | None) -> None:
        try:
            conversion = await crdt.run(engine.convert, state, kind=crdt.READ)
            if conversion.document is None:
                self.dirty = True
                self.registry.counters["flush_invalid"] += 1
                if conversion.anomalies.no_pages:
                    self._enqueue(Item("repair"))
                if conversion.problem not in self._warned:
                    self._warned.add(conversion.problem)
                    self._send_text_all(
                        {"type": "warning", "code": "document_invalid", "message": conversion.problem},
                        writers_only=True,
                    )
                log.warning("flush refused design=%s problem=%s", self.design_id, conversion.problem)
                return
            self._warned.clear()
            result = await db(store.flush_document)(self.design_id, conversion.document, version, editor)
        except Exception:
            self.dirty = True
            self.registry.counters["flush_failed"] += 1
            log.exception("flush failed design=%s", self.design_id)
            return
        if result.saved:
            self.revision = result.revision
            self.registry.counters["flushes"] += 1
            log.info("flush design=%s revision=%s", self.design_id, result.revision)
            self._send_text_all(
                {"type": "saved", "revision": result.revision, "at": _now_iso()},
            )
            if conversion.anomalies:
                self._enqueue(Item("repair"))
        elif result.reason == "external_change":
            self.dirty = True

    async def _repair(self) -> None:
        try:
            delta = await crdt.run(engine.repair, self.doc)
        except (ValueError, TypeError, RuntimeError, crdt.EngineFailure):
            log.exception("repair failed design=%s", self.design_id)
            return
        if delta:
            self.registry.counters["repairs"] += 1
            self.sv = await crdt.run(lambda: protocol.decode_state_vector(self.doc.get_state(), limit=None))
            await self._persist([(None, delta)], delta, None)

    # ------------------------------------------------------------------ closing

    async def _fail(self, reason: str) -> None:
        """Drop the room: close every connection (they reconnect and rebuild from the database)."""
        self.closing = True
        self.close_all(1011, reason)
        await self._teardown(flush=False)

    async def _shutdown(self) -> None:
        await self._teardown(flush=True)

    async def _teardown(self, *, flush: bool) -> None:
        try:
            current = asyncio.current_task()
            for task in self._tasks:
                if task is not current:
                    task.cancel()
            if self._flush_task is not None and not self._flush_task.done():
                await asyncio.gather(self._flush_task, return_exceptions=True)
            if flush and self.dirty:
                try:
                    state = await crdt.run(engine.full_state, self.doc)
                    await self._flush(state, self.versions.latest, self.last_editor_id)
                except Exception:
                    log.exception("final flush failed design=%s", self.design_id)
            if flush and self.rows_since_compact:
                try:
                    await self._compact()
                except Exception:
                    log.exception("final compaction failed design=%s", self.design_id)
            try:
                await self.layer.group_discard(self.group, self.channel)
            except Exception:
                log.debug("group_discard failed", exc_info=True)
        finally:
            self.registry.forget(self)
            self.closed.set()

    async def finish(self) -> None:
        """Wait until the room has shut down (used by tests and process shutdown)."""
        await self.closed.wait()


def _now_iso() -> str:
    from django.utils import timezone

    return timezone.now().isoformat()


class RoomRegistry:
    """All rooms of one server process, plus the process-wide counters and heartbeat."""

    def __init__(self, instance: str | None = None, layer: BaseChannelLayer | None = None) -> None:
        self.instance = instance or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._layer = layer
        self.rooms: dict[uuid.UUID, Room] = {}
        self.counters: Counter[str] = Counter()
        self.pending: Counter[object] = Counter()  # logins in progress per user
        self._opening: dict[uuid.UUID, asyncio.Lock] = {}
        self._heartbeat: asyncio.Task | None = None

    @property
    def layer(self) -> BaseChannelLayer:
        if self._layer is None:
            self._layer = get_channel_layer()
        if self._layer is None:
            raise RoomUnavailable("realtime_disabled")
        return self._layer

    @property
    def shared_layer(self) -> bool:
        return not isinstance(self.layer, InMemoryChannelLayer)

    @property
    def process_key(self) -> str:
        """`host:pid` of this process (instances of one process share it, e.g. in tests)."""
        return self.instance.rsplit(":", 1)[0]

    async def acquire(self, design_id: uuid.UUID) -> Room:
        """The running room of a design, opening it (from the database) when this process has none."""
        while True:
            room = self.rooms.get(design_id)
            if room is not None and not room.closing:
                return room
            if room is not None:
                await room.closed.wait()
                continue
            lock = self._opening.setdefault(design_id, asyncio.Lock())
            async with lock:
                if design_id in self.rooms:
                    continue
                opened = await self._open(design_id)
                self.rooms[design_id] = opened
                self._ensure_heartbeat()
                return opened

    async def _open(self, design_id: uuid.UUID) -> Room:
        others = await db(store.other_instance_serves)(design_id, self.instance)
        foreign = [name for name in others if name.rsplit(":", 1)[0] != self.process_key]
        if foreign and not self.shared_layer:
            log.error(
                "refusing room design=%s: other processes %s serve it without a shared channel layer",
                design_id,
                foreign,
            )
            raise RoomUnavailable("shared_layer_required")
        loaded = await db(store.load_or_init)(design_id, self.instance, engine.build_snapshot)
        try:
            opened = await crdt.run(engine.open_doc, loaded.snapshot, loaded.updates)
        except (ValueError, TypeError, RuntimeError, crdt.EngineFailure):
            # Unreadable stored state: start over from the saved design rather than lock everyone out.
            log.exception("stored state unreadable, rebuilding it from the design design=%s", design_id)
            self.counters["state_rebuilt"] += 1
            await db(store.reset_state)(design_id, engine.build_snapshot)
            loaded = await db(store.load_or_init)(design_id, self.instance, engine.build_snapshot)
            opened = await crdt.run(engine.open_doc, loaded.snapshot, loaded.updates)
        room = Room(self, design_id, opened, loaded)
        await room.start()
        return room

    def forget(self, room: Room) -> None:
        if self.rooms.get(room.design_id) is room:
            del self.rooms[room.design_id]
        self._opening.pop(room.design_id, None)

    def _ensure_heartbeat(self) -> None:
        if self._heartbeat is None or self._heartbeat.done():
            self._heartbeat = asyncio.create_task(self._beat(), name="collab-heartbeat")

    async def _beat(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            await self.heartbeat()

    async def heartbeat(self) -> None:
        try:
            ids = [member.connection_id for room in self.rooms.values() for member in room.members.values()]
            await db(store.heartbeat)(self.instance, self.shared_layer, dict(self.counters), ids)
        except Exception:
            log.exception("heartbeat failed")

    async def shutdown(self) -> None:
        """Close every room cleanly (flushing them) and forget this process."""
        if self._heartbeat is not None:
            self._heartbeat.cancel()
        for room in list(self.rooms.values()):
            room.close_all(1012, "server_restart")
        for room in list(self.rooms.values()):
            await room.finish()
        await db(store.forget_instance)(self.instance)
