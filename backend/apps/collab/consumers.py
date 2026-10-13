"""The WebSocket consumer: handshake, login, rate limits, then frames to and from the room."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.security.websocket import WebsocketDenier
from django.conf import settings

from apps.sharing.serializers import public_name

from . import access, protocol, store
from .limits import TokenBucket, allow_connection_attempt
from .room import Member, RoomRegistry, RoomUnavailable, db

log = logging.getLogger("doory.collab")

_registry: RoomRegistry | None = None
MAX_PASSWORD_ATTEMPTS = 5
MAX_AUTH_FRAME_BYTES = 1024


def get_registry() -> RoomRegistry:
    """The registry of this server process."""
    global _registry
    if _registry is None:
        _registry = RoomRegistry()
    return _registry


def reset_registry() -> None:
    global _registry
    _registry = None


class RealtimeOriginValidator:
    """Refuses a handshake whose `Origin` is not this site (cross-site WebSocket hijacking)."""

    def __init__(self, application: Any) -> None:
        self.application = application

    async def __call__(self, scope: dict, receive: Any, send: Any) -> Any:
        headers = {name.decode("latin1"): value.decode("latin1") for name, value in scope.get("headers", [])}
        if access.origin_allowed(headers.get("origin"), headers.get("host")):
            return await self.application(scope, receive, send)
        return await WebsocketDenier()(scope, receive, send)


def client_ip(scope: dict) -> str:
    """Client address for rate limiting: X-Forwarded-For behind the configured number of proxies."""
    proxies = getattr(settings, "REST_FRAMEWORK", {}).get("NUM_PROXIES")
    if proxies:
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                parts = [part.strip() for part in value.decode("latin1").split(",") if part.strip()]
                if len(parts) >= proxies:
                    return parts[-proxies]
    client = scope.get("client") or ("", 0)
    return str(client[0])


class CollabConsumer(AsyncWebsocketConsumer):
    """One connection to `/ws/designs/<uuid>/`."""

    # Rooms talk to the channel layer themselves; a connection needs no channel of its own.
    channel_layer_alias = "none"

    def __init__(self, registry: RoomRegistry | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._registry = registry
        self.member: Member | None = None
        self.room = None
        self.design_id: uuid.UUID | None = None
        self.user: Any = None
        self.state = "new"
        self.bucket: TokenBucket | None = None
        self._auth_timer: asyncio.Task | None = None
        self._attempts = 0
        self._pending = False

    @property
    def registry(self) -> RoomRegistry:
        return self._registry or get_registry()

    # ------------------------------------------------------------------ transport for the room

    async def send_bytes(self, data: bytes) -> None:
        await self.send(bytes_data=data)

    async def send_text(self, text: str) -> None:
        await self.send(text_data=text)

    def _settle_pending(self) -> None:
        """The connection is no longer waiting for its login (it got in, was refused or went away)."""
        if self._pending:
            self._pending = False
            self.registry.pending[self.user.pk] -= 1

    async def refuse(self, code: int, reason: str) -> None:
        self._settle_pending()
        self.state = "closed"
        self.registry.counters[f"refused_{code}"] += 1
        log.info("refuse design=%s code=%s reason=%s", self.design_id, code, reason)
        await self.close(code=code, reason=reason)

    # ------------------------------------------------------------------ lifecycle

    async def connect(self) -> None:
        self.design_id = self.scope["url_route"]["kwargs"]["design_id"]
        await self.accept()
        self.user = self.scope.get("user")
        if self.user is None or not self.user.is_authenticated:
            await self.refuse(4401, "not_authenticated")
            return
        if not await db(allow_connection_attempt)(self.user.pk):
            await self.refuse(4429, "rate_limited")
            return
        self.bucket = TokenBucket.from_settings()
        try:
            grant = await db(access.owner_grant)(self.user, self.design_id)
        except access.DesignGone:
            await self.refuse(4404, "design_trashed")
            return
        if grant is not None:
            await self.enter(grant)
            return
        if self.registry.pending[self.user.pk] >= settings.REALTIME_MAX_CONNECTIONS_PER_USER:
            await self.refuse(4429, "too_many_connections")
            return
        self.registry.pending[self.user.pk] += 1
        self._pending = True
        self.state = "authenticating"
        self._auth_timer = asyncio.create_task(self._auth_timeout())

    async def _auth_timeout(self) -> None:
        await asyncio.sleep(settings.REALTIME_AUTH_TIMEOUT_SECONDS)
        if self.state == "authenticating":
            await self.refuse(4408, "auth_timeout")

    async def disconnect(self, code: int) -> None:
        if self._auth_timer is not None:
            self._auth_timer.cancel()
        self._settle_pending()
        member, self.member = self.member, None
        self.state = "closed"
        if member is not None:
            if self.room is not None:
                self.room.leave(member)
            await db(store.release)(member.connection_id)
            log.info(
                "close design=%s user=%s role=%s code=%s",
                self.design_id,
                member.user_id,
                member.role,
                code,
            )

    async def close(self, code: int | None = None, reason: str | None = None) -> None:
        await super().close(code=code, reason=reason)

    # ------------------------------------------------------------------ login

    async def enter(self, grant: access.Grant) -> None:
        """Admit the connection: limits, room, `ready` frame."""
        self._settle_pending()
        admission = await db(store.admit)(
            self.design_id, self.user.pk, grant.role, grant.link_id, self.registry.instance
        )
        if not admission.ok:
            await self.refuse(4429, admission.reason)
            return
        if self.state == "closed":  # the client left while it was being admitted
            await db(store.release)(admission.connection_id)
            return
        member = Member(
            id=uuid.uuid4().hex,
            user_id=self.user.pk,
            name=public_name(self.user),  # never the first part of the e-mail address
            avatar_url=self.user.avatar.url if self.user.avatar else None,
            role=grant.role,
            link_id=grant.link_id,
            session_key=getattr(self.scope.get("session"), "session_key", None),
            connection_id=admission.connection_id,
            transport=self,
        )
        try:
            room = await self._join(member)
        except RoomUnavailable as exc:
            await db(store.release)(admission.connection_id)
            await self.refuse(1013, exc.reason)
            return
        except Exception:
            await db(store.release)(admission.connection_id)
            log.exception("could not open the room design=%s", self.design_id)
            await self.refuse(1011, "internal_error")
            return
        if self.state == "closed":
            room.leave(member)
            await db(store.release)(admission.connection_id)
            return
        self.member, self.room, self.state = member, room, "active"
        if self._auth_timer is not None:
            self._auth_timer.cancel()
        self.registry.counters["connects"] += 1
        log.info("connect design=%s user=%s role=%s", self.design_id, member.user_id, member.role)
        ready = {
            "type": "ready",
            "role": grant.role,
            "canWrite": member.can_write,
            "user": {"id": str(member.user_id), "name": member.name, "avatar_url": member.avatar_url},
            "title": room.title,
            "revision": room.revision,
            "limits": {
                "maxFrameBytes": settings.REALTIME_MAX_FRAME_BYTES,
                "maxParticipants": settings.REALTIME_MAX_CONNECTIONS_PER_DESIGN,
            },
        }
        member.outbox.put_nowait(("t", json.dumps(ready, separators=(",", ":"))))

    async def _join(self, member: Member):
        for _ in range(3):
            room = await self.registry.acquire(self.design_id)
            if room.join(member):
                return room
        raise RoomUnavailable("try_again")

    async def _authenticate(self, text: str) -> None:
        try:
            message = json.loads(text)
        except (ValueError, RecursionError):
            await self.refuse(4400, "bad_auth")
            return
        if not isinstance(message, dict) or message.get("type") != "auth":
            await self.refuse(4400, "auth_required")
            return
        token, password = message.get("token"), message.get("password")
        if not isinstance(token, str) or not (password is None or isinstance(password, str)):
            await self.refuse(4400, "bad_auth")
            return
        try:
            grant = await db(access.link_grant)(self.design_id, token, password, client_ip(self.scope))
        except access.Forbidden:
            self.registry.counters["auth_failed"] += 1
            await self.refuse(4403, "forbidden")
            return
        except access.PasswordNeeded:
            self._attempts += 1
            self.registry.counters["auth_failed"] += 1
            if self._attempts >= MAX_PASSWORD_ATTEMPTS:
                await self.refuse(4403, "forbidden")
                return
            await self._error("password_required", "This link needs its password.")
            return
        except access.Locked as exc:
            self.registry.counters["auth_failed"] += 1
            await self._error("throttled", "Too many wrong passwords.", retry_after=exc.retry_after)
            await self.refuse(4429, "password_locked")
            return
        await self.enter(grant)

    async def _error(self, code: str, message: str, **extra: Any) -> None:
        await self.send(text_data=json.dumps({"type": "error", "code": code, "message": message, **extra}))

    # ------------------------------------------------------------------ frames

    async def receive(self, text_data: str | None = None, bytes_data: bytes | None = None) -> None:
        if self.state in ("closed", "closing", "new") or self.bucket is None:
            return
        size = len(bytes_data) if bytes_data is not None else len((text_data or "").encode("utf-8"))
        if size > settings.REALTIME_MAX_FRAME_BYTES:
            await self._close_member(4413, "frame_too_large")
            return
        if not self.bucket.allow(size):
            self.registry.counters["rate_limited"] += 1
            await self._close_member(4429, "rate_limited")
            return
        if self.state == "authenticating":
            if text_data is None:
                await self.refuse(4400, "auth_required")
            elif len(text_data) > MAX_AUTH_FRAME_BYTES:
                await self.refuse(4413, "frame_too_large")
            else:
                await self._authenticate(text_data)
            return
        member = self.member
        if member is None or self.room is None or member.closing:
            return
        member.last_seen = asyncio.get_running_loop().time()
        if text_data is not None:
            await self._text(text_data)
            return
        try:
            frame = protocol.parse_frame(bytes_data or b"")
        except protocol.ProtocolError:
            await self._close_member(4400, "bad_frame")
            return
        await self.room.submit(member, frame)

    async def _text(self, text: str) -> None:
        try:
            message = json.loads(text)
        except (ValueError, RecursionError):
            await self._close_member(4400, "bad_frame")
            return
        kind = message.get("type") if isinstance(message, dict) else None
        if kind == "ping":
            await self.send(text_data='{"type":"pong"}')
        elif kind == "flush":
            if self.member is not None and self.room is not None and self.member.can_write:
                self.room.request_flush(self.member)
        elif kind != "auth":
            await self._close_member(4400, "bad_frame")

    async def _close_member(self, code: int, reason: str) -> None:
        """Close an active (or logging-in) connection through the room so its state is cleaned up first."""
        self.state = "closing"
        if self.member is not None and self.room is not None:
            self.room.kick(self.member, code, reason)
        else:
            await self.refuse(code, reason)
