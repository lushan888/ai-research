"""
Fix for Issue #939 — WebSocket CSRF → Cross-Origin Data Exfiltration
====================================================================

Vulnerability
-------------
The WebSocket endpoint ``/ws/realtime`` accepts connections from any origin
without validating the ``Origin`` header. An attacker can create a malicious
web page that opens a WebSocket connection to the target server using the
victim's existing authenticated session (cookies are sent automatically by
the browser). This allows the attacker to exfiltrate real-time data streams.

Fix Strategy
------------
1. Validate the ``Origin`` header against a whitelist of allowed origins.
2. Implement a CSRF challenge-response handshake before the WebSocket
   connection is fully established.
3. Return HTTP 403 when the origin is invalid.
4. Use cryptographic nonces for the CSRF handshake.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence


# Default allowed origins (configured via environment in production)
DEFAULT_ALLOWED_ORIGINS = frozenset({
    "https://example.com",
    "https://www.example.com",
    "https://app.example.com",
})

# Origin validation regex (RFC 6454)
ORIGIN_RE = re.compile(
    r"^https?://"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?::[0-9]{1,5})?"
    r"$"
)

# CSRF token configuration
CSRF_TOKEN_BYTES = 32
CSRF_TOKEN_TTL = 300  # 5 minutes
CSRF_CHALLENGE_HEADER = "X-CSRF-Token"


class WebSocketCSRFError(ValueError):
    """Raised when WebSocket CSRF validation fails."""


@dataclass
class WebSocketCSRFGuard:
    """Guard against WebSocket CSRF attacks.

    Validates the Origin header and implements a CSRF challenge-response
    handshake before allowing WebSocket connections.

    Usage::

        guard = WebSocketCSRFGuard(
            allowed_origins=["https://app.example.com"]
        )

        # On HTTP endpoint (before WebSocket upgrade):
        challenge = guard.create_challenge(session_id)
        # Send challenge to client via HTTP response header

        # On WebSocket upgrade request:
        guard.validate_upgrade(origin, challenge_token, session_id)
    """

    allowed_origins: set[str] = field(default_factory=lambda: set(DEFAULT_ALLOWED_ORIGINS))
    _challenges: dict[str, _ChallengeRecord] = field(default_factory=dict)

    def add_allowed_origin(self, origin: str) -> None:
        """Add an origin to the whitelist."""
        if not ORIGIN_RE.fullmatch(origin):
            raise WebSocketCSRFError(f"invalid origin format: {origin!r}")
        self.allowed_origins.add(origin)

    def set_allowed_origins(self, origins: Iterable[str]) -> None:
        """Set the complete whitelist of allowed origins."""
        self.allowed_origins = set()
        for origin in origins:
            self.add_allowed_origin(origin)

    def validate_origin(self, origin: str | None) -> str:
        """Validate the Origin header against the whitelist.

        Args:
            origin: The value of the ``Origin`` header, or None.

        Returns:
            The validated origin string.

        Raises:
            WebSocketCSRFError: If the origin is invalid.
        """
        if not origin:
            raise WebSocketCSRFError("missing Origin header")

        if not ORIGIN_RE.fullmatch(origin):
            raise WebSocketCSRFError(f"invalid Origin header format: {origin!r}")

        if origin not in self.allowed_origins:
            raise WebSocketCSRFError(
                f"origin {origin!r} is not in the allowed origins whitelist"
            )

        return origin

    def create_challenge(self, session_id: str) -> str:
        """Create a CSRF challenge token for the WebSocket handshake.

        The challenge is a cryptographic token tied to the session ID.
        The client must return this token in the ``X-CSRF-Token`` header
        during the WebSocket upgrade request.

        Args:
            session_id: The user's session identifier.

        Returns:
            A challenge token string.
        """
        token = _generate_csrf_token()
        self._challenges[session_id] = _ChallengeRecord(
            token=token,
            created_at=time.time(),
        )
        return token

    def validate_upgrade(
        self,
        origin: str | None,
        challenge_token: str | None,
        session_id: str,
    ) -> None:
        """Validate the WebSocket upgrade request.

        Args:
            origin: The ``Origin`` header from the WebSocket upgrade request.
            challenge_token: The ``X-CSRF-Token`` header value.
            session_id: The user's session identifier.

        Raises:
            WebSocketCSRFError: If validation fails.
        """
        # Step 1: Validate origin
        self.validate_origin(origin)

        # Step 2: Validate CSRF challenge
        if not challenge_token:
            raise WebSocketCSRFError("missing CSRF challenge token")

        record = self._challenges.get(session_id)
        if record is None:
            raise WebSocketCSRFError("no CSRF challenge issued for this session")

        # Check expiry
        if time.time() - record.created_at > CSRF_TOKEN_TTL:
            del self._challenges[session_id]
            raise WebSocketCSRFError("CSRF challenge token expired")

        # Verify token
        if not hmac.compare_digest(record.token, challenge_token):
            raise WebSocketCSRFError("CSRF challenge token mismatch")

        # Clean up used challenge
        del self._challenges[session_id]

    def cleanup_expired(self) -> int:
        """Remove expired challenge records.

        Returns:
            Number of records cleaned up.
        """
        now = time.time()
        expired = [
            sid for sid, record in self._challenges.items()
            if now - record.created_at > CSRF_TOKEN_TTL
        ]
        for sid in expired:
            del self._challenges[sid]
        return len(expired)


@dataclass
class _ChallengeRecord:
    token: str
    created_at: float


def _generate_csrf_token() -> str:
    """Generate a cryptographically secure CSRF token."""
    import base64
    return base64.urlsafe_b64encode(os.urandom(CSRF_TOKEN_BYTES)).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Middleware example for popular frameworks
# ---------------------------------------------------------------------------

def make_wsgi_middleware(
    app: Callable,
    guard: WebSocketCSRFGuard,
    ws_path: str = "/ws/realtime",
) -> Callable:
    """WSGI middleware that validates WebSocket upgrade requests.

    Usage with Flask/Django::

        app = Flask(__name__)
        guard = WebSocketCSRFGuard()
        app.wsgi_app = make_wsgi_middleware(app.wsgi_app, guard)
    """
    from urllib.parse import parse_qs

    def middleware(environ, start_response):
        path = environ.get("PATH_INFO", "")
        is_websocket = environ.get("HTTP_UPGRADE", "").lower() == "websocket"

        if path == ws_path and is_websocket:
            origin = environ.get("HTTP_ORIGIN")
            session_id = _get_session_id(environ)
            challenge = environ.get(f"HTTP_{CSRF_CHALLENGE_HEADER.upper().replace('-', '_')}")

            try:
                guard.validate_upgrade(origin, challenge, session_id)
            except WebSocketCSRFError:
                start_response("403 Forbidden", [("Content-Type", "text/plain")])
                return [b"WebSocket CSRF validation failed"]

        return app(environ, start_response)

    return middleware


def _get_session_id(environ: Mapping) -> str:
    """Extract session ID from the request environment."""
    cookies = environ.get("HTTP_COOKIE", "")
    for cookie in cookies.split(";"):
        cookie = cookie.strip()
        if cookie.startswith("session="):
            return cookie[8:]
    return ""


# ---------------------------------------------------------------------------
# Async middleware example (ASGI / FastAPI / Starlette)
# ---------------------------------------------------------------------------

async def make_asgi_middleware(
    scope: dict,
    receive: Callable,
    send: Callable,
    guard: WebSocketCSRFGuard,
    ws_path: str = "/ws/realtime",
) -> None:
    """ASGI middleware for WebSocket CSRF protection.

    Usage with FastAPI/Starlette::

        from fastapi import FastAPI, WebSocket

        app = FastAPI()
        guard = WebSocketCSRFGuard()

        @app.websocket("/ws/realtime")
        async def ws_endpoint(websocket: WebSocket):
            await make_asgi_middleware(
                websocket.scope, websocket.receive, websocket.send, guard
            )
            await websocket.accept()
            ...
    """
    if scope.get("path") != ws_path or scope.get("type") != "websocket":
        return

    headers = dict(scope.get("headers", []))
    origin = headers.get(b"origin", b"").decode("utf-8") or None
    session_id = _get_session_id_asgi(headers)
    challenge = headers.get(
        f"x-csrf-token".encode("utf-8"), b""
    ).decode("utf-8") or None

    try:
        guard.validate_upgrade(origin, challenge, session_id)
    except WebSocketCSRFError:
        # Send 403 close frame
        await send({
            "type": "websocket.close",
            "code": 3403,
            "reason": "CSRF validation failed",
        })
        return


def _get_session_id_asgi(headers: dict[bytes, bytes]) -> str:
    """Extract session ID from ASGI headers."""
    cookie = headers.get(b"cookie", b"").decode("utf-8")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("session="):
            return part[8:]
    return ""