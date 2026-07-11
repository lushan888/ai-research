"""
Fix for Issue #666 — CORS Misconfiguration + Origin Reflection → Credential Theft
=================================================================================

Vulnerability
-------------
API responses reflect the inbound ``Origin`` header into
``Access-Control-Allow-Origin`` while simultaneously setting
``Access-Control-Allow-Credentials: true``. Any malicious site can
initiate credentialed cross-origin requests and read the API response,
stealing session tokens, PII, and financial data from the victim's
browser.

Root cause: the server trusts the client-supplied ``Origin`` header and
uses it directly as the allowlist match.

Fix Strategy
------------
1. Maintain an explicit, out-of-band allowlist of trusted origins.
2. Perform an exact, case-sensitive match against the allowlist;
   never use ``*`` when ``credentials`` is allowed.
3. Always return ``Vary: Origin`` so caches don't mix per-origin
   responses.
4. Reject preflight (OPTIONS) requests whose origin is not allowlisted.
5. Audit-log rejected origins so operators can detect probing.

This module is framework-agnostic and provides a drop-in WSGI
middleware, a Starlette/FastAPI middleware factory, and a bare
reference implementation.

Usage
-----
    from cors_misconfiguration_fix import CORSMiddleware

    # Flask / WSGI
    app.wsgi_app = CORSMiddleware(app.wsgi_app,
        allowed_origins=["https://app.example.com",
                         "https://admin.example.com"])

    # FastAPI / ASGI
    from starlette.middleware.base import BaseHTTPMiddleware
    app.add_middleware(BaseHTTPMiddleware, dispatch=cors_dispatch)

Self-tests
----------
>>> import runpy, sys
>>> runpy.run_path(__file__, run_name="__test__")
All tests passed (8/8)
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, Optional, Callable

logger = logging.getLogger(__name__)

# ---- helpers ----------------------------------------------------------- #

def _normalise_origin(origin: str) -> Optional[str]:
    """Return a canonical ``scheme://host[:port]`` or ``None`` on bad input."""
    if not origin or not isinstance(origin, str):
        return None
    origin = origin.strip()
    if not origin:
        return None
    # Reject schemes that are not http/https (no file:, blob:, data:, etc.)
    if not re.fullmatch(r"https?://[^\s;]+", origin):
        return None
    # Strip trailing slashes that some browsers add
    return origin.rstrip("/")


def _build_origin_matcher(allowed: Iterable[str]) -> Callable[[str], bool]:
    """Return a predicate that checks an origin against the allowlist."""
    canonical = {_normalise_origin(o) for o in allowed}
    canonical.discard(None)

    def check(origin: str) -> bool:
        return _normalise_origin(origin) in canonical

    return check


# ---- bare reference implementation ------------------------------------- #

def add_cors_headers(
    origin: Optional[str],
    allowed_origins: Iterable[str],
) -> list[tuple[str, str]]:
    """Return a list of (name, value) header tuples to append.

    Returns the minimal set; the caller is responsible for not adding
    duplicate ``Access-Control-Allow-Origin`` values.
    """
    matcher = _build_origin_matcher(allowed_origins)
    headers: list[tuple[str, str]] = [("Vary", "Origin")]

    if origin and matcher(origin):
        headers.append(("Access-Control-Allow-Origin", origin))
        headers.append(("Access-Control-Allow-Credentials", "true"))

    return headers


# ---- WSGI middleware --------------------------------------------------- #

class CORSMiddleware:
    """WSGI middleware that enforces origin allowlist + Vary: Origin."""

    def __init__(self, app, allowed_origins: Iterable[str]):
        self.app = app
        self._match = _build_origin_matcher(allowed_origins)
        self._logger = logging.getLogger(self.__module__)

    def __call__(self, environ, start_response):
        origin = environ.get("HTTP_ORIGIN")
        method = environ.get("REQUEST_METHOD", "")
        path = environ.get("PATH_INFO", "")

        headers_to_add: list[tuple[str, str]] = [("Vary", "Origin")]

        # Reject OPTIONS (preflight) if origin not allowed
        if method == "OPTIONS":
            if origin and self._match(origin):
                headers_to_add.append(("Access-Control-Allow-Origin", origin))
                headers_to_add.append(("Access-Control-Allow-Credentials", "true"))
                headers_to_add.extend([
                    ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS"),
                    ("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With"),
                    ("Access-Control-Max-Age", "86400"),
                ])
            else:
                self._logger.warning(
                    "Rejected preflight OPTIONS from origin=%r path=%s", origin, path
                )
                # Respond 403 directly — do not forward to the app
                start_response("403 Forbidden", headers_to_add)
                return [b""]

        # For non-OPTIONS, attach CORS headers when origin is allowed
        if origin and self._match(origin):
            headers_to_add.append(("Access-Control-Allow-Origin", origin))
            headers_to_add.append(("Access-Control-Allow-Credentials", "true"))
        else:
            # Origin not allowed — do NOT set ACAO. Browser will block it.
            self._logger.debug(
                "Not adding CORS headers: origin=%r path=%s", origin, path
            )

        def custom_start_response(status, response_headers, exc_info=None):
            # De-duplicate headers while preserving order
            seen: set[str] = set()
            final_headers: list[tuple[str, str]] = []
            # First add our CORS headers (so app headers can override)
            for name, value in response_headers:
                final_headers.append((name, value))
            # Now prepend ours
            for name, value in headers_to_add:
                key = name.lower()
                if key not in seen:
                    final_headers.insert(0, (name, value))
                else:
                    # For Vary, merge
                    if key == "vary":
                        final_headers = [
                            (n, v) for n, v in final_headers if n.lower() != "vary"
                        ]
                        existing = next(
                            (v for n, v in final_headers if n.lower() == "vary"), ""
                        )
                        merged = f"{existing}, Origin" if existing else "Origin"
                        final_headers.append(("Vary", merged))
                seen.add(key)
            return start_response(status, final_headers, exc_info)

        return self.app(environ, custom_start_response)


# ---- ASGI / Starlette dispatcher --------------------------------------- #

def cors_asgi_dispatch(
    receive, send, scope, app, allowed_origins: Iterable[str]
):
    """Starlette/FastAPI ASGI middleware dispatch callable."""
    if scope["type"] != "http":
        return app(scope, receive, send)

    matcher = _build_origin_matcher(allowed_origins)
    headers = dict(scope.get("headers", []) or [])
    # headers are bytes tuples in ASGI
    origin = None
    for k, v in headers.items():
        if k == b"origin":
            origin = v.decode("utf-8", errors="replace")
            break

    extra_headers = [(b"Vary", b"Origin")]
    method = scope.get("method", "")

    if method == "OPTIONS":
        if origin and matcher(origin):
            extra_headers.extend([
                (b"Access-Control-Allow-Origin", origin.encode()),
                (b"Access-Control-Allow-Credentials", b"true"),
                (b"Access-Control-Allow-Methods",
                 b"GET, POST, PUT, DELETE, PATCH, OPTIONS"),
                (b"Access-Control-Allow-Headers",
                 b"Content-Type, Authorization, X-Requested-With"),
                (b"Access-Control-Max-Age", b"86400"),
            ])
        else:
            async def reject(receive, send):
                await send({
                    "type": "http.response.start",
                    "status": 403,
                    "headers": extra_headers,
                })
                await send({"type": "http.response.body", "body": b""})
            return reject(receive, send)

    if origin and matcher(origin):
        extra_headers.extend([
            (b"Access-Control-Allow-Origin", origin.encode()),
            (b"Access-Control-Allow-Credentials", b"true"),
        ])

    async def inner_receive():
        return await receive()

    async def inner_send(message):
        if message.get("type") == "http.response.start":
            existing = dict(message.get("headers", []) or [])
            # Merge Vary
            vary_existing = existing.get(b"Vary", b"")
            new_vary = f"{vary_existing.decode()}, Origin".strip(", ") if vary_existing else "Origin"
            message["headers"] = [
                (k, v) for k, v in message["headers"]
                if k.lower() not in (b"vary", b"access-control-allow-origin",
                                      b"access-control-allow-credentials")
            ]
            message["headers"].extend(extra_headers)
            message["headers"].append((b"Vary", new_vary.encode()))
        await send(message)

    return app(scope, inner_receive, inner_send)


# ---- self-test --------------------------------------------------------- #

def _run_tests():
    import pytest

    tests_passed = 0
    tests_total = 8

    def ok():
        nonlocal tests_passed
        tests_passed += 1

    # 1. normalise origin
    assert _normalise_origin("https://app.example.com") == "https://app.example.com"
    ok()

    # 2. reject bad schemes
    assert _normalise_origin("file:///etc/passwd") is None
    ok()

    # 3. allowed origin gets ACAO
    headers = add_cors_headers(
        "https://app.example.com",
        ["https://app.example.com", "https://admin.example.com"],
    )
    values = {n: v for n, v in headers}
    assert values.get("Access-Control-Allow-Origin") == "https://app.example.com"
    assert values.get("Access-Control-Allow-Credentials") == "true"
    assert values.get("Vary") == "Origin"
    ok()

    # 4. disallowed origin gets no ACAO
    headers = add_cors_headers(
        "https://evil.example.com",
        ["https://app.example.com"],
    )
    values = {n: v for n, v in headers}
    assert "Access-Control-Allow-Origin" not in values
    ok()

    # 5. no origin → no ACAO, but Vary is still set
    headers = add_cors_headers(None, ["https://app.example.com"])
    values = {n: v for n, v in headers}
    assert "Access-Control-Allow-Origin" not in values
    assert values.get("Vary") == "Origin"
    ok()

    # 6. never emit * with credentials
    headers = add_cors_headers("https://app.example.com", ["https://app.example.com"])
    values = {n: v for n, v in headers}
    assert values.get("Access-Control-Allow-Origin") != "*"
    ok()

    # 7. allowlist is case-sensitive (Origin header is case-sensitive per spec)
    assert _build_origin_matcher(["https://Example.com"])("https://example.com") is False
    ok()

    # 8. trailing slash stripped
    assert _build_origin_matcher(["https://app.example.com/"])(
        "https://app.example.com"
    ) is True
    ok()

    print(f"All tests passed ({tests_passed}/{tests_total})")
    return tests_passed == tests_total


if __name__ == "__main__" or __name__ == "__test__":
    assert _run_tests(), "Tests failed"
