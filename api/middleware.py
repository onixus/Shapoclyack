"""ASGI middleware that runs before request-body parsing.

Kept as raw ASGI (not ``BaseHTTPMiddleware``) precisely because the body cap
below has to be decided from the request headers, before Starlette/FastAPI
buffers and JSON-parses the payload.
"""

from __future__ import annotations

import json
import re
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from api.services import metrics as metrics_service

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class BodySizeLimitMiddleware:
    """Reject oversized (or unmeasurable) bodies on the guarded paths.

    Agent_plan.md S9, decision 1: the endpoint-inventory contract has a hard
    ``OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES`` cap enforced *before* JSON
    parsing, so a hostile or broken collector cannot make the API buffer and
    parse an arbitrarily large document just to have per-field limits reject it
    afterwards.

    A request without ``Content-Length`` (chunked/streaming upload) is answered
    with ``411 Length Required`` rather than being read to find out how big it
    is — the inventory contract is a single bounded JSON document, so a
    length-less body is out of contract by definition.

    The agent results upload (#222) is guarded by a second instance of this
    middleware with its own cap: ``POST /api/agent/jobs/{job_id}/results``
    carries a whole run archive as multipart, and the route read it in full
    before this. Both guarded contracts send a single in-memory body, so the
    ``411`` for a length-less request holds for the results path too.
    ``count_endpoint_submissions`` is what separates them: the inventory counter
    below describes endpoint submissions and would be a lie on the agent path.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        max_bytes: int,
        paths: tuple[str, ...] = (),
        path_patterns: tuple[str, ...] = (),
        count_endpoint_submissions: bool = True,
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.paths = paths
        # For routes whose identity is not a prefix: `/api/agent/jobs/{job_id}/
        # results` shares its prefix with the claim endpoint, and capping the
        # claim body at the archive size would guard the wrong contract.
        self.path_patterns = tuple(re.compile(pattern) for pattern in path_patterns)
        self.count_endpoint_submissions = count_endpoint_submissions

    def _guards(self, path: str) -> bool:
        if any(path.startswith(prefix) for prefix in self.paths):
            return True
        return any(pattern.match(path) is not None for pattern in self.path_patterns)

    async def _reject(self, send: Send, *, status_code: int, detail: str) -> None:
        # Same counter the route uses, so body-cap rejections show up in the
        # submission outcome breakdown instead of vanishing before the handler.
        if self.count_endpoint_submissions:
            metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels(
                "too_large" if status_code == 413 else "invalid"
            ).inc()
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "") not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if not self._guards(path):
            await self.app(scope, receive, send)
            return

        raw_length: bytes | None = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                raw_length = value
                break

        if raw_length is None:
            await self._reject(
                send,
                status_code=411,
                detail="Content-Length is required on this endpoint",
            )
            return
        try:
            length = int(raw_length)
        except ValueError:
            await self._reject(send, status_code=400, detail="invalid Content-Length header")
            return
        if length > self.max_bytes:
            await self._reject(
                send,
                status_code=413,
                detail=f"request body {length} bytes exceeds limit {self.max_bytes}",
            )
            return

        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Inject defensive HTTP security headers on all responses.

    Enforces:
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY (clickjacking protection)
    - X-XSS-Protection: 1; mode=block
    - Referrer-Policy: strict-origin-when-cross-origin
    - Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
    - Cross-Origin-Opener-Policy: same-origin
    - Content-Security-Policy (CSP)
    - Strict-Transport-Security (HSTS) when configured
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        enable_hsts: bool = False,
        content_security_policy: str | None = None,
    ) -> None:
        self.app = app
        self.enable_hsts = enable_hsts
        self.csp = content_security_policy or (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def _send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                raw_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                existing_keys = {k.lower() for k, _ in raw_headers}

                sec_headers: list[tuple[bytes, bytes]] = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"x-xss-protection", b"1; mode=block"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ]
                if self.csp:
                    sec_headers.append((b"content-security-policy", self.csp.encode("utf-8")))
                if self.enable_hsts:
                    sec_headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))

                for k, v in sec_headers:
                    if k not in existing_keys:
                        raw_headers.append((k, v))

                message["headers"] = raw_headers
            await send(message)

        await self.app(scope, receive, _send_with_headers)
