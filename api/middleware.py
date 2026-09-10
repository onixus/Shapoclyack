"""ASGI middleware that runs before request-body parsing.

Kept as raw ASGI (not ``BaseHTTPMiddleware``) precisely because the body cap
below has to be decided from the request headers, before Starlette/FastAPI
buffers and JSON-parses the payload. The request-id layer at the bottom is raw
ASGI for the neighbouring reason: it has to bind the correlation id before any
other layer can log, the body-cap rejections that never reach a route included.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from starlette.types import ASGIApp, Receive, Scope, Send

from api.request_context import (
    REQUEST_ID_HEADER,
    new_request_id,
    reset_request_id,
    sanitize_request_id,
    set_request_id,
)
from api.services import metrics as metrics_service

LOG = logging.getLogger("shapoclyack.api")

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


class RequestIdMiddleware:
    """Bind a correlation id to the request and echo it back (#330).

    Reads ``X-Request-Id`` from the caller when it is a value we are willing to
    put in a log line and a response header (see
    :func:`api.request_context.sanitize_request_id`), and mints a uuid4 hex
    otherwise. An id that fails validation is *replaced*, not escaped: a client
    whose id we had to rewrite cannot correlate on it anyway.

    Raw ASGI rather than ``BaseHTTPMiddleware``, like the two classes above.
    Installed by :func:`install_request_id_middleware` rather than by
    ``app.add_middleware``, because "outermost" has to mean outside Starlette's
    own ``ServerErrorMiddleware`` too — see that function.

    The OTel span attribute is set from the ``http.response.start`` hook rather
    than on the way in: ``FastAPIInstrumentor`` is installed *inside* this
    middleware (``tracing.configure`` runs before ``create_app`` adds this one),
    so on the way in there is no server span yet, while the response-start
    message is sent from within it.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        supplied: str | None = None
        wanted = REQUEST_ID_HEADER.lower().encode("ascii")
        for name, value in scope.get("headers", []):
            if name.lower() == wanted:
                supplied = value.decode("latin-1", "replace")
                break
        request_id = sanitize_request_id(supplied) or new_request_id()

        async def _send_with_id(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                _annotate_span(request_id)
                raw_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                header_name = REQUEST_ID_HEADER.encode("ascii")
                if not any(k.lower() == wanted for k, _ in raw_headers):
                    raw_headers.append((header_name, request_id.encode("ascii")))
                message["headers"] = raw_headers
            await send(message)

        token = set_request_id(request_id)
        try:
            await self.app(scope, receive, _send_with_id)
        except Exception:
            # By the time an unhandled exception reaches here, the 500 for it
            # has already been written by ``ServerErrorMiddleware`` — which
            # this layer wraps, so it went out through ``_send_with_id`` and
            # carries the header like every other response. What is left is the
            # log line: re-raising would hand it to uvicorn's
            # "Exception in ASGI application", one frame above this contextvar,
            # i.e. with ``request_id=""`` — the one record about the request
            # that could not be found by its id. So it is written here, where
            # the id is still bound, and not raised again (#330).
            LOG.exception(
                "unhandled exception serving %s %s",
                scope.get("method", "?"),
                scope.get("path", "?"),
            )
        finally:
            reset_request_id(token)


def install_request_id_middleware(app: Any) -> None:
    """Wrap ``app``'s middleware stack in :class:`RequestIdMiddleware` (#330).

    ``app.add_middleware`` cannot express what this layer needs. Starlette
    builds ``ServerErrorMiddleware`` *outside* everything added that way, and
    that is where an unhandled exception becomes a 500 — sent through the send
    callable of whatever wraps it, which with ``add_middleware`` is uvicorn's
    own. So the single response in the API that most needs a correlation id was
    the only one without an ``X-Request-Id`` header, and
    docs/api-and-rbac.md's "every response carries" was false for it.

    Building the stack here rather than letting the first request build it is
    the price: ``add_middleware`` raises afterwards, so this is called last in
    ``create_app``.
    """
    app.middleware_stack = RequestIdMiddleware(app.build_middleware_stack())


# Resolved once, not per response: OpenTelemetry is an optional dependency of
# this install (``api/services/tracing.py`` degrades to a warning without it),
# and a missing package must not turn every response into a 500 — nor an
# ImportError into per-request work.
try:  # pragma: no cover - depends on the install's extras
    from opentelemetry import trace as _otel_trace
except ImportError:  # pragma: no cover - depends on the install's extras
    _otel_trace = None  # type: ignore[assignment]


def _annotate_span(request_id: str) -> None:
    """Put the correlation id on the active span, when tracing is on.

    With tracing off but the package present, ``get_current_span()`` answers the
    non-recording span and ``set_attribute`` is a no-op, so this costs one
    attribute lookup on an installation that exports nothing.
    """
    if _otel_trace is None:  # pragma: no cover - depends on the install's extras
        return
    _otel_trace.get_current_span().set_attribute("shapoclyack.request_id", request_id)
