"""ASGI middleware that runs before request-body parsing.

Kept as raw ASGI (not ``BaseHTTPMiddleware``) precisely because the body cap
below has to be decided from the request headers, before Starlette/FastAPI
buffers and JSON-parses the payload.
"""

from __future__ import annotations

import json

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
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int, paths: tuple[str, ...]) -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.paths = paths

    async def _reject(self, send: Send, *, status_code: int, detail: str) -> None:
        # Same counter the route uses, so body-cap rejections show up in the
        # submission outcome breakdown instead of vanishing before the handler.
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
        if not any(path.startswith(prefix) for prefix in self.paths):
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
