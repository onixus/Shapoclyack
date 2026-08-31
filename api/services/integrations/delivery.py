"""The wire half of webhook delivery (ROADMAP P2 / Phase 10.3).

Everything here is stateless and database-free so the queue in ``webhooks.py``
can be tested without a network and this can be tested without Postgres.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from api.services import outbound_targets

LOG = logging.getLogger("shapoclyack.webhooks")

SIGNATURE_HEADER = "X-Shapoclyack-Signature"
TIMESTAMP_HEADER = "X-Shapoclyack-Timestamp"
EVENT_HEADER = "X-Shapoclyack-Event"
EVENT_ID_HEADER = "X-Shapoclyack-Event-Id"
DELIVERY_HEADER = "X-Shapoclyack-Delivery"
TENANT_HEADER = "X-Shapoclyack-Tenant"
USER_AGENT = "Shapoclyack-Webhook/1"

# Headers a subscription may not set: they either carry the signature this
# service computes or describe a body it serialises itself.
_RESERVED_HEADER_PREFIXES = ("x-shapoclyack-",)
_RESERVED_HEADERS = {"content-type", "content-length", "host", "user-agent"}

# Response body kept on a failed attempt. Enough to recognise "401 invalid
# token" in the DLQ, short enough that a receiver returning an HTML error page
# cannot fill the audit table. The wire reader is bounded separately so this is
# also not an invitation to buffer a receiver's 2 GiB error page first.
_ERROR_EXCERPT_CHARS = 500
_MAX_ERROR_BODY_BYTES = 4096


#: The URL is not a legal webhook target (bad scheme, or blocked address).
#: An alias rather than a subclass: the parsing lives in
#: ``api/services/outbound_targets.py`` since #240, and it raises the shared
#: type — a subclass here would simply stop catching it.
WebhookTargetError = outbound_targets.OutboundTargetError


@dataclass(frozen=True)
class DeliveryResult:
    """Outcome of one POST.

    ``retryable`` is the only field the queue really acts on. A 4xx other than
    408/429 is the receiver saying the request itself is wrong — replaying it
    unchanged five more times just spends the backoff window to arrive at the
    same answer — so it goes straight to the dead-letter queue, while a
    timeout, a connection error or a 5xx is retried.
    """

    ok: bool
    status_code: int | None
    error: str | None
    retryable: bool
    duration_seconds: float = 0.0
    #: Response body when the caller asked for it (ticket create needs the
    #: issue key). Webhook deliveries leave this None — the receiver's 200
    #: body is not audit material.
    body: str | None = None
    ticket_key: str | None = None
    ticket_url: str | None = None


#: A webhook URL plus the exact addresses approved for this delivery.
_ResolvedTarget = outbound_targets.HttpTarget


def canonical_body(payload: dict[str, Any]) -> bytes:
    """Serialise a payload to the exact bytes that get signed and sent.

    Separators are pinned so the signature the receiver recomputes over the
    body it read matches the one computed here — a re-serialisation with
    different spacing would verify as a forgery.
    """
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """HMAC-SHA256 over ``{timestamp}.{body}``, hex, prefixed with ``sha256=``.

    The timestamp is inside the MAC, not merely beside it: a receiver that
    rejects old timestamps can only rely on that if replaying an old body with
    a fresh timestamp invalidates the signature.
    """
    mac = hmac.new(secret.encode("utf-8"), b"", hashlib.sha256)
    mac.update(timestamp.encode("utf-8"))
    mac.update(b".")
    mac.update(body)
    return f"sha256={mac.hexdigest()}"


def sanitize_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Drop reserved names and coerce to ``str``; raise on illegal values."""
    cleaned: dict[str, str] = {}
    for raw_name, raw_value in (headers or {}).items():
        name = str(raw_name).strip()
        value = str(raw_value)
        lowered = name.lower()
        if not name or lowered in _RESERVED_HEADERS:
            continue
        if any(lowered.startswith(prefix) for prefix in _RESERVED_HEADER_PREFIXES):
            continue
        # A newline in a header value is header injection, not a header.
        if any(char in name or char in value for char in ("\r", "\n")):
            raise ValueError(f"illegal characters in header {name!r}")
        cleaned[name] = value
    return cleaned


def _parse_target(url: str, *, allow_private: bool) -> _ResolvedTarget:
    """Parse and validate one webhook URL under the #151 boundary.

    A thin call into the shared boundary so the deployer's probe (#240) and
    this path cannot drift apart on what "a target" is — only on the policy,
    which is the part that legitimately differs.
    """
    return outbound_targets.parse_url(
        url, policy=outbound_targets.webhook_policy(allow_private=allow_private)
    )


def validate_url(url: str, *, allow_private: bool = False) -> str:
    """Return the URL if it is a legal webhook target, else raise.

    Called when a subscription is written and again for every delivery. DNS
    failure is deliberately not rejected at write time: a temporarily missing
    record is an availability problem, not a policy violation. When delivery
    runs, however, the resolved addresses are pinned into the TCP connection so
    a second DNS lookup cannot redirect an already-approved hostname inward.
    """
    _parse_target(url, allow_private=allow_private)
    return (url or "").strip()


def build_request(
    *,
    payload: dict[str, Any],
    secret: str | None,
    extra_headers: dict[str, Any] | None,
    delivery_id: str,
    tenant_id: str,
    event_kind: str,
    event_id: str,
    timestamp: datetime | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Return ``(body, headers)`` for one delivery attempt."""
    body = canonical_body(payload)
    stamp = str(int((timestamp or datetime.now(timezone.utc)).timestamp()))
    headers = sanitize_headers(extra_headers)
    headers.update(
        {
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            TIMESTAMP_HEADER: stamp,
            DELIVERY_HEADER: delivery_id,
            TENANT_HEADER: tenant_id,
            EVENT_HEADER: event_kind,
            EVENT_ID_HEADER: event_id,
        }
    )
    if secret:
        headers[SIGNATURE_HEADER] = sign(secret, stamp, body)
    return body, headers


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that dials a validated IP but verifies the DNS name."""

    def __init__(
        self,
        *,
        connect_host: str,
        server_hostname: str,
        port: int,
        timeout: float,
    ) -> None:
        super().__init__(
            server_hostname,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._connect_host = connect_host

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _read_error_excerpt(response: http.client.HTTPResponse, *, deadline: float) -> str:
    """Read at most a few KiB while respecting the delivery wall-clock budget."""
    chunks: list[bytes] = []
    remaining_bytes = _MAX_ERROR_BODY_BYTES
    while remaining_bytes > 0:
        remaining_time = deadline - time.perf_counter()
        if remaining_time <= 0:
            raise TimeoutError("webhook delivery deadline exceeded while reading response")
        sock = getattr(response, "fp", None)
        raw = getattr(sock, "raw", None)
        socket_obj = getattr(raw, "_sock", None)
        if socket_obj is not None:
            socket_obj.settimeout(remaining_time)
        chunk = response.read(min(1024, remaining_bytes))
        if not chunk:
            break
        chunks.append(chunk)
        remaining_bytes -= len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()[:_ERROR_EXCERPT_CHARS]


def _send_to_address(
    target: _ResolvedTarget,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    body: bytes,
    headers: dict[str, str],
    *,
    method: str = "POST",
    deadline: float,
    capture_body: bool = False,
) -> tuple[int, str]:
    """Send to one already-approved IP without performing DNS resolution."""
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise TimeoutError("webhook delivery deadline exceeded before connect")

    if target.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            connect_host=str(address),
            server_hostname=target.hostname,
            port=target.port,
            timeout=remaining,
        )
    else:
        connection = http.client.HTTPConnection(str(address), target.port, timeout=remaining)

    request_headers = dict(headers)
    request_headers["Host"] = target.host_header
    try:
        connection.request(method, target.request_target, body=body, headers=request_headers)
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("webhook delivery deadline exceeded waiting for response")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        response = connection.getresponse()
        code = response.status
        if 200 <= code < 300 and not capture_body:
            # Successful webhook bodies are irrelevant; do not read them at all.
            excerpt = ""
        else:
            excerpt = _read_error_excerpt(response, deadline=deadline)
        return code, excerpt
    finally:
        connection.close()


def request(
    method: str,
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private: bool = False,
    capture_body: bool = False,
) -> DeliveryResult:
    """One request over the pinned, SSRF-validated wire.

    ``post`` is this with ``method="POST"``. Status polling and status
    reflection (:mod:`api.services.integrations.ticket_sync`) need GET and
    PATCH against the same trackers, and they must not get there over a plain
    HTTP client: the base URL comes from a stored subscription, so it is
    exactly the kind of value the SSRF guard exists for.
    """
    started = time.perf_counter()
    deadline = started + max(1.0, float(timeout_seconds))
    try:
        target = _parse_target(url, allow_private=allow_private)
    except WebhookTargetError as exc:
        return DeliveryResult(
            ok=False,
            status_code=None,
            error=str(exc),
            retryable=False,
            duration_seconds=time.perf_counter() - started,
        )

    if not target.addresses:
        return DeliveryResult(
            ok=False,
            status_code=None,
            error=f"DNS resolution failed for webhook host {target.hostname}",
            retryable=True,
            duration_seconds=time.perf_counter() - started,
        )

    last_error: Exception | None = None
    for address in target.addresses:
        try:
            code, excerpt = _send_to_address(
                target,
                address,
                body,
                headers,
                method=method,
                deadline=deadline,
                capture_body=capture_body,
            )
        except Exception as exc:  # noqa: BLE001 - socket/ssl/http.client family
            last_error = exc
            if time.perf_counter() >= deadline:
                break
            continue

        duration = time.perf_counter() - started
        if 200 <= code < 300:
            return DeliveryResult(
                ok=True,
                status_code=code,
                error=None,
                retryable=False,
                duration_seconds=duration,
                body=excerpt or None,
            )
        retryable = code >= 500 or code in (408, 429)
        return DeliveryResult(
            ok=False,
            status_code=code,
            error=f"HTTP {code}: {excerpt}" if excerpt else f"HTTP {code}",
            retryable=retryable,
            duration_seconds=duration,
        )

    error = last_error or TimeoutError("webhook delivery deadline exceeded")
    return DeliveryResult(
        ok=False,
        status_code=None,
        error=f"{type(error).__name__}: {error}"[:_ERROR_EXCERPT_CHARS],
        retryable=True,
        duration_seconds=time.perf_counter() - started,
    )


def post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private: bool = False,
    capture_body: bool = False,
) -> DeliveryResult:
    """POST one delivery, pinned to the addresses that passed SSRF validation.

    Redirects are never followed. The timeout is a wall-clock budget shared by
    connection, request, response headers and the bounded error-body read.
    Every failure is returned as data so one bad receiver cannot crash the
    dispatcher thread.
    """
    return request(
        "POST",
        url,
        body,
        headers,
        timeout_seconds=timeout_seconds,
        allow_private=allow_private,
        capture_body=capture_body,
    )
