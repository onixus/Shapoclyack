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
from urllib.parse import urlsplit

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


class WebhookTargetError(ValueError):
    """The URL is not a legal webhook target (bad scheme, or blocked address)."""


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


@dataclass(frozen=True)
class _ResolvedTarget:
    """A webhook URL plus the exact addresses approved for this delivery.

    The hostname is kept separately because HTTPS must verify the receiver's
    certificate and send SNI for the original DNS name even though the TCP
    socket is opened directly to one of the already-validated IP addresses.
    That separation is the SSRF boundary: no library resolver gets a second
    chance to turn the hostname into a different address after validation.
    """

    scheme: str
    hostname: str
    port: int
    request_target: str
    host_header: str
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


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
    url = (url or "").strip()
    if not url:
        raise WebhookTargetError("webhook url required")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise WebhookTargetError("webhook url must be http or https")
    if not parts.hostname:
        raise WebhookTargetError("webhook url must include a host")
    if parts.username is not None or parts.password is not None:
        raise WebhookTargetError("webhook url must not contain userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise WebhookTargetError("webhook url contains an invalid port") from exc
    port = port or (443 if parts.scheme == "https" else 80)

    addresses = tuple(_resolve(parts.hostname))
    if not allow_private:
        for address in addresses:
            if not address.is_global or address.is_multicast:
                raise WebhookTargetError(
                    f"webhook host {parts.hostname} resolves to non-public address {address}; "
                    "set OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS=true to allow it"
                )

    path = parts.path or "/"
    request_target = f"{path}?{parts.query}" if parts.query else path
    host = parts.hostname
    host_for_header = f"[{host}]" if ":" in host else host
    default_port = 443 if parts.scheme == "https" else 80
    host_header = host_for_header if port == default_port else f"{host_for_header}:{port}"
    return _ResolvedTarget(
        scheme=parts.scheme,
        hostname=host,
        port=port,
        request_target=request_target,
        host_header=host_header,
        addresses=addresses,
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


def _resolve(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address ``hostname`` resolves to. Unresolvable → empty list."""
    try:
        literal = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        pass
    else:
        return [literal]
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:  # pragma: no cover - getaddrinfo returned a non-address
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


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


def _post_to_address(
    target: _ResolvedTarget,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    body: bytes,
    headers: dict[str, str],
    *,
    deadline: float,
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
        connection.request("POST", target.request_target, body=body, headers=request_headers)
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("webhook delivery deadline exceeded waiting for response")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        response = connection.getresponse()
        code = response.status
        # Successful webhook bodies are irrelevant; do not read them at all.
        excerpt = "" if 200 <= code < 300 else _read_error_excerpt(response, deadline=deadline)
        return code, excerpt
    finally:
        connection.close()


def post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private: bool = False,
) -> DeliveryResult:
    """POST one delivery, pinned to the addresses that passed SSRF validation.

    Redirects are never followed. The timeout is a wall-clock budget shared by
    connection, request, response headers and the bounded error-body read.
    Every failure is returned as data so one bad receiver cannot crash the
    dispatcher thread.
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
            code, excerpt = _post_to_address(
                target,
                address,
                body,
                headers,
                deadline=deadline,
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
