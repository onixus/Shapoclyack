"""The wire half of webhook delivery (ROADMAP P2 / Phase 10.3).

Everything here is stateless and database-free so the queue in ``webhooks.py``
can be tested without a network and this can be tested without Postgres.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import socket
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
# cannot fill the audit table.
_ERROR_EXCERPT_CHARS = 500


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


def validate_url(url: str, *, allow_private: bool = False) -> str:
    """Return the URL if it is a legal webhook target, else raise.

    Called both when a subscription is written (so an operator learns
    immediately) and again immediately before every POST (so a hostname that
    later resolves into the cluster is caught then, not only at creation).
    """
    url = (url or "").strip()
    if not url:
        raise WebhookTargetError("webhook url required")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise WebhookTargetError("webhook url must be http or https")
    if not parts.hostname:
        raise WebhookTargetError("webhook url must include a host")
    if allow_private:
        return url
    for address in _resolve(parts.hostname):
        if not address.is_global or address.is_multicast:
            raise WebhookTargetError(
                f"webhook host {parts.hostname} resolves to non-public address {address}; "
                "set OCTO_WEBHOOK_ALLOW_PRIVATE_TARGETS=true to allow it"
            )
    return url


def _resolve(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address ``hostname`` resolves to. Unresolvable → empty list.

    A name that does not resolve is not a policy decision to make here: the
    POST will fail on its own and be retried, which is the right handling for
    a receiver whose DNS is briefly down.
    """
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
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:  # pragma: no cover - getaddrinfo returned a non-address
            continue
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


def post(
    url: str,
    body: bytes,
    headers: dict[str, str],
    *,
    timeout_seconds: int = 10,
    allow_private: bool = False,
) -> DeliveryResult:
    """POST one delivery. Never raises — every failure becomes a result.

    Redirects are not followed: a 302 to an internal address would walk around
    the check ``validate_url`` just made, and a webhook receiver that answers
    with a redirect is misconfigured rather than relocated.
    """
    import httpx

    started = time.perf_counter()
    try:
        validate_url(url, allow_private=allow_private)
    except WebhookTargetError as exc:
        # Not retryable: re-resolving the same name in five minutes is not going
        # to make it public. The operator has to change the URL (or the flag).
        return DeliveryResult(
            ok=False,
            status_code=None,
            error=str(exc),
            retryable=False,
            duration_seconds=time.perf_counter() - started,
        )

    try:
        response = httpx.post(
            url,
            content=body,
            headers=headers,
            timeout=timeout_seconds,
            follow_redirects=False,
        )
    except Exception as exc:  # noqa: BLE001 - httpx raises a family of transport errors
        return DeliveryResult(
            ok=False,
            status_code=None,
            error=f"{type(exc).__name__}: {exc}"[:_ERROR_EXCERPT_CHARS],
            retryable=True,
            duration_seconds=time.perf_counter() - started,
        )

    duration = time.perf_counter() - started
    code = response.status_code
    if 200 <= code < 300:
        return DeliveryResult(ok=True, status_code=code, error=None, retryable=False, duration_seconds=duration)
    excerpt = (response.text or "").strip()[:_ERROR_EXCERPT_CHARS]
    retryable = code >= 500 or code in (408, 429)
    return DeliveryResult(
        ok=False,
        status_code=code,
        error=f"HTTP {code}: {excerpt}" if excerpt else f"HTTP {code}",
        retryable=retryable,
        duration_seconds=duration,
    )
