"""SSRF-safe outbound HTTPS for scanner stages (org_profile M1).

Every other outbound client in ``scanner/`` (``asn_discovery.py``,
``fingerprint.py``, ``cloud_discovery.py``, ``hostnames.py``) talks to a
*constant* host, follows redirects and never looks at the address it lands on.
That is safe only because the URL is a literal in the source. ``ownership.py``
is the first stage whose next hop is chosen by a remote party -- the IANA
bootstrap file names the registry server, and ``rdap.org`` answers with a 302 to
one -- so the address has to be validated on this side of the wire.

This is a deliberate *second* implementation of the boundary that already lives
in ``api/services/integrations/delivery.py`` (``_parse_target``, ``_resolve``,
``_PinnedHTTPSConnection``, ``_read_error_excerpt``), which is the original and
stays authoritative for webhook delivery. It is copied rather than imported
because ``scanner/`` does not import ``api/`` -- the scanner ships as its own
container without the API package, and adding that dependency to reuse ~80
lines would couple the two deployables far more than it saves.

Differences from the webhook boundary, all tightening it:

- https only (a webhook may legitimately target plain http on-cluster);
- no ``allow_private`` escape hatch, and no way to turn off certificate
  verification or address pinning from config -- neither is a setting;
- redirects may be followed, but every ``Location`` is re-parsed, re-resolved
  and re-validated by the same code as the first hop, so a 302 cannot walk the
  request into link-local space or downgrade it to http;
- the response body is read under a byte cap.

Pinning matters as much as validation: without it a target with TTL=0 answers
the ``getaddrinfo`` used for validation with a public address and the one the
TLS library performs at connect time with 169.254.169.254. The socket therefore
dials an already-approved IP literal while SNI and certificate verification use
the DNS name.

``http.client`` is used rather than ``httpx`` for the same reason: it performs
no name resolution of its own and honours no ``HTTP_PROXY``/``HTTPS_PROXY``
environment variables. A proxy inherited from an agent's environment would
route the request through a third party and void the pinning entirely.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlsplit

LOG = logging.getLogger("shapoclyack.safe-http")

#: Default body cap. Callers that expect larger documents pass their own.
DEFAULT_MAX_BODY_BYTES = 256 * 1024
_READ_CHUNK_BYTES = 8192
_REDIRECT_CODES = (301, 302, 303, 307, 308)


class SafeHttpError(Exception):
    """A safe request could not be completed (DNS, deadline, or transport)."""


class UnsafeTargetError(SafeHttpError, ValueError):
    """The URL is not a legal scanner target (scheme, userinfo, or address)."""


#: Everything a fail-soft caller has to catch around :func:`get`. ``OSError``
#: covers ``socket``/``ssl``/``TimeoutError``; ``HTTPException`` covers a peer
#: that answers with something that is not HTTP.
SAFE_HTTP_ERRORS = (SafeHttpError, OSError, http.client.HTTPException)


@dataclass(frozen=True)
class SafeResponse:
    """One completed response, body already read and capped."""

    url: str
    status: int
    #: Header names lowercased; duplicates keep the last value.
    headers: dict[str, str]
    body: bytes
    #: True when the body hit ``max_bytes`` and the rest was never read.
    truncated: bool


@dataclass(frozen=True)
class _ResolvedTarget:
    """A URL plus the exact addresses approved for this request."""

    hostname: str
    port: int
    request_target: str
    host_header: str
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


def _resolve(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address ``hostname`` resolves to. Unresolvable -> empty list."""
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


def _parse_target(url: str) -> _ResolvedTarget:
    """Validate one URL and pin the addresses it is allowed to reach.

    The *whole* address set has to pass: a name that answers with one public
    and one loopback address is rejected outright, because which one the
    connection would use is not this code's decision to make.
    """
    url = (url or "").strip()
    if not url:
        raise UnsafeTargetError("request url required")
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        # urlsplit raises a bare ValueError on a malformed IPv6 literal ("[" in
        # the netloc). The next hop is named by the remote side -- the IANA
        # bootstrap file, or the cached copy of it -- so an unhandled ValueError
        # here would escape SAFE_HTTP_ERRORS and take the whole run down from
        # inside a stage that is documented as fail-soft.
        raise UnsafeTargetError("request url is malformed") from exc
    if parts.scheme != "https":
        raise UnsafeTargetError(f"request url must be https, got {parts.scheme or 'no scheme'!r}")
    if not parts.hostname:
        raise UnsafeTargetError("request url must include a host")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTargetError("request url must not contain userinfo")
    try:
        port = parts.port
    except ValueError as exc:
        raise UnsafeTargetError("request url contains an invalid port") from exc
    port = port or 443

    addresses = tuple(_resolve(parts.hostname))
    if not addresses:
        raise SafeHttpError(f"DNS resolution failed for {parts.hostname}")
    for address in addresses:
        if not address.is_global or address.is_multicast:
            raise UnsafeTargetError(
                f"host {parts.hostname} resolves to non-public address {address}"
            )

    path = parts.path or "/"
    request_target = f"{path}?{parts.query}" if parts.query else path
    host = parts.hostname
    host_for_header = f"[{host}]" if ":" in host else host
    host_header = host_for_header if port == 443 else f"{host_for_header}:{port}"
    return _ResolvedTarget(
        hostname=host,
        port=port,
        request_target=request_target,
        host_header=host_header,
        addresses=addresses,
    )


def validate_url(url: str) -> str:
    """Return the URL if it is a legal scanner target, else raise."""
    _parse_target(url)
    return (url or "").strip()


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


def _read_body(
    response: http.client.HTTPResponse,
    *,
    deadline: float,
    max_bytes: int,
) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` while respecting the wall-clock budget.

    Both bounds are needed. The cap alone still lets a peer trickle one byte
    per minute; the deadline alone still lets it stream gigabytes inside the
    budget. The remaining time is pushed onto the socket on every iteration so
    a stalled read cannot outlive the request.
    """
    chunks: list[bytes] = []
    remaining_bytes = max_bytes
    truncated = False
    while remaining_bytes > 0:
        remaining_time = deadline - time.perf_counter()
        if remaining_time <= 0:
            raise SafeHttpError("request deadline exceeded while reading response body")
        sock = getattr(response, "fp", None)
        raw = getattr(sock, "raw", None)
        socket_obj = getattr(raw, "_sock", None)
        if socket_obj is not None:
            socket_obj.settimeout(remaining_time)
        chunk = response.read(min(_READ_CHUNK_BYTES, remaining_bytes))
        if not chunk:
            break
        chunks.append(chunk)
        remaining_bytes -= len(chunk)
    else:
        # The cap was reached exactly; anything still on the wire is dropped.
        truncated = bool(response.read(1))
    return b"".join(chunks), truncated


def _request_once(
    target: _ResolvedTarget,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    headers: dict[str, str],
    *,
    deadline: float,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes, bool]:
    """Send one GET to an already-approved IP without resolving anything."""
    remaining = deadline - time.perf_counter()
    if remaining <= 0:
        raise SafeHttpError("request deadline exceeded before connect")

    connection = _PinnedHTTPSConnection(
        connect_host=str(address),
        server_hostname=target.hostname,
        port=target.port,
        timeout=remaining,
    )
    request_headers = dict(headers)
    request_headers["Host"] = target.host_header
    try:
        connection.request("GET", target.request_target, headers=request_headers)
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise SafeHttpError("request deadline exceeded waiting for response")
        if connection.sock is not None:
            connection.sock.settimeout(remaining)
        response = connection.getresponse()
        body, truncated = _read_body(response, deadline=deadline, max_bytes=max_bytes)
        collected = {name.lower(): value for name, value in response.getheaders()}
        return response.status, collected, body, truncated
    finally:
        connection.close()


def get(
    url: str,
    *,
    timeout_seconds: float,
    max_bytes: int = DEFAULT_MAX_BODY_BYTES,
    headers: dict[str, str] | None = None,
    max_redirects: int = 0,
) -> SafeResponse:
    """GET ``url`` over pinned, verified HTTPS and return the capped response.

    ``timeout_seconds`` is one wall-clock budget covering connect, request,
    response headers and the body read of *every* hop -- a redirect chain does
    not get a fresh timeout per hop. Each ``Location`` goes back through
    :func:`_parse_target`, so a redirect to http, to a private address or to a
    URL with userinfo raises :class:`UnsafeTargetError` instead of being
    followed.
    """
    deadline = time.perf_counter() + max(1.0, float(timeout_seconds))
    request_headers = dict(headers or {})
    current = (url or "").strip()

    for _ in range(max_redirects + 1):
        target = _parse_target(current)
        last_error: Exception | None = None
        hop: tuple[int, dict[str, str], bytes, bool] | None = None
        for address in target.addresses:
            try:
                hop = _request_once(
                    target,
                    address,
                    request_headers,
                    deadline=deadline,
                    max_bytes=max_bytes,
                )
            except SAFE_HTTP_ERRORS as exc:
                last_error = exc
                if time.perf_counter() >= deadline:
                    break
                continue
            break
        if hop is None:
            raise SafeHttpError(
                f"no address of {target.hostname} could be reached: "
                f"{type(last_error).__name__}: {last_error}"
            ) from last_error
        status, response_headers, body, truncated = hop

        location = response_headers.get("location")
        if status in _REDIRECT_CODES and location:
            # Relative Location is legal (RFC 9110) and must be resolved
            # against the hop that produced it before revalidation.
            current = urljoin(current, location.strip())
            continue
        return SafeResponse(
            url=current,
            status=status,
            headers=response_headers,
            body=body,
            truncated=truncated,
        )

    raise SafeHttpError(f"too many redirects (>{max_redirects}) starting at {url}")


def json_body(response: SafeResponse) -> Any:
    """Decode a capped body as JSON.

    Parsing happens on the already-bounded ``bytes``, never on a live stream:
    a streaming JSON decode would read past ``max_bytes`` to find the closing
    brace, which is exactly the read the cap exists to prevent.
    """
    if response.truncated:
        raise SafeHttpError(f"response body from {response.url} exceeded the size cap")
    try:
        return json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SafeHttpError(f"response from {response.url} is not valid JSON") from exc
