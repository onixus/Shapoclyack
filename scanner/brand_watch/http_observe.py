"""Brand-watch HTTP observation (M2).

At most two GETs: ``/`` and, when the first page answers, ``/favicon.ico``.
Bodies are byte-capped. No POST, no cookies, no JavaScript, no proxy, no
path brute, no nuclei. A redirect to another host is recorded and not
followed. Same-host redirects are followed up to a small hop cap so a
trailing-slash bounce does not hide the page; the first cross-host
``Location`` stops the walk.

The only address dialled is one the caller just got back from DNS for this
name, and only when it is public. Sinkholes (``0.0.0.0/8``, ``127.0.0.0/8``,
``::``, ``::1``) and anything ``scanner.pipeline.safe_http.is_public_address``
rejects are refused before a socket is opened. TLS subject, SAN and
``not_before`` are captured from the handshake; the peer certificate PEM is
never stored.

The result is an evidence pack: hashes, a short title, a short visible-text
excerpt, certificate fields, and the redirect host. Raw HTML is parsed
inside this module and is not returned.
"""

from __future__ import annotations

import hashlib
import html
import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx

from scanner.pipeline.parking import match_parking
from scanner.pipeline.safe_http import is_public_address

from .similarity import (
    EMPTY_VISIBLE_WORDS,
    YOUNG_DAYS,
    brand_in_cert,
    shingle_overlap,
)

USER_AGENT = "shapoclyack/brand-watch"
BODY_MAX_BYTES = 64 * 1024
FAVICON_MAX_BYTES = 32 * 1024
TITLE_MAX_CHARS = 200
EXCERPT_MAX_CHARS = 200
#: The whole observation is two GETs. A same-host redirect spends the second
#: one, and the favicon is skipped. A cross-host Location is never requested.
MAX_REQUESTS = 2
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
DEFAULT_TIMEOUT = 10.0

_SINKHOLE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = tuple(
    ipaddress.ip_network(network) for network in ("0.0.0.0/8", "127.0.0.0/8", "::/128", "::1/128")
)
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")
_SITE_LOCAL = ipaddress.IPv6Network("fec0::/10")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(
    r"<(script|style|noscript)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_PASSWORD_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*[\"']?password\b", re.IGNORECASE
)
_WS_RE = re.compile(r"\s+")


class RefusedAddress(ValueError):
    """The DNS answer is not a public address this observer may dial."""

    def __init__(self, address: str, reason: str) -> None:
        super().__init__(f"{address}: {reason}")
        self.address = address
        self.reason = reason


@dataclass(frozen=True)
class HttpObservationRequest:
    """One name plus the address DNS just returned for it."""

    name: str
    address: str
    brand: str
    mx_present: bool = False
    registered: bool = True
    #: RDAP registration time, if the caller already has it. Optional.
    rdap_created: datetime | None = None
    #: sha256 hex digests of reference favicons. Empty means "no reference".
    favicon_references: tuple[str, ...] = ()
    #: Visible-text excerpts of the real brand site. Empty skips shingles.
    reference_excerpts: tuple[str, ...] = ()
    scheme: str = "https"
    port: int | None = None
    now: datetime | None = None


def refuse_reason(address: str) -> str | None:
    """Why ``address`` must not be dialled, or ``None`` when it may.

    Sinkholes first (a filtering resolver's answer), then the project's
    public-address rule. A non-address is refused as a sinkhole: there is
    nothing to dial.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "sinkholed"
    embedded = getattr(ip, "ipv4_mapped", None)
    if embedded is None and ip in _NAT64_WELL_KNOWN:
        embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    inner = embedded if embedded is not None else ip
    if any(inner.version == network.version and inner in network for network in _SINKHOLE_NETWORKS):
        return "sinkholed"
    if not is_public_address(ip) or ip in _SITE_LOCAL:
        return "private_address"
    return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bracket(address: str) -> str:
    if ":" in address and not address.startswith("["):
        return f"[{address}]"
    return address


def _origin(scheme: str, address: str, port: int) -> str:
    default = 443 if scheme == "https" else 80
    host = _bracket(address)
    if port == default:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def visible_text(raw_html: str) -> str:
    """Tags, scripts, styles and comments stripped; whitespace collapsed."""
    without = _SCRIPT_STYLE_RE.sub(" ", raw_html or "")
    without = _COMMENT_RE.sub(" ", without)
    without = _TAG_RE.sub(" ", without)
    return _WS_RE.sub(" ", html.unescape(without)).strip()


def page_title(raw_html: str) -> str:
    """First ``<title>``, tags stripped, collapsed, capped at 200 characters."""
    match = _TITLE_RE.search(raw_html or "")
    if match is None:
        return ""
    text = visible_text(match.group(1))
    return text[:TITLE_MAX_CHARS]


def has_password_input(raw_html: str) -> bool:
    """True when the first page contains ``<input type=password>``."""
    return _PASSWORD_RE.search(raw_html or "") is not None


def _location_host(location: str, current_host: str) -> str | None:
    """Host of ``Location``, or ``current_host`` for a relative URL."""
    if not location:
        return None
    parts = urlsplit(location)
    if parts.scheme and parts.scheme.lower() not in {"http", "https"}:
        return None
    if not parts.netloc:
        return current_host
    return (parts.hostname or "").casefold() or None


def _same_host(left: str, right: str) -> bool:
    return left.casefold().rstrip(".") == right.casefold().rstrip(".")


def _young(moment: datetime | None, now: datetime) -> bool:
    if moment is None:
        return False
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return now - YOUNG_DAYS * timedelta(days=1) <= moment <= now + timedelta(days=1)


def _cert_names(peer: dict[str, Any] | None) -> tuple[str, tuple[str, ...], datetime | None]:
    """CN, SAN DNS names, and ``not_before``. No PEM, no raw cert."""
    if not peer:
        return "", (), None
    subject_cn = ""
    for rdn in peer.get("subject") or ():
        for attr, value in rdn:
            if attr == "commonName":
                subject_cn = str(value)
                break
        if subject_cn:
            break
    san: list[str] = []
    for kind, value in peer.get("subjectAltName") or ():
        if str(kind).casefold() == "dns":
            san.append(str(value))
    not_before = _parse_ssl_date(peer.get("notBefore"))
    return subject_cn, tuple(san), not_before


def _parse_ssl_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _read_capped(response: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes``. Returns ``(body, truncated)``."""
    chunks: list[bytes] = []
    total = 0
    truncated = False
    for chunk in response.iter_bytes():
        if not chunk:
            continue
        remaining = max_bytes - total
        if remaining <= 0:
            truncated = True
            break
        if len(chunk) > remaining:
            chunks.append(chunk[:remaining])
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            # One extra empty iteration is avoided: the next chunk, if any,
            # would prove truncation. Peeking costs a read, so a body that
            # lands exactly on the cap is reported as not truncated.
            break
    return b"".join(chunks), truncated


class _CaptureServerHostname(httpx.Auth):
    """Grab ``getpeercert()`` during the handshake. Stores no PEM.

    httpx does not expose the peer certificate on the response. An auth
    flow runs after the connection is up and before the body is read, which
    is the only hook that can see the verified cert dict without a second
    TLS stack. ``sync_auth_flow`` is enough: this observer is synchronous.
    """

    def __init__(self) -> None:
        self.peer: dict[str, Any] | None = None

    def sync_auth_flow(self, request: httpx.Request):  # type: ignore[no-untyped-def]
        response = yield request
        stream = getattr(response, "extensions", None) or {}
        network = stream.get("network_stream")
        self.peer = _peer_from_stream(network)
        return response


def _peer_from_stream(network: Any) -> dict[str, Any] | None:
    """``getpeercert()`` dict, or ``None``. Never the PEM form."""
    ssl_object = getattr(network, "get_extra_info", None)
    if ssl_object is None:
        return None
    try:
        obj = network.get_extra_info("ssl_object")
    except Exception:  # noqa: BLE001 - a missing extension is "no cert", not a failure
        return None
    if obj is None:
        return None
    try:
        # binary_form=False is the dict. binary_form=True is DER; never requested.
        cert = obj.getpeercert(binary_form=False)
    except Exception:  # noqa: BLE001 - handshake already finished; cert is optional
        return None
    if not isinstance(cert, dict):
        return None
    return cert


def _empty_pack(
    request: HttpObservationRequest,
    *,
    state: str,
    skip_reason: str | None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "name": request.name,
        "address": request.address,
        "brand": request.brand,
        "state": state,
        "skip_reason": skip_reason,
        "error": error,
        "scheme": request.scheme,
        "status": None,
        "redirect_host": None,
        "redirected_off_host": False,
        "title": "",
        "excerpt": "",
        "body_sha256": None,
        "favicon_sha256": None,
        "favicon_match": False,
        "password_form": False,
        "parked": False,
        "parking_marker": None,
        "mx_present": request.mx_present,
        "registered": request.registered,
        "cert": {
            "subject_cn": "",
            "san": [],
            "not_before": None,
        },
        "rdap_created": _iso(request.rdap_created),
        "young_domain": False,
        "young_cert": False,
        "brand_in_title": False,
        "brand_in_cert": False,
        "shingle_overlap": 0.0,
        "empty_spa": False,
        "live": False,
        "has_site": False,
        "truncated": False,
        "requests": 0,
    }


def _iso(moment: datetime | None) -> str | None:
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def observe_http(
    request: HttpObservationRequest,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    cert_lookup: Callable[[], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Fetch ``/`` and maybe ``/favicon.ico``. Return an evidence pack.

    ``transport`` is the test seam (``httpx.MockTransport``). Production
    leaves it ``None`` and dials the pinned address with ``trust_env=False``
    so no proxy is consulted. ``cert_lookup``, when given, supplies the
    peer-certificate dict instead of the handshake hook — tests use it so
    they do not need a TLS stack. The dict is the ``getpeercert()`` shape;
    PEM is neither accepted nor returned.

    Raises :class:`RefusedAddress` when ``address`` is not public. Callers
    that want a pack instead of an exception should use
    :func:`observe_http_or_refuse`.
    """
    reason = refuse_reason(request.address)
    if reason is not None:
        raise RefusedAddress(request.address, reason)

    scheme = request.scheme if request.scheme in {"https", "http"} else "https"
    port = request.port or (443 if scheme == "https" else 80)
    origin = _origin(scheme, request.address, port)
    now = request.now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    capture = _CaptureServerHostname()
    client = httpx.Client(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT},
        auth=capture,
        verify=True,
    )
    requests_made = 0
    try:
        page, redirect_host, off_host, requests_made = _fetch_root(
            client,
            origin=origin,
            name=request.name,
            scheme=scheme,
            budget=MAX_REQUESTS,
        )
        peer = cert_lookup() if cert_lookup is not None else capture.peer
        favicon_sha: str | None = None
        favicon_match = False
        if page is not None:
            body, status, truncated = page
            favicon_sha, favicon_match, favicon_requests = _fetch_favicon(
                client,
                origin=origin,
                name=request.name,
                references=request.favicon_references,
                allowed=not off_host and status < 400 and requests_made < MAX_REQUESTS,
            )
            requests_made += favicon_requests
        else:
            body, status, truncated = b"", None, False
    finally:
        client.close()

    subject_cn, san, not_before = _cert_names(peer)
    young_cert = _young(not_before, now)
    young_domain = _young(request.rdap_created, now)

    if page is None:
        pack = _empty_pack(request, state="resolving", skip_reason=None, error="no_answer")
        pack["requests"] = requests_made
        pack["redirect_host"] = redirect_host
        pack["redirected_off_host"] = off_host
        pack["young_domain"] = young_domain
        pack["young_cert"] = young_cert
        pack["cert"] = _cert_fields(subject_cn, san, not_before)
        pack["brand_in_cert"] = brand_in_cert(request.brand, subject_cn, san)
        return pack

    body, status, truncated = page
    # Decode only for parsing. The decoded text is not placed in the pack.
    text = body.decode("utf-8", errors="replace")
    title = page_title(text)
    visible = visible_text(text)
    words = visible.split()
    empty = len(words) < EMPTY_VISIBLE_WORDS and not has_password_input(text)
    password = has_password_input(text)
    parking = match_parking(title, visible)

    brand_title = bool(request.brand) and request.brand.casefold() in title.casefold()
    brand_cert = brand_in_cert(request.brand, subject_cn, san)
    overlap = shingle_overlap(visible, request.reference_excerpts) if not empty else 0.0

    pack = {
        "name": request.name,
        "address": request.address,
        "brand": request.brand,
        "state": "parked" if parking else "http_live",
        "skip_reason": "empty_spa" if empty and not parking else None,
        "error": None,
        "scheme": scheme,
        "status": status,
        "redirect_host": redirect_host,
        "redirected_off_host": off_host,
        "title": title,
        "excerpt": visible[:EXCERPT_MAX_CHARS],
        "body_sha256": _sha256(body),
        "favicon_sha256": favicon_sha,
        "favicon_match": favicon_match,
        "password_form": password,
        "parked": parking is not None,
        "parking_marker": parking[0] if parking else None,
        "mx_present": request.mx_present,
        "registered": request.registered,
        "cert": _cert_fields(subject_cn, san, not_before),
        "rdap_created": _iso(request.rdap_created),
        "young_domain": young_domain,
        "young_cert": young_cert,
        "brand_in_title": brand_title,
        "brand_in_cert": brand_cert,
        "shingle_overlap": round(overlap, 4),
        "empty_spa": empty and not parking,
        "live": True,
        "has_site": True,
        "truncated": truncated,
        "requests": requests_made,
    }
    _assert_no_html(pack, text)
    return pack


def _cert_fields(
    subject_cn: str, san: tuple[str, ...], not_before: datetime | None
) -> dict[str, Any]:
    return {
        "subject_cn": subject_cn,
        "san": list(san),
        "not_before": _iso(not_before),
    }


def _assert_no_html(pack: dict[str, Any], raw: str) -> None:
    """The pack must not carry the page. A programming error if it does."""
    if not raw or len(raw) < 40:
        return
    blob = repr(pack)
    if raw[:80] in blob:
        raise RuntimeError("evidence pack included raw HTML")


def _fetch_root(
    client: httpx.Client,
    *,
    origin: str,
    name: str,
    scheme: str,
    budget: int,
) -> tuple[tuple[bytes, int, bool] | None, str | None, bool, int]:
    """GET ``/``, following only same-host redirects.

    Returns ``(page, redirect_host, off_host, requests)``. ``page`` is
    ``(body, status, truncated)`` of the last same-host response, or ``None``
    when nothing answered. A cross-host ``Location`` sets ``redirect_host``
    and ``off_host`` and is not requested.
    """
    url = f"{origin}/"
    requests_made = 0
    redirect_host: str | None = None
    off_host = False
    page: tuple[bytes, int, bool] | None = None
    current_host = name
    while requests_made < budget:
        requests_made += 1
        try:
            response = client.send(
                client.build_request(
                    "GET",
                    url,
                    headers={"Host": name},
                    extensions={"sni_hostname": name} if scheme == "https" else {},
                ),
                stream=True,
            )
        except httpx.HTTPError:
            break
        try:
            body, truncated = _read_capped(response, BODY_MAX_BYTES)
        finally:
            response.close()
        page = (body, response.status_code, truncated)
        location = response.headers.get("location")
        if response.status_code not in REDIRECT_STATUSES or not location:
            break
        host = _location_host(location, current_host)
        if host is None or not _same_host(host, name):
            redirect_host = host
            off_host = True
            # The redirect response itself is not the page. Drop it so a
            # parking interstitial on the foreign host is not scored.
            page = None
            break
        url = _next_url(origin, location)
        current_host = host
    return page, redirect_host, off_host, requests_made


def _next_url(origin: str, location: str) -> str:
    parts = urlsplit(location)
    if parts.scheme and parts.netloc:
        # Same host already checked by the caller. Keep the pinned origin so
        # the dial stays on the DNS address, not on a name httpx would resolve.
        path = parts.path or "/"
        query = f"?{parts.query}" if parts.query else ""
        return f"{origin}{path}{query}"
    if location.startswith("/"):
        return f"{origin}{location}"
    return f"{origin}/{location}"


def _fetch_favicon(
    client: httpx.Client,
    *,
    origin: str,
    name: str,
    references: tuple[str, ...],
    allowed: bool,
) -> tuple[str | None, bool, int]:
    """One GET of ``/favicon.ico``, capped. Skipped when the root did not answer."""
    if not allowed:
        return None, False, 0
    try:
        response = client.send(
            client.build_request("GET", f"{origin}/favicon.ico", headers={"Host": name}),
            stream=True,
        )
    except httpx.HTTPError:
        return None, False, 1
    try:
        if response.status_code != 200:
            return None, False, 1
        body, _truncated = _read_capped(response, FAVICON_MAX_BYTES)
    finally:
        response.close()
    if not body:
        return None, False, 1
    digest = _sha256(body)
    wanted = {item.casefold() for item in references}
    return digest, digest.casefold() in wanted, 1


def observe_http_or_refuse(
    request: HttpObservationRequest,
    **kwargs: Any,
) -> dict[str, Any]:
    """Like :func:`observe_http`, but a refused address is a pack, not a raise."""
    reason = refuse_reason(request.address)
    if reason is not None:
        pack = _empty_pack(request, state="resolving", skip_reason=reason, error=reason)
        return pack
    return observe_http(request, **kwargs)


