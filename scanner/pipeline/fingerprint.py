"""Tech stack fingerprinting (Phase 9.1, catalogue since DQ4).

Reuses the already-discovered ``open_ports.txt`` endpoints from the ports
stage — this module never scans a new port itself. For each open TCP
endpoint that looks like a web port (``http_ports`` / ``https_ports``), it
GETs the root, size-capped, and classifies the answer against the
data-driven catalogue in ``fingerprint_catalogue.json`` (format, matcher
grammar and confidence levels: ``fingerprint_catalogue.py``):

  * every technology the response identifies -- CDN/WAF, load balancer, web
    and application server, framework, CMS, shop, admin and database UI,
    devops and monitoring console, VPN and remote-access portal, webmail,
    network appliance -- with its version where the product states one
    reliably and its NVD CPE where there is a single key for it;
  * the two lists consumers read since Phase 9.1, derived from the above:
    ``cdn_waf`` (CDN/WAF matches of *high* confidence only) and
    ``cms_framework`` (CMS, framework and e-commerce matches). Their names
    for the original eleven signatures are unchanged;
  * exposure findings (``exposures`` in ``fingerprint.json``) for
    high-confidence matches only: a console or management UI answering
    (``exposed_admin_interface``, rated by what it answered -- an open
    database API high, a console without a login page medium, a login page
    low), a VPN, remote-access or webmail portal
    (``exposed_remote_access_gateway``, info), and a version stated in a
    response header (``version_disclosure``, info).

Requests. One GET to ``scheme://host:port/``. A redirect is followed -- at
most ``MAX_REDIRECT_HOPS`` times -- only while it stays on the address the
stage was given (any scheme or port of that address: it is the same in-scope
host). A redirect anywhere else, a host name included, is recorded as
``redirect_location`` with ``redirected_off_host`` and not fetched: the stage
contacts nothing it was not given, and a name is the virtual-host case, which
is a target of its own. The client ignores ``HTTP(S)_PROXY`` (``trust_env``
off): scan traffic must not go through whatever proxy the sensor's
environment names. NSE (``nse.py``) emits no structured HTTP data this could
reuse, so this is the one HTTP client per endpoint; a ``/favicon.ico`` hash or
a probe of a known login path would identify more and would be a request of
its own, which is not made.

The scanned host writes the body, so classification is bounded: the page is
read by a linear scan, every catalogue regex has a bounded repeat count, and
classification runs in a worker thread against a deadline
(``CLASSIFY_SECONDS``). An endpoint that runs past it is reported with
``error: classification_timeout`` and nothing derived from its body.

HONESTY NOTE: the catalogue is a curated perimeter-first list (~150 entries),
not Wappalyzer. Its markers are public knowledge checked against synthetic
fixtures, not against a corpus of live captures; a product the catalogue does
not know, or one that hides its markers, is simply absent from the output.

SAFETY: disabled by default (``fingerprint.enabled = false``). Requests are
capped by ``concurrency`` (in-flight) and ``body_max_bytes`` (per-response,
via streamed read) and the candidate endpoint list itself is capped by
``max_targets`` -- past the cap, remaining endpoints are skipped and the run
is flagged "truncated" rather than silently scanning everything. Findings
are reported only (``fingerprint.json``) -- never merged into scan scope or
asset identity (same non-escalation principle as ``cloud_discovery.py``).
Risk scoring may apply a small named likelihood discount when ``cdn_waf``
was observed on the same host:port (#173); that is not a claim the
control blocks the CVE, and it is not merging the fingerprint into scope.
Only the six providers ``risk_scoring.CDN_WAF_PROVIDERS`` names earn it -- a
CDN/WAF the catalogue learned later is reported, not discounted -- and an
endpoint that redirected elsewhere has an empty ``cdn_waf``: a CDN in front
of the name it points at is not in front of this address.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from pathlib import Path
from typing import Any, NamedTuple

import httpx

from .config_schema import FingerprintConfig
from .fingerprint_catalogue import (
    Catalogue,
    ClassificationTimeout,
    Match,
    Response,
    load_catalogue,
)
from .protocol import is_ipv6, parse_endpoint
from .utils import save_json, write_lines

LOG = logging.getLogger("shapoclyack.fingerprint")

USER_AGENT = "shapoclyack/fingerprint"

#: Redirects followed per endpoint, all on the address the stage was given.
MAX_REDIRECT_HOPS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
#: Wall-clock budget for classifying one response. Normal pages take
#: milliseconds; the budget is for a body written to cost more.
CLASSIFY_SECONDS = 2.0

#: Categories whose high-confidence match is a finding, and its kind. Every
#: other category is inventory only. Webmail is a remote-access portal to the
#: mailbox and is filed with them; the category stays on the finding.
EXPOSURE_KIND_BY_CATEGORY: dict[str, str] = {
    "admin_panel": "exposed_admin_interface",
    "database_ui": "exposed_admin_interface",
    "database": "exposed_admin_interface",
    "devops": "exposed_admin_interface",
    "monitoring": "exposed_admin_interface",
    "network_appliance": "exposed_admin_interface",
    "remote_access": "exposed_remote_access_gateway",
    "mail_webmail": "exposed_remote_access_gateway",
}
VERSION_DISCLOSURE = ("version_disclosure", "info")

#: Categories that make up the Phase 9.1 ``cms_framework`` list.
CMS_FRAMEWORK_CATEGORIES = frozenset({"cms", "framework", "ecommerce"})

#: A path that is a login page by name (``/login``, ``/users/sign_in``,
#: ``/dana-na/auth/...``).
_LOGIN_PATH_RE = re.compile(
    r"(?:^|/)(?:login|log-in|logon|signin|sign-in|sign_in|auth|sso)(?:[/._?;-]|$)", re.IGNORECASE
)
_MATRIX_RE = re.compile(r";[^/]{0,2048}")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class _Fetched(NamedTuple):
    status: int
    headers: httpx.Headers
    body: str
    #: The URL that gave this answer (the endpoint, or a same-address hop).
    url: str
    #: Where an unfollowed redirect pointed, sanitized.
    redirect_location: str | None = None
    redirected_off_host: bool = False


def _candidate_endpoints(
    open_ports: list[str], http_ports: set[int], https_ports: set[int]
) -> list[tuple[str, int, str]]:
    """(host, port, scheme) tuples for open TCP endpoints on configured web ports.

    A port listed under *both* ``http_ports`` and ``https_ports`` yields a
    candidate for each scheme rather than just one. That is how a custom scan
    port -- one the operator asked for but whose scheme is unknown -- is
    covered: it is added to both sets (see ``extend_web_ports_with_custom``),
    so the endpoint is probed as http *and* https and a wrong scheme guess
    never silently drops it. The default port lists do not overlap, so this is
    a no-op for the built-in 80/443/... classification.
    """
    candidates: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != "tcp":
            continue
        try:
            port = int(parsed.port)
        except ValueError:
            continue
        schemes: list[str] = []
        if port in https_ports:
            schemes.append("https")
        if port in http_ports:
            schemes.append("http")
        for scheme in schemes:
            key = (parsed.host, port, scheme)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((parsed.host, port, scheme))
    candidates.sort()
    return candidates


def _build_url(host: str, port: int, scheme: str) -> str:
    hostpart = f"[{host}]" if is_ipv6(host) else host
    return f"{scheme}://{hostpart}:{port}/"


def _effective_port(url: httpx.URL) -> int:
    return url.port if url.port is not None else _DEFAULT_PORTS.get(url.scheme, 0)


def sanitize_url(url: str) -> str:
    """``scheme://host:port/path`` -- no userinfo, query, fragment or ``;params``.

    Every URL that reaches ``fingerprint.json`` goes through here: a redirect
    target's query can carry a return URL or a token, a path parameter a
    session id, and userinfo a password.
    """
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        return ""
    if parsed.scheme not in _DEFAULT_PORTS or not parsed.host:
        return ""
    host = f"[{parsed.host}]" if is_ipv6(parsed.host) else parsed.host
    return f"{parsed.scheme}://{host}:{_effective_port(parsed)}{_MATRIX_RE.sub('', parsed.path or '/')}"


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError):
        return None
    return parsed.scheme, (parsed.host or "").lower(), _effective_port(parsed)


def _same_address(host: str, target: str) -> bool:
    """The redirect stays on the address the stage was given (IPs compared as IPs)."""
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(target)
    except ValueError:
        return host.lower().rstrip(".") == target.lower().rstrip(".")


async def _read(resp: httpx.Response, max_bytes: int) -> str:
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.aiter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    return b"".join(chunks).decode("utf-8", errors="ignore")


async def _fetch(
    client: httpx.AsyncClient, url: str, timeout: float, max_bytes: int
) -> _Fetched | None:
    """GET ``url``, following redirects only while they stay on its address.

    A hop that fails returns the redirect that led to it, so what the target
    itself said is kept.
    """
    target = httpx.URL(url).host
    current = url
    last: _Fetched | None = None
    for hop in range(MAX_REDIRECT_HOPS + 1):
        try:
            async with client.stream("GET", current, timeout=timeout) as resp:
                body = await _read(resp, max_bytes)
                status, headers = resp.status_code, resp.headers
        except httpx.HTTPError as exc:
            LOG.debug("fingerprint: request failed for %s: %s", current, exc)
            return last
        location = headers.get("location") if status in REDIRECT_STATUSES else None
        if not location:
            return _Fetched(status, headers, body, current)
        try:
            nxt = httpx.URL(current).join(location.strip())
        except (httpx.InvalidURL, TypeError, ValueError):
            return _Fetched(status, headers, body, current)
        same = nxt.scheme in _DEFAULT_PORTS and bool(nxt.host) and _same_address(nxt.host, target)
        last = _Fetched(status, headers, body, current, sanitize_url(str(nxt)) or None, not same)
        if not same:
            return last
        # The hop itself carries no credentials, whatever the Location said.
        current = str(httpx.URL(scheme=nxt.scheme, host=nxt.host, port=nxt.port, raw_path=nxt.raw_path))
    return last


def _auth_required(resp: Response) -> bool:
    """The answer is a login: 401/403, a password field, or a login path."""
    if resp.status in (401, 403) or resp.page.password_input:
        return True
    return bool(_LOGIN_PATH_RE.search(resp.url_path.partition("?")[0]))


def _console_rating(match: Match, resp: Response, auth_required: bool) -> tuple[str, str]:
    name = match.technology.name
    if auth_required:
        return "low", f"{name} login page reachable (HTTP {resp.status})"
    if (
        match.technology.category == "database"
        and 200 <= resp.status < 300
        and not match.technology.root_is_public
    ):
        return "high", f"{name} answers its API without authentication (HTTP {resp.status})"
    return "medium", f"{name} answers with no login page in front (HTTP {resp.status})"


def _finding(
    kind: str, severity: str, outcome: dict[str, Any], match: Match, **extra: Any
) -> dict[str, Any]:
    origin = _origin(outcome["final_url"] or outcome["url"])
    return {
        "kind": kind,
        "severity": severity,
        "host": outcome["host"],
        "port": origin[2] if origin else outcome["port"],
        "url": outcome["final_url"] or sanitize_url(outcome["url"]),
        "technology": match.technology.id,
        "evidence": list(match.evidence),
        "name": match.technology.name,
        "category": match.technology.category,
        "version": match.version,
        "cpe": match.cpe,
        "confidence": match.confidence,
        "http_status": outcome["http_status"],
        **extra,
    }


def _exposures(outcome: dict[str, Any], matches: list[Match], resp: Response) -> list[dict[str, Any]]:
    """Exposure findings for one endpoint; none when its answer was a redirect elsewhere."""
    if outcome["redirected_off_host"]:
        return []
    auth_required = _auth_required(resp)
    found: list[dict[str, Any]] = []
    disclosed: set[str] = set()
    for match in matches:
        kind = EXPOSURE_KIND_BY_CATEGORY.get(match.technology.category)
        if kind is not None and match.confidence == "high":
            if kind == "exposed_remote_access_gateway":
                severity = "info"
                detail = f"{match.technology.name} portal reachable (HTTP {resp.status})"
            else:
                severity, detail = _console_rating(match, resp, auth_required)
            found.append(_finding(kind, severity, outcome, match, auth_required=auth_required, detail=detail))
        source = match.version_source or ""
        if not match.version or not source.startswith("header "):
            continue
        header = source.removeprefix("header ")
        if header in disclosed:
            continue
        disclosed.add(header)
        value = resp.header_value(header) or ""
        disclosure = _finding(
            *VERSION_DISCLOSURE,
            outcome,
            match,
            header=header,
            detail=f"{header}: {value}"[:160],
        )
        disclosure["evidence"] = [f"{header}: {value}"[:160]]
        found.append(disclosure)
    return found


def _classify(catalogue: Catalogue, fetched: _Fetched, deadline: float) -> tuple[Response, list[Match]]:
    resp = Response.build(fetched.status, fetched.headers, fetched.body, fetched.url)
    return resp, catalogue.match_response(resp, deadline=deadline)


async def _fingerprint_one(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    max_bytes: int,
    catalogue: Catalogue,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    url = _build_url(host, port, scheme)
    outcome: dict[str, Any] = {
        "host": host,
        "port": port,
        "scheme": scheme,
        "url": url,
        "final_url": None,
        "redirect_location": None,
        "redirected_off_host": False,
        "http_status": None,
        "server": "",
        "x_powered_by": "",
        "title": "",
        "cdn_waf": [],
        "cms_framework": [],
        "technologies": [],
        "error": None,
    }
    fetched = await _fetch(client, url, timeout, max_bytes)
    if fetched is None:
        outcome["error"] = "request_failed"
        return outcome, []

    outcome["final_url"] = sanitize_url(fetched.url)
    outcome["redirect_location"] = fetched.redirect_location
    outcome["redirected_off_host"] = fetched.redirected_off_host
    outcome["http_status"] = fetched.status
    outcome["server"] = fetched.headers.get("server", "")
    outcome["x_powered_by"] = fetched.headers.get("x-powered-by", "")
    # Off the event loop and against a deadline: the body is the scanned
    # host's to write, and one slow page must not stall every other request.
    deadline = time.monotonic() + CLASSIFY_SECONDS
    try:
        resp, matches = await asyncio.wait_for(
            asyncio.to_thread(_classify, catalogue, fetched, deadline), timeout=CLASSIFY_SECONDS + 1.0
        )
    except (ClassificationTimeout, asyncio.TimeoutError):
        LOG.warning("fingerprint: classification of %s ran past %.1fs; left unclassified", url, CLASSIFY_SECONDS)
        outcome["error"] = "classification_timeout"
        return outcome, []

    outcome["title"] = resp.title[:200]
    outcome["technologies"] = [match.as_dict() for match in matches]
    # Phase 9.1 consumers: the risk model reads cdn_waf for the #173 discount,
    # so only a CDN/WAF the catalogue is sure of, seen on this address, may
    # appear in it.
    if not fetched.redirected_off_host:
        outcome["cdn_waf"] = [
            m.technology.id for m in matches if m.technology.category == "cdn_waf" and m.confidence == "high"
        ]
    outcome["cms_framework"] = [
        m.technology.id for m in matches if m.technology.category in CMS_FRAMEWORK_CATEGORIES
    ]
    return outcome, _exposures(outcome, matches, resp)


def _dedupe_by_origin(exposures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One finding per origin: ``:80`` redirecting to ``:443`` is one console, not two."""
    seen: set[tuple[Any, ...]] = set()
    kept = []
    for item in exposures:
        key = (item["kind"], item["technology"], item.get("header"), _origin(item["url"]))
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    return kept


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "fingerprint.json", result)
    lines = []
    for finding in result["findings"]:
        if not finding["cdn_waf"] and not finding["cms_framework"]:
            continue
        tags = ",".join(finding["cdn_waf"] + finding["cms_framework"])
        lines.append(f"{finding['host']}:{finding['port']}:{finding['scheme']}:{tags}")
    write_lines(output_dir / "fingerprint_matches.txt", lines)


async def fingerprint_hosts(
    open_ports: list[str],
    config: FingerprintConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Async HTTP header/body fingerprinting across already-discovered open web ports."""
    result: dict[str, Any] = {
        "targets_considered": 0,
        "checked_count": 0,
        "findings": [],
        "exposures": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "fingerprint.disabled"
        _persist(output_dir, result)
        return result

    http_ports = set(config.http_ports)
    https_ports = set(config.https_ports)
    candidates = _candidate_endpoints(open_ports, http_ports, https_ports)
    result["targets_considered"] = len(candidates)
    if not candidates:
        result["skipped_reason"] = "no_web_ports"
        _persist(output_dir, result)
        return result

    catalogue = load_catalogue()
    result["catalogue"] = {
        "schema": catalogue.schema_version,
        "updated": catalogue.updated,
        "technologies": len(catalogue.technologies),
    }
    truncated = len(candidates) > config.max_targets
    candidates = candidates[: config.max_targets]

    timeout = float(config.timeout_seconds)
    semaphore = asyncio.Semaphore(config.concurrency)
    headers = {"User-Agent": USER_AGENT}

    async with httpx.AsyncClient(
        headers=headers, verify=config.verify_tls, follow_redirects=False, trust_env=False
    ) as client:

        async def _guarded(host: str, port: int, scheme: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
            async with semaphore:
                return await _fingerprint_one(
                    client, host, port, scheme, timeout, config.body_max_bytes, catalogue
                )

        outcomes = await asyncio.gather(
            *(_guarded(host, port, scheme) for host, port, scheme in candidates)
        )

    findings = [outcome for outcome, _ in outcomes]
    result["checked_count"] = len(findings)
    result["findings"] = findings
    result["exposures"] = _dedupe_by_origin([exposure for _, exposures in outcomes for exposure in exposures])
    result["truncated"] = truncated

    matched = sum(1 for f in findings if f["technologies"])
    _persist(output_dir, result)
    LOG.info(
        "fingerprint: %d endpoint(s) checked -> %d with an identified technology, %d exposure(s)%s",
        len(findings),
        matched,
        len(result["exposures"]),
        " [truncated]" if truncated else "",
    )
    return result


def fingerprint_hosts_sync(
    open_ports: list[str],
    config: FingerprintConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Sync wrapper for pipeline stages (uses ``asyncio.run``)."""
    return asyncio.run(fingerprint_hosts(open_ports, config, output_dir))
