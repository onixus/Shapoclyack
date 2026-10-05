"""Tech stack fingerprinting (Phase 9.1, catalogue since DQ4).

Reuses the already-discovered ``open_ports.txt`` endpoints from the ports
stage — this module never scans a new port itself. For each open TCP
endpoint that looks like a web port (``http_ports`` / ``https_ports``), it
issues a single, size-capped HTTP GET and classifies the response against the
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
  * exposure findings (``exposures`` in ``fingerprint.json``): an admin,
    database, devops or monitoring console or a network appliance's
    management UI answering (``exposed_admin_interface``, medium), a VPN,
    remote-access or webmail portal (``exposed_remote_access_gateway``, info
    -- meant to be reachable, and the products with the most KEV entries, so
    each carries its ``cpe`` for a later join), and a version stated in a
    response header (``version_disclosure``, info).

NSE (``nse.py``) drives nmap's own ``-sV``/NSE script checks, but does not
currently emit structured, parseable HTTP header/body data this module could
reuse -- reusing it would mean scraping nmap's text output instead of doing
one dedicated GET per candidate endpoint. To avoid a *second* independent
HTTP client stack duplicating requests against the same hosts, this module
performs exactly one GET per endpoint and derives every signal from that
single response. The catalogue adds no request: a ``/favicon.ico`` hash or a
probe of a known login path would identify more, and would also be a second
request per endpoint; that trade is not made here.

Redirects are followed as before. When they end on a different host than the
endpoint's, the technologies are still listed (with ``final_url`` and
``redirected_off_host``), but no exposure is raised: a root that redirects to
a hosted SSO or a SaaS tracker says nothing about what *this* address exposes.

HONESTY NOTE: the catalogue is a curated perimeter-first list (~140 entries),
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
CDN/WAF the catalogue learned later is reported, not discounted.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, NamedTuple

import httpx

from .config_schema import FingerprintConfig
from .fingerprint_catalogue import Catalogue, Match, load_catalogue, page_title
from .protocol import is_ipv6, parse_endpoint
from .utils import save_json, write_lines

LOG = logging.getLogger("shapoclyack.fingerprint")

USER_AGENT = "shapoclyack/fingerprint"

#: Categories whose match is itself a finding: ``(kind, severity)``. Every
#: other category is inventory only. Webmail is a remote-access portal to the
#: mailbox and is filed with them; the category stays on the finding.
EXPOSURE_BY_CATEGORY: dict[str, tuple[str, str]] = {
    "admin_panel": ("exposed_admin_interface", "medium"),
    "database_ui": ("exposed_admin_interface", "medium"),
    "database": ("exposed_admin_interface", "medium"),
    "devops": ("exposed_admin_interface", "medium"),
    "monitoring": ("exposed_admin_interface", "medium"),
    "network_appliance": ("exposed_admin_interface", "medium"),
    "remote_access": ("exposed_remote_access_gateway", "info"),
    "mail_webmail": ("exposed_remote_access_gateway", "info"),
}
VERSION_DISCLOSURE = ("version_disclosure", "info")

#: Categories that make up the Phase 9.1 ``cms_framework`` list.
CMS_FRAMEWORK_CATEGORIES = frozenset({"cms", "framework", "ecommerce"})


class _Fetched(NamedTuple):
    status: int
    headers: httpx.Headers
    body: str
    #: Where the response actually came from, after redirects.
    url: str


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


def _without_query(url: str) -> str:
    """``url`` minus query and fragment: where the answer came from, not what it carried."""
    try:
        return str(httpx.URL(url).copy_with(query=None, fragment=None))
    except httpx.InvalidURL:
        return ""


def _same_host(url: str, host: str) -> bool:
    try:
        landed = httpx.URL(url).host
    except httpx.InvalidURL:
        return False
    return landed.lower().rstrip(".") == host.lower().rstrip(".")


async def _fetch(
    client: httpx.AsyncClient, url: str, timeout: float, max_bytes: int
) -> _Fetched | None:
    try:
        async with client.stream("GET", url, timeout=timeout) as resp:
            chunks: list[bytes] = []
            total = 0
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                total += len(chunk)
                if total >= max_bytes:
                    break
            body = b"".join(chunks).decode("utf-8", errors="ignore")
            return _Fetched(resp.status_code, resp.headers, body, str(resp.url))
    except httpx.HTTPError as exc:
        LOG.debug("fingerprint: request failed for %s: %s", url, exc)
        return None


def _finding(kind: str, severity: str, outcome: dict[str, Any], match: Match, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "severity": severity,
        "host": outcome["host"],
        "port": outcome["port"],
        "url": outcome["final_url"] or outcome["url"],
        "technology": match.technology.id,
        "evidence": list(match.evidence),
        "name": match.technology.name,
        "category": match.technology.category,
        "version": match.version,
        "cpe": match.cpe,
        "confidence": match.confidence,
        **extra,
    }


def _exposures(outcome: dict[str, Any], matches: list[Match], headers: httpx.Headers) -> list[dict[str, Any]]:
    """Exposure findings for one endpoint; none when the answer came from elsewhere."""
    if outcome["redirected_off_host"]:
        return []
    found: list[dict[str, Any]] = []
    disclosed: set[str] = set()
    for match in matches:
        exposure = EXPOSURE_BY_CATEGORY.get(match.technology.category)
        if exposure is not None:
            found.append(_finding(*exposure, outcome, match))
        source = match.version_source or ""
        if not match.version or not source.startswith("header "):
            continue
        header = source.removeprefix("header ")
        if header in disclosed:
            continue
        disclosed.add(header)
        value = ", ".join(headers.get_list(header))
        disclosure = _finding(*VERSION_DISCLOSURE, outcome, match, header=header)
        disclosure["evidence"] = [f"{header}: {value}"[:160]]
        found.append(disclosure)
    return found


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

    matches = catalogue.classify(fetched.status, fetched.headers, fetched.body, fetched.url)
    outcome["final_url"] = _without_query(fetched.url)
    outcome["redirected_off_host"] = not _same_host(fetched.url, host)
    outcome["http_status"] = fetched.status
    outcome["server"] = fetched.headers.get("server", "")
    outcome["x_powered_by"] = fetched.headers.get("x-powered-by", "")
    outcome["title"] = page_title(fetched.body)[:200]
    outcome["technologies"] = [match.as_dict() for match in matches]
    # Phase 9.1 consumers: the risk model reads cdn_waf for the #173 discount,
    # so only a CDN/WAF the catalogue is sure of may appear in it.
    outcome["cdn_waf"] = [
        m.technology.id for m in matches if m.technology.category == "cdn_waf" and m.confidence == "high"
    ]
    outcome["cms_framework"] = [
        m.technology.id for m in matches if m.technology.category in CMS_FRAMEWORK_CATEGORIES
    ]
    return outcome, _exposures(outcome, matches, fetched.headers)


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

    async with httpx.AsyncClient(headers=headers, verify=config.verify_tls, follow_redirects=True) as client:

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
    result["exposures"] = [exposure for _, exposures in outcomes for exposure in exposures]
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
