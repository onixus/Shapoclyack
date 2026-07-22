"""Tech stack fingerprinting (Phase 9.1).

Reuses the already-discovered ``open_ports.txt`` endpoints from the ports
stage — this module never scans a new port itself. For each open TCP
endpoint that looks like a web port (``http_ports`` / ``https_ports``), it
issues a single, size-capped HTTP GET and classifies the response against a
small, hand-picked set of signatures:

  * CDN / WAF detection from response headers (``cf-ray``, ``x-akamai-*``,
    ``x-sucuri-id``, ``via``, ``x-amz-cf-id``, ``x-served-by``, ...).
  * CMS / framework detection from a mix of headers and lightweight
    body/meta-tag markers (WordPress, Drupal, Joomla, Next.js, generic PHP).

NSE (``nse.py``) drives nmap's own ``-sV``/NSE script checks, but does not
currently emit structured, parseable HTTP header/body data this module could
reuse -- reusing it would mean scraping nmap's text output instead of doing
one dedicated GET per candidate endpoint. To avoid a *second* independent
HTTP client stack duplicating requests against the same hosts, this module
performs exactly one GET per endpoint and derives both CDN/WAF and CMS
signals from that single response.

HONESTY NOTE: the signature set here is intentionally small and not meant to
be exhaustive fingerprinting (à la Wappalyzer/BuiltWith) -- it is a first
pass covering the handful of CDN/WAF providers and CMS/frameworks common
enough to matter for prioritization. Add signatures incrementally in
``_CDN_WAF_SIGNATURES`` / ``_CMS_FRAMEWORK_SIGNATURES`` rather than trying to
cover everything up front.

SAFETY: disabled by default (``fingerprint.enabled = false``). Requests are
capped by ``concurrency`` (in-flight) and ``body_max_bytes`` (per-response,
via streamed read) and the candidate endpoint list itself is capped by
``max_targets`` -- past the cap, remaining endpoints are skipped and the run
is flagged "truncated" rather than silently scanning everything. Findings
are reported only (``fingerprint.json``) -- never merged into scan scope or
asset identity (same non-escalation principle as ``cloud_discovery.py``).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

from .config_schema import FingerprintConfig
from .protocol import parse_endpoint
from .utils import save_json, write_lines

LOG = logging.getLogger("octo-man.fingerprint")

USER_AGENT = "shapoclyack-octo-man/fingerprint"


def _header_has_prefix(headers: httpx.Headers, prefix: str) -> bool:
    return any(key.lower().startswith(prefix) for key in headers.keys())


def _cookies_contain(headers: httpx.Headers, needles: tuple[str, ...]) -> bool:
    blob = " ".join(headers.get_list("set-cookie")).lower()
    return any(needle in blob for needle in needles)


# Each entry: (name, predicate(headers) -> bool). Headers lookups are
# case-insensitive (httpx.Headers). Keep this list small and add signatures
# one at a time rather than trying to be exhaustive -- see module docstring.
_CDN_WAF_SIGNATURES: list[tuple[str, Callable[[httpx.Headers], bool]]] = [
    ("cloudflare", lambda h: "cf-ray" in h or "cloudflare" in h.get("server", "").lower()),
    (
        "akamai",
        lambda h: _header_has_prefix(h, "x-akamai") or "akamai" in h.get("server", "").lower(),
    ),
    ("sucuri", lambda h: "x-sucuri-id" in h or "x-sucuri-cache" in h),
    (
        "imperva_incapsula",
        lambda h: "x-iinfo" in h or _cookies_contain(h, ("incap_ses", "visid_incap")),
    ),
    ("cloudfront", lambda h: "x-amz-cf-id" in h or "cloudfront" in h.get("via", "").lower()),
    (
        "fastly",
        lambda h: "x-fastly-request-id" in h or "fastly" in h.get("x-served-by", "").lower(),
    ),
]

# Each entry: (name, predicate(headers, lowercased_body) -> bool).
_CMS_FRAMEWORK_SIGNATURES: list[tuple[str, Callable[[httpx.Headers, str], bool]]] = [
    (
        "wordpress",
        lambda h, b: "wordpress" in h.get("x-generator", "").lower()
        or "wp-content" in b
        or "wp-includes" in b,
    ),
    (
        "drupal",
        lambda h, b: "drupal" in h.get("x-generator", "").lower()
        or "drupal.settings" in b
        or 'content="drupal' in b,
    ),
    ("joomla", lambda h, b: "joomla" in b),
    (
        "nextjs",
        lambda h, b: "next.js" in h.get("x-powered-by", "").lower() or "__next_data__" in b,
    ),
    ("generic_php", lambda h, b: h.get("x-powered-by", "").lower().startswith("php")),
]


def _candidate_endpoints(
    open_ports: list[str], http_ports: set[int], https_ports: set[int]
) -> list[tuple[str, int, str]]:
    """(host, port, scheme) tuples for open TCP endpoints on configured web ports."""
    candidates: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != "tcp":
            continue
        try:
            port = int(parsed.port)
        except ValueError:
            continue
        key = (parsed.host, port)
        if key in seen:
            continue
        if port in https_ports:
            scheme = "https"
        elif port in http_ports:
            scheme = "http"
        else:
            continue
        seen.add(key)
        candidates.append((parsed.host, port, scheme))
    candidates.sort()
    return candidates


def _build_url(host: str, port: int, scheme: str) -> str:
    from .protocol import is_ipv6

    hostpart = f"[{host}]" if is_ipv6(host) else host
    return f"{scheme}://{hostpart}:{port}/"


async def _fetch(
    client: httpx.AsyncClient, url: str, timeout: float, max_bytes: int
) -> tuple[int, httpx.Headers, str] | None:
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
            return resp.status_code, resp.headers, body
    except httpx.HTTPError as exc:
        LOG.debug("fingerprint: request failed for %s: %s", url, exc)
        return None


async def _fingerprint_one(
    client: httpx.AsyncClient,
    host: str,
    port: int,
    scheme: str,
    timeout: float,
    max_bytes: int,
) -> dict[str, Any]:
    url = _build_url(host, port, scheme)
    outcome: dict[str, Any] = {
        "host": host,
        "port": port,
        "scheme": scheme,
        "url": url,
        "http_status": None,
        "server": "",
        "x_powered_by": "",
        "cdn_waf": [],
        "cms_framework": [],
        "error": None,
    }
    fetched = await _fetch(client, url, timeout, max_bytes)
    if fetched is None:
        outcome["error"] = "request_failed"
        return outcome

    status, headers, body = fetched
    body_lower = body.lower()
    outcome["http_status"] = status
    outcome["server"] = headers.get("server", "")
    outcome["x_powered_by"] = headers.get("x-powered-by", "")
    outcome["cdn_waf"] = [name for name, matches in _CDN_WAF_SIGNATURES if matches(headers)]
    outcome["cms_framework"] = [
        name for name, matches in _CMS_FRAMEWORK_SIGNATURES if matches(headers, body_lower)
    ]
    return outcome


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

    truncated = len(candidates) > config.max_targets
    candidates = candidates[: config.max_targets]

    timeout = float(config.timeout_seconds)
    semaphore = asyncio.Semaphore(config.concurrency)
    headers = {"User-Agent": USER_AGENT}

    async with httpx.AsyncClient(headers=headers, verify=config.verify_tls, follow_redirects=True) as client:

        async def _guarded(host: str, port: int, scheme: str) -> dict[str, Any]:
            async with semaphore:
                return await _fingerprint_one(client, host, port, scheme, timeout, config.body_max_bytes)

        findings = await asyncio.gather(
            *(_guarded(host, port, scheme) for host, port, scheme in candidates)
        )

    result["checked_count"] = len(findings)
    result["findings"] = list(findings)
    result["truncated"] = truncated

    matched = sum(1 for f in findings if f["cdn_waf"] or f["cms_framework"])
    _persist(output_dir, result)
    LOG.info(
        "fingerprint: %d endpoint(s) checked -> %d with cdn/waf or cms/framework signal(s)%s",
        len(findings),
        matched,
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
