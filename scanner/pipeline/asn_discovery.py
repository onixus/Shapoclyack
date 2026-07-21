"""ASN / WHOIS / BGP org mapping (Phase 8.1).

Seed domain -> resolved IP -> ASN -> announced prefixes, via RIPEstat's free,
keyless public API (https://stat.ripe.net/docs/02.data-api/) rather than raw
WHOIS/RDAP protocol parsing. Same "free public API, fail-soft per call, opt-in"
posture as discover.py's Cloudflare integration and hostnames.py's CT-log
discovery.

SAFETY: an ASN can span far more than one organization's infrastructure
(shared hosting, CDNs, cloud providers). ``max_total_ips`` hard-caps how many
IPs from announced prefixes get merged into scan scope — results past the cap
are dropped and the run is flagged "truncated" rather than silently exploding
scope. This module is disabled by default (discovery.asn.enabled = false).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from typing import Any

import httpx

from .config_schema import AsnDiscoveryConfig
from .utils import save_json, write_lines

LOG = logging.getLogger("octo-man.asn-discovery")

RIPESTAT_NETWORK_INFO = "https://stat.ripe.net/data/network-info/data.json"
RIPESTAT_ANNOUNCED_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json"
USER_AGENT = "shapoclyack-octo-man/asn-discovery"


def _resolve_domain_ips(domain: str, timeout: float) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None)
    except (socket.gaierror, OSError) as exc:
        LOG.warning("asn_discovery: DNS resolve failed for %s: %s", domain, exc)
        return []
    return sorted({info[4][0] for info in infos})


def _lookup_asn_for_ip(client: httpx.Client, ip: str, timeout: float) -> str | None:
    try:
        resp = client.get(RIPESTAT_NETWORK_INFO, params={"resource": ip}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOG.warning("asn_discovery: network-info lookup failed for %s: %s", ip, exc)
        return None
    asns = ((data.get("data") or {}).get("asns")) or []
    return str(asns[0]) if asns else None


def _announced_prefixes(client: httpx.Client, asn: str, timeout: float) -> list[str]:
    try:
        resp = client.get(
            RIPESTAT_ANNOUNCED_PREFIXES, params={"resource": f"AS{asn}"}, timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOG.warning("asn_discovery: announced-prefixes lookup failed for AS%s: %s", asn, exc)
        return []
    prefixes = ((data.get("data") or {}).get("prefixes")) or []
    return [str(p["prefix"]) for p in prefixes if isinstance(p, dict) and p.get("prefix")]


def _count_ips(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses
    except ValueError:
        return 0


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "asn_discovery.json", result)
    write_lines(output_dir / "asn_ranges.txt", result["ip_ranges"])


def discover_asn_ranges(
    domains: list[str],
    config: AsnDiscoveryConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Resolve seed domains -> ASNs -> announced prefixes, capped at max_total_ips."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "seed_ips": [],
        "asns": {},
        "ip_ranges": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "asn.disabled"
        _persist(output_dir, result)
        return result

    seeds = [d.strip().lower() for d in (config.domains or domains) if d.strip()]
    seeds = sorted(set(seeds))
    if not seeds:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result
    result["seed_domains"] = seeds

    timeout = float(config.timeout_seconds)
    seed_ips: list[str] = []
    asns: dict[str, dict[str, Any]] = {}
    ip_ranges: list[str] = []
    total_ips = 0
    truncated = False

    with httpx.Client(headers={"User-Agent": USER_AGENT}) as client:
        for domain in seeds:
            if truncated:
                break
            for ip in _resolve_domain_ips(domain, timeout):
                seed_ips.append(ip)
                if truncated:
                    break
                asn = _lookup_asn_for_ip(client, ip, timeout)
                if not asn or asn in asns:
                    continue
                kept: list[str] = []
                for prefix in _announced_prefixes(client, asn, timeout):
                    prefix_size = _count_ips(prefix)
                    if total_ips + prefix_size > config.max_total_ips:
                        truncated = True
                        break
                    kept.append(prefix)
                    total_ips += prefix_size
                asns[asn] = {"prefixes": kept}
                ip_ranges.extend(kept)
                if truncated:
                    break

    result["seed_ips"] = sorted(set(seed_ips))
    result["asns"] = asns
    result["ip_ranges"] = sorted(set(ip_ranges))
    result["truncated"] = truncated
    if truncated:
        LOG.warning(
            "asn_discovery: truncated at max_total_ips=%s; raise discovery.asn.max_total_ips "
            "if this scope expansion is intentional",
            config.max_total_ips,
        )
    _persist(output_dir, result)
    LOG.info(
        "asn_discovery: %d seed domain(s) -> %d ASN(s) -> %d range(s) (~%d IPs)%s",
        len(seeds),
        len(asns),
        len(result["ip_ranges"]),
        total_ips,
        " [truncated]" if truncated else "",
    )
    return result
