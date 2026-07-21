from __future__ import annotations

import asyncio
import json
import logging
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config_schema import BruteForceSubdomainConfig, CertificateTransparencyConfig, DiscoveryConfig
from .utils import load_json, run_command, save_json, write_lines

DEFAULT_WORDLIST_PATH = Path(__file__).resolve().parents[2] / "scanner" / "data" / "wordlists" / "subdomains-small.txt"


def forward_map_from_resolution(output_dir: Path) -> dict[str, list[str]]:
    """Build ip -> input FQDNs from ``dns_resolution.json`` (dnsx forward records)."""
    raw = load_json(output_dir / "dns_resolution.json", fallback={"records": []})
    mapping: dict[str, list[str]] = {}
    for record in raw.get("records", []):
        fqdn = (record.get("host") or "").strip().rstrip(".").lower()
        if not fqdn:
            continue
        for key in ("a", "aaaa"):
            for ip in record.get(key, []) or []:
                ip = str(ip).strip()
                if not ip:
                    continue
                names = mapping.setdefault(ip, [])
                if fqdn not in names:
                    names.append(fqdn)
    for ip in mapping:
        mapping[ip] = sorted(mapping[ip])
    return mapping


def reverse_map_from_ptr(
    hosts: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, list[str]]:
    """Run dnsx PTR lookup for alive IPs. Returns ip -> PTR names."""
    if not hosts:
        return {}

    batch_dir = output_dir / "discover"
    batch_dir.mkdir(parents=True, exist_ok=True)
    input_file = batch_dir / "ptr.targets.txt"
    json_out = batch_dir / "ptr.records.jsonl"
    write_lines(input_file, sorted(set(hosts)))

    run_command(
        [
            "dnsx",
            "-l",
            str(input_file),
            "-ptr",
            "-json",
            "-silent",
            "-o",
            str(json_out),
        ],
        timeout=timeout,
        retries=retries,
    )

    mapping: dict[str, list[str]] = {}
    if not json_out.exists():
        return mapping

    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        ip = (parsed.get("host") or "").strip()
        if not ip:
            continue
        ptrs = parsed.get("ptr") or []
        names = sorted({str(name).strip().rstrip(".").lower() for name in ptrs if str(name).strip()})
        if names:
            mapping[ip] = names
    return mapping


def merge_name_lists(*sources: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for source in sources:
        for name in source:
            normalized = name.strip().rstrip(".").lower()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            merged.append(normalized)
    return merged


def build_hostnames_map(
    alive_hosts: list[str],
    *,
    forward: dict[str, list[str]],
    reverse: dict[str, list[str]],
) -> dict[str, dict[str, list[str] | str]]:
    """Per-IP hostname enrichment for alive hosts."""
    result: dict[str, dict[str, list[str] | str]] = {}
    for ip in sorted(set(alive_hosts)):
        fwd = forward.get(ip, [])
        rev = reverse.get(ip, [])
        names = merge_name_lists(fwd, rev)
        entry: dict[str, list[str] | str] = {
            "forward": fwd,
            "reverse": rev,
            "names": names,
        }
        if names:
            entry["primary"] = names[0]
        result[ip] = entry
    return result


def primary_hostname(hostnames_map: dict[str, dict], host: str) -> str:
    entry = hostnames_map.get(host) or {}
    primary = entry.get("primary")
    if isinstance(primary, str) and primary:
        return primary
    names = entry.get("names")
    if isinstance(names, list) and names:
        return str(names[0])
    return ""


def enrich_discovery_hostnames(
    alive_hosts: list[str],
    output_dir: Path,
    discovery: DiscoveryConfig,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, list[str] | str]]:
    """Resolve forward (input FQDNs) and/or reverse (PTR) names for alive hosts."""
    hostnames_cfg = discovery.hostnames
    if not hostnames_cfg.forward and not hostnames_cfg.reverse:
        save_json(output_dir / "hostnames.json", {})
        return {}

    forward: dict[str, list[str]] = {}
    reverse: dict[str, list[str]] = {}

    if hostnames_cfg.forward:
        forward = forward_map_from_resolution(output_dir)
        logging.info(
            "discovery hostnames: forward map covers %s IP(s) from dns_resolution.json",
            len(forward),
        )

    if hostnames_cfg.reverse and alive_hosts:
        logging.info(
            "discovery hostnames: PTR lookup for %s alive host(s)",
            len(alive_hosts),
        )
        reverse = reverse_map_from_ptr(
            alive_hosts,
            output_dir,
            timeout=timeout,
            retries=retries,
        )
        logging.info("discovery hostnames: PTR resolved for %s IP(s)", len(reverse))

    hostnames_map = build_hostnames_map(alive_hosts, forward=forward, reverse=reverse)
    named = sum(1 for entry in hostnames_map.values() if entry.get("names"))
    logging.info(
        "discovery hostnames: %s/%s alive host(s) with at least one name",
        named,
        len(alive_hosts),
    )
    save_json(output_dir / "hostnames.json", hostnames_map)
    return hostnames_map


def _normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _http_get_json(url: str, timeout: int, headers: dict[str, str] | None = None) -> Any:
    request = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def query_crtsh(domain: str, timeout: int) -> list[str]:
    """Query crt.sh for certificate names covering ``domain``."""
    query = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    try:
        payload = _http_get_json(url, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        logging.warning("crt.sh query failed for %s: %s", domain, exc)
        return []
    names: list[str] = []
    if not isinstance(payload, list):
        return names
    for row in payload:
        if not isinstance(row, dict):
            continue
        raw = str(row.get("name_value") or "")
        for part in raw.split("\n"):
            name = _normalize_name(part)
            if not name or "*" in name:
                continue
            if name == domain or name.endswith(f".{domain}"):
                names.append(name)
    return names


def query_certspotter(domain: str, timeout: int) -> list[str]:
    """Query Cert Spotter issuances API for ``domain`` DNS names."""
    params = urllib.parse.urlencode(
        {
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        }
    )
    url = f"https://api.certspotter.com/v1/issuances?{params}"
    try:
        payload = _http_get_json(url, timeout, headers={"Accept": "application/json"})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        logging.warning("Cert Spotter query failed for %s: %s", domain, exc)
        return []
    names: list[str] = []
    if not isinstance(payload, list):
        return names
    for row in payload:
        if not isinstance(row, dict):
            continue
        for part in row.get("dns_names") or []:
            name = _normalize_name(str(part))
            if not name or "*" in name:
                continue
            if name == domain or name.endswith(f".{domain}"):
                names.append(name)
    return names


def query_otx_passive_dns(domain: str, timeout: int) -> list[str]:
    """Query AlienVault OTX passive DNS (keyless read access) for ``domain``."""
    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{urllib.parse.quote(domain)}/passive_dns"
    try:
        payload = _http_get_json(url, timeout, headers={"Accept": "application/json"})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        logging.warning("OTX passive DNS query failed for %s: %s", domain, exc)
        return []
    names: list[str] = []
    if not isinstance(payload, dict):
        return names
    for row in payload.get("passive_dns") or []:
        if not isinstance(row, dict):
            continue
        name = _normalize_name(str(row.get("hostname") or ""))
        if not name or "*" in name:
            continue
        if name == domain or name.endswith(f".{domain}"):
            names.append(name)
    return names


def _load_wordlist(wordlist_file: str) -> list[str]:
    path = Path(wordlist_file) if wordlist_file else DEFAULT_WORDLIST_PATH
    if not path.is_file():
        logging.warning("brute_force: wordlist not found at %s", path)
        return []
    words: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        word = line.strip().lower()
        if word and not word.startswith("#"):
            words.append(word)
    return words


def _resolves(candidate: str, timeout: int) -> bool:
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(candidate, None)
        return True
    except (socket.gaierror, OSError):
        return False
    finally:
        socket.setdefaulttimeout(original_timeout)


async def brute_force_subdomains(domain: str, config: BruteForceSubdomainConfig) -> list[str]:
    """Generate ``{word}.{domain}`` candidates and keep only those that resolve.

    Concurrency and candidate-count are capped (config.concurrency /
    config.max_candidates) so this stays a bounded, well-behaved DNS query
    burst rather than an unbounded flood against the target's resolvers.
    """
    if not config.enabled:
        return []
    wordlist = _load_wordlist(config.wordlist_file)
    if not wordlist:
        return []
    candidates = [f"{word}.{domain}" for word in wordlist][: config.max_candidates]

    semaphore = asyncio.Semaphore(config.concurrency)

    async def _check(candidate: str) -> str | None:
        async with semaphore:
            ok = await asyncio.to_thread(_resolves, candidate, config.timeout_seconds)
        return candidate if ok else None

    results = await asyncio.gather(*(_check(c) for c in candidates))
    return sorted({name for name in results if name})


def base_domains_from_fqdns(fqdns: list[str]) -> list[str]:
    """Reduce FQDNs to registrable-ish base domains (last two labels)."""
    bases: list[str] = []
    seen: set[str] = set()
    for fqdn in fqdns:
        name = _normalize_name(fqdn)
        if not name or "." not in name:
            continue
        parts = name.split(".")
        base = ".".join(parts[-2:]) if len(parts) >= 2 else name
        if base not in seen:
            seen.add(base)
            bases.append(base)
    return bases


async def discover_ct_subdomains(
    domains: list[str],
    config: CertificateTransparencyConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Async CT subdomain discovery across configured providers."""
    result: dict[str, Any] = {
        "domains": [],
        "subdomains": [],
        "by_provider": {},
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "ct.disabled"
        return result

    targets = [_normalize_name(d) for d in (config.domains or domains) if _normalize_name(d)]
    targets = sorted(set(targets))
    if not targets:
        result["skipped_reason"] = "no_domains"
        save_json(output_dir / "ct_subdomains.json", result)
        return result

    result["domains"] = targets
    provider_names = list(config.providers)
    collected: list[str] = []
    by_provider: dict[str, list[str]] = {}

    async def _run_provider(provider: str, domain: str) -> tuple[str, str, list[str]]:
        if provider == "crtsh":
            names = await asyncio.to_thread(query_crtsh, domain, config.timeout_seconds)
        elif provider == "certspotter":
            names = await asyncio.to_thread(query_certspotter, domain, config.timeout_seconds)
        elif provider == "otx":
            names = await asyncio.to_thread(query_otx_passive_dns, domain, config.timeout_seconds)
        else:
            names = []
        cleaned: list[str] = []
        for raw in names:
            name = _normalize_name(str(raw))
            if not name or "*" in name:
                continue
            if name == domain or name.endswith(f".{domain}"):
                cleaned.append(name)
        return provider, domain, cleaned

    tasks = [
        _run_provider(provider, domain)
        for domain in targets
        for provider in provider_names
    ]
    for provider, domain, names in await asyncio.gather(*tasks):
        key = f"{provider}:{domain}"
        by_provider[key] = sorted(set(names))
        collected.extend(names)

    if config.brute_force.enabled:
        bf_results = await asyncio.gather(
            *(brute_force_subdomains(domain, config.brute_force) for domain in targets)
        )
        for domain, names in zip(targets, bf_results):
            by_provider[f"brute_force:{domain}"] = names
            collected.extend(names)

    unique = merge_name_lists(collected)
    if len(unique) > config.max_subdomains:
        unique = unique[: config.max_subdomains]
        result["truncated"] = True
    result["subdomains"] = unique
    result["by_provider"] = by_provider
    logging.info(
        "CT discovery: %s domain(s), %s subdomain(s) via %s",
        len(targets),
        len(unique),
        ",".join(provider_names),
    )
    save_json(output_dir / "ct_subdomains.json", result)
    write_lines(output_dir / "ct_subdomains.txt", unique)
    return result


def discover_ct_subdomains_sync(
    domains: list[str],
    config: CertificateTransparencyConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Sync wrapper for pipeline stages (uses ``asyncio.run``)."""
    return asyncio.run(discover_ct_subdomains(domains, config, output_dir))
