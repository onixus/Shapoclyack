from __future__ import annotations

import json
import logging
from pathlib import Path

from .config_schema import DiscoveryConfig
from .utils import load_json, run_command, save_json, write_lines


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
