from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config_schema import CloudflareDiscoveryConfig, DiscoveryConfig
from .coverage_tracker import expand_target_ips
from .discovery_targets import pending_discovery_targets
from .probe_ladder import run_probe_ladder
from .utils import save_json, write_lines

_CF_API = "https://api.cloudflare.com/client/v4"


def host_discovery(
    targets: list[str],
    output_dir: Path,
    rate: int,
    timeout: int,
    retries: int,
    skip_discovery: bool,
    discovery: DiscoveryConfig,
    known_alive: set[str] | None = None,
    skip_known_alive: bool = False,
    max_pending_hosts: int | None = 65536,
    tag: str = "all",
) -> list[str]:
    """Run host discovery for a single batch via the configured probe ladder.

    Per-batch inputs/outputs live under ``output_dir/discover/<tag>.*`` so each
    batch is independent and resumable. Returns the alive hosts for this batch.
    """
    batch_dir = output_dir / "discover"
    input_file = batch_dir / f"{tag}.targets.txt"
    alive_file = batch_dir / f"{tag}.alive.txt"
    scan_targets = list(targets)
    if skip_known_alive and known_alive is not None:
        scan_targets = pending_discovery_targets(
            targets,
            known_alive,
            max_hosts=max_pending_hosts,
        )
        if not scan_targets:
            logging.info(
                "Discovery batch %s: skipping — all targets already alive (%s known)",
                tag,
                len(known_alive),
            )
            write_lines(input_file, [])
            write_lines(alive_file, [])
            return []

    write_lines(input_file, scan_targets)
    if not scan_targets:
        write_lines(alive_file, [])
        return []

    if skip_discovery:
        alive = sorted(set(scan_targets))
        write_lines(alive_file, alive)
        return alive

    probe_hosts = sorted(expand_target_ips(scan_targets, max_hosts=max_pending_hosts))
    if not probe_hosts:
        write_lines(alive_file, [])
        return []

    alive, _stats = run_probe_ladder(
        probe_hosts,
        output_dir,
        discovery,
        rate=rate,
        timeout=timeout,
        retries=retries,
        tag=tag,
        scope_members=targets,
    )
    write_lines(alive_file, alive)
    return alive


def cloudflare_api_token(config: CloudflareDiscoveryConfig) -> str:
    return (config.api_token or os.environ.get("OCTO_CLOUDFLARE_API_TOKEN") or "").strip()


def _cf_request(path: str, token: str, timeout: int, params: dict[str, str] | None = None) -> dict[str, Any]:
    query = f"?{urllib.parse.urlencode(params)}" if params else ""
    url = f"{_CF_API}{path}{query}"
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("success", False):
        errors = payload.get("errors") or []
        raise ValueError(f"Cloudflare API error: {errors}")
    return payload


def list_cloudflare_zones(token: str, timeout: int) -> list[dict[str, Any]]:
    zones: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = _cf_request(
            "/zones",
            token,
            timeout,
            params={"page": str(page), "per_page": "50"},
        )
        batch = payload.get("result") or []
        zones.extend(batch)
        info = payload.get("result_info") or {}
        total_pages = int(info.get("total_pages") or 1)
        if page >= total_pages:
            break
        page += 1
    return zones


def list_cloudflare_dns_records(zone_id: str, token: str, timeout: int) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    page = 1
    while True:
        payload = _cf_request(
            f"/zones/{zone_id}/dns_records",
            token,
            timeout,
            params={"page": str(page), "per_page": "100"},
        )
        batch = payload.get("result") or []
        records.extend(batch)
        info = payload.get("result_info") or {}
        total_pages = int(info.get("total_pages") or 1)
        if page >= total_pages:
            break
        page += 1
    return records


def _normalize_fqdn(name: str) -> str:
    return name.strip().rstrip(".").lower()


def import_cloudflare_dns_targets(
    config: CloudflareDiscoveryConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Fetch Cloudflare DNS records; return FQDNs/IPs and write artifacts.

    Fail-soft: on API/config errors returns ``skipped_reason`` and empty lists.
    """
    result: dict[str, Any] = {
        "fqdns": [],
        "ips": [],
        "records": [],
        "misconfigurations": [],
        "zones": [],
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "cloudflare.disabled"
        return result

    token = cloudflare_api_token(config)
    if not token:
        result["skipped_reason"] = "missing OCTO_CLOUDFLARE_API_TOKEN / api_token"
        logging.warning("Cloudflare discovery enabled but API token is empty")
        return result

    timeout = config.timeout_seconds
    try:
        all_zones = list_cloudflare_zones(token, timeout)
        wanted = {_normalize_fqdn(z) for z in config.zones if z.strip()}
        selected: list[dict[str, Any]] = []
        for zone in all_zones:
            zone_id = str(zone.get("id") or "")
            zone_name = _normalize_fqdn(str(zone.get("name") or ""))
            if wanted and zone_id not in wanted and zone_name not in wanted:
                continue
            selected.append({"id": zone_id, "name": zone_name})
        if wanted and not selected:
            result["skipped_reason"] = "no_matching_zones"
            logging.warning("Cloudflare: no zones matched config.zones=%s", sorted(wanted))
            save_json(output_dir / "cloudflare_dns.json", result)
            return result

        result["zones"] = selected
        fqdns: list[str] = []
        ips: list[str] = []
        records_out: list[dict[str, Any]] = []
        misconfigs: list[dict[str, Any]] = []

        for zone in selected:
            zone_records = list_cloudflare_dns_records(zone["id"], token, timeout)
            for record in zone_records:
                rtype = str(record.get("type") or "").upper()
                name = _normalize_fqdn(str(record.get("name") or ""))
                content = str(record.get("content") or "").strip()
                proxied = bool(record.get("proxied"))
                if rtype not in {"A", "AAAA", "CNAME"}:
                    continue
                if proxied and not config.include_proxied:
                    continue
                if (not proxied) and not config.include_unproxied:
                    continue
                entry = {
                    "zone": zone["name"],
                    "zone_id": zone["id"],
                    "type": rtype,
                    "name": name,
                    "content": content,
                    "proxied": proxied,
                }
                records_out.append(entry)
                if name:
                    fqdns.append(name)
                if rtype in {"A", "AAAA"} and content:
                    ips.append(content)
                if config.flag_unproxied_a and rtype in {"A", "AAAA"} and not proxied:
                    misconfigs.append(
                        {
                            **entry,
                            "finding": "unproxied_a_record",
                            "severity": "medium",
                            "detail": (
                                "Public A/AAAA record is not Cloudflare-proxied "
                                "(origin IP exposed)."
                            ),
                        }
                    )

        result["fqdns"] = sorted(set(fqdns))
        result["ips"] = sorted(set(ips))
        result["records"] = records_out
        result["misconfigurations"] = misconfigs
        logging.info(
            "Cloudflare import: %s zone(s), %s FQDN(s), %s IP(s), %s unproxied finding(s)",
            len(selected),
            len(result["fqdns"]),
            len(result["ips"]),
            len(misconfigs),
        )
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        result["skipped_reason"] = f"error: {exc}"
        logging.warning("Cloudflare discovery failed: %s", exc)

    save_json(output_dir / "cloudflare_dns.json", result)
    write_lines(output_dir / "cloudflare_targets.txt", result["fqdns"])
    save_json(output_dir / "cloudflare_misconfig.json", {"findings": result["misconfigurations"]})
    return result
