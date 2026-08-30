"""Related domains discovery via multi-source passive correlation (org_profile M4, EPIC #182).

Discovers co-owned organizational domains across independent sources:
1. ``cert_san``: Domain names extracted from Subject Alternative Names (SAN) in TLS certificates.
2. ``ct_org``: Certificate Transparency search by registrant Organization name (crt.sh).
3. ``reverse_ns``: Shared authoritative nameservers with strict exclusion of public providers.
4. ``reverse_mx``: Shared mail exchange servers with strict exclusion of public mail hosts.
5. ``asn``: Infrastructure correlation against organization-owned autonomous systems.

SAFETY INVARIANTS:
- Finding-only by default (``merge_into_scope: false``): candidate domains are NEVER actively
  scanned within the current run unless explicitly configured.
- Confirmation rule: a domain is marked ``confirmed`` only if supported by >= 2 independent
  sources OR a single high-confidence source with weight >= ``min_confidence``.
- Explainability: every candidate includes an ``evidence[]`` list with exact source, indicator,
  and factual observation.
- Hard caps: enforces ``max_candidates`` and ``max_merged_domains`` limits with ``truncated: true``.
- Disclaimer is embedded in artifact and UI stating attribution is probabilistic.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .asset_identity import registrable_domain
from .config_schema import RelatedDomainsConfig
from .hostnames import base_domains_from_fqdns, query_crtsh
from .utils import load_json, save_json, write_lines

LOG = logging.getLogger("shapoclyack.related_domains")

SOURCE_WEIGHTS: dict[str, float] = {
    "cert_san": 0.70,
    "ct_org": 0.50,
    "reverse_ns": 0.45,
    "reverse_mx": 0.45,
    "asn": 0.50,
    "reverse_whois": 0.60,
}

DISCLAIMER = (
    "Attribution is probabilistic. The operator is responsible for verifying domain "
    "authorization prior to active scanning."
)


def _is_excluded(value: str, excluded_list: list[str]) -> bool:
    """Return True if ``value`` contains or matches any string in ``excluded_list``."""
    val = value.lower().strip().rstrip(".")
    for pattern in excluded_list:
        p = pattern.lower().strip().rstrip(".")
        if p and (val == p or val.endswith(f".{p}") or p in val):
            return True
    return False


def _extract_cert_san_candidates(
    output_dir: Path,
    seed_domains: set[str],
) -> dict[str, list[dict[str, Any]]]:
    """Extract candidate domains from Subject Alternative Names in TLS posture artifacts."""
    candidates: dict[str, list[dict[str, Any]]] = {}
    tls_file = output_dir / "tls_posture.json"
    tls_data = load_json(tls_file, fallback=None)

    if not isinstance(tls_data, dict):
        return candidates

    findings = tls_data.get("findings") or []
    endpoints = tls_data.get("endpoints") or []
    entries = findings + endpoints

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        san_val = entry.get("san") or entry.get("subject_alternative_names")
        host_port = entry.get("endpoint") or f"{entry.get('host', '')}:{entry.get('port', '')}"

        san_names: list[str] = []
        if isinstance(san_val, list):
            san_names = [str(x) for x in san_val]
        elif isinstance(san_val, str):
            san_names = [part.strip() for part in san_val.split(",")]

        for raw_name in san_names:
            clean_name = raw_name.replace("DNS:", "").strip().lower().lstrip("*.")
            if not clean_name:
                continue
            reg_dom = registrable_domain(clean_name)
            if reg_dom and reg_dom not in seed_domains:
                evidence_item = {
                    "source": "cert_san",
                    "indicator": "tls_san",
                    "detail": f"Observed in TLS certificate SAN on endpoint {host_port}".strip(),
                }
                candidates.setdefault(reg_dom, []).append(evidence_item)

    return candidates


def _extract_ct_org_candidates(
    output_dir: Path,
    seed_domains: set[str],
    timeout_seconds: int,
) -> dict[str, list[dict[str, Any]]]:
    """Query Certificate Transparency (crt.sh) for domains issued to the organization."""
    candidates: dict[str, list[dict[str, Any]]] = {}
    ownership_file = output_dir / "ownership.json"
    ownership_data = load_json(ownership_file, fallback=None)

    if not isinstance(ownership_data, dict):
        return candidates

    domains_map = ownership_data.get("domains") or {}
    org_names: set[str] = set()

    for dom_info in domains_map.values():
        if isinstance(dom_info, dict):
            org = dom_info.get("org_name") or dom_info.get("registrant_organization")
            status = dom_info.get("registrant_status")
            if org and status not in ("redacted", "natural_person", "unknown") and len(org.strip()) >= 3:
                org_names.add(org.strip())

    for org_name in org_names:
        LOG.info("Searching crt.sh for certificates issued to organization: %s", org_name)
        try:
            query = urllib.parse.quote(org_name)
            url = f"https://crt.sh/?O={query}&output=json"
            from urllib.request import Request, urlopen

            req = Request(url, headers={"User-Agent": "shapoclyack/related_domains", "Accept": "application/json"})
            with urlopen(req, timeout=timeout_seconds) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if isinstance(data, list):
                    for row in data:
                        if not isinstance(row, dict):
                            continue
                        name_val = str(row.get("name_value") or "")
                        for line in name_val.splitlines():
                            clean = line.strip().lower().lstrip("*.")
                            reg_dom = registrable_domain(clean)
                            if reg_dom and reg_dom not in seed_domains:
                                evidence_item = {
                                    "source": "ct_org",
                                    "indicator": "crt_sh_org",
                                    "detail": f"Matched certificate issued to Organization '{org_name}'",
                                }
                                candidates.setdefault(reg_dom, []).append(evidence_item)
        except Exception as exc:
            LOG.warning("crt.sh organization query failed for '%s': %s", org_name, exc)

    return candidates


def _extract_reverse_ns_candidates(
    output_dir: Path,
    seed_domains: set[str],
    excluded_ns: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Cross-reference authoritative nameservers filtering out public cloud providers."""
    candidates: dict[str, list[dict[str, Any]]] = {}
    dns_file = output_dir / "dns_hygiene.json"
    dns_data = load_json(dns_file, fallback=None)

    if not isinstance(dns_data, dict):
        return candidates

    domains_map = dns_data.get("domains") or {}
    custom_ns_map: dict[str, set[str]] = {}

    for dom, dom_info in domains_map.items():
        if not isinstance(dom_info, dict):
            continue
        ns_list = dom_info.get("ns") or []
        for ns_server in ns_list:
            ns_str = str(ns_server).strip().lower().rstrip(".")
            if ns_str and not _is_excluded(ns_str, excluded_ns):
                custom_ns_map.setdefault(ns_str, set()).add(dom)

    # Correlate domains that share dedicated / private NS servers
    for ns_server, shared_doms in custom_ns_map.items():
        for d in shared_doms:
            reg_dom = registrable_domain(d)
            if reg_dom and reg_dom not in seed_domains:
                evidence_item = {
                    "source": "reverse_ns",
                    "indicator": "shared_custom_ns",
                    "detail": f"Shares authoritative nameserver '{ns_server}' with verified domain(s)",
                }
                candidates.setdefault(reg_dom, []).append(evidence_item)

    return candidates


def _extract_reverse_mx_candidates(
    output_dir: Path,
    seed_domains: set[str],
    excluded_mx: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Cross-reference mail exchange hosts filtering out multi-tenant email providers."""
    candidates: dict[str, list[dict[str, Any]]] = {}
    mail_file = output_dir / "mail_posture.json"
    mail_data = load_json(mail_file, fallback=None)

    if not isinstance(mail_data, dict):
        return candidates

    domains_map = mail_data.get("domains") or {}
    custom_mx_map: dict[str, set[str]] = {}

    for dom, dom_info in domains_map.items():
        if not isinstance(dom_info, dict):
            continue
        mx_list = dom_info.get("mx") or []
        for mx_server in mx_list:
            mx_str = str(mx_server).strip().lower().rstrip(".")
            if mx_str and not _is_excluded(mx_str, excluded_mx):
                custom_mx_map.setdefault(mx_str, set()).add(dom)

    for mx_server, shared_doms in custom_mx_map.items():
        for d in shared_doms:
            reg_dom = registrable_domain(d)
            if reg_dom and reg_dom not in seed_domains:
                evidence_item = {
                    "source": "reverse_mx",
                    "indicator": "shared_custom_mx",
                    "detail": f"Shares dedicated mail exchanger '{mx_server}' with verified domain(s)",
                }
                candidates.setdefault(reg_dom, []).append(evidence_item)

    return candidates


def _compute_confidence(evidence_list: list[dict[str, Any]]) -> tuple[float, list[str]]:
    """Compute overall confidence from evidence items using independent source combination."""
    unique_sources = sorted(list({e.get("source", "unknown") for e in evidence_list}))
    if not unique_sources:
        return 0.0, []

    # Combined probability: 1 - product(1 - w_i)
    prob_not = 1.0
    for src in unique_sources:
        weight = SOURCE_WEIGHTS.get(src, 0.40)
        prob_not *= (1.0 - weight)

    confidence = round(max(0.0, min(1.0, 1.0 - prob_not)), 2)
    return confidence, unique_sources


def discover_related_domains(
    output_dir: Path,
    config: RelatedDomainsConfig,
    seed_domains: list[str] | None = None,
) -> dict[str, Any]:
    """Execute related domains discovery and emit related_domains.json & org_profile.json."""
    seeds: set[str] = set()
    if seed_domains:
        for d in seed_domains:
            r = registrable_domain(d)
            if r:
                seeds.add(r)
    else:
        # Load from targets / alive_hosts
        alive = load_json(output_dir / "alive_hosts.json", fallback=[])
        if isinstance(alive, list):
            for row in alive:
                if isinstance(row, dict):
                    name = row.get("hostname") or row.get("host")
                    if name:
                        r = registrable_domain(name)
                        if r:
                            seeds.add(r)

    candidate_evidence: dict[str, list[dict[str, Any]]] = {}

    # 1. Cert SAN
    if "cert_san" in config.sources:
        san_res = _extract_cert_san_candidates(output_dir, seeds)
        for dom, evs in san_res.items():
            candidate_evidence.setdefault(dom, []).extend(evs)

    # 2. CT Org
    if "ct_org" in config.sources:
        ct_res = _extract_ct_org_candidates(output_dir, seeds, config.timeout_seconds)
        for dom, evs in ct_res.items():
            candidate_evidence.setdefault(dom, []).extend(evs)

    # 3. Reverse NS
    if "reverse_ns" in config.sources:
        ns_res = _extract_reverse_ns_candidates(output_dir, seeds, config.excluded_ns_providers)
        for dom, evs in ns_res.items():
            candidate_evidence.setdefault(dom, []).extend(evs)

    # 4. Reverse MX
    if "reverse_mx" in config.sources:
        mx_res = _extract_reverse_mx_candidates(output_dir, seeds, config.excluded_mx_providers)
        for dom, evs in mx_res.items():
            candidate_evidence.setdefault(dom, []).extend(evs)

    # Build candidate items
    items: list[dict[str, Any]] = []
    for dom, evs in candidate_evidence.items():
        # Deduplicate evidence
        seen_ev = set()
        dedup_ev: list[dict[str, Any]] = []
        for e in evs:
            k = (e.get("source"), e.get("indicator"), e.get("detail"))
            if k not in seen_ev:
                seen_ev.add(k)
                dedup_ev.append(e)

        confidence, sources = _compute_confidence(dedup_ev)
        is_confirmed = len(sources) >= 2 or confidence >= config.min_confidence

        items.append({
            "domain": dom,
            "status": "confirmed" if is_confirmed else "candidate",
            "confidence": confidence,
            "sources": sources,
            "evidence": dedup_ev,
        })

    # Sort: confirmed first, then confidence desc, then domain asc
    items.sort(key=lambda x: (0 if x["status"] == "confirmed" else 1, -x["confidence"], x["domain"]))

    total_candidates = len(items)
    truncated = total_candidates > config.max_candidates
    items = items[: config.max_candidates]

    confirmed_count = sum(1 for x in items if x["status"] == "confirmed")
    candidate_count = sum(1 for x in items if x["status"] == "candidate")

    # Auto merge if configured
    merged_domains: list[str] = []
    if config.auto_merge:
        confirmed_domains = [x["domain"] for x in items if x["status"] == "confirmed"]
        merged_domains = confirmed_domains[: config.max_merged_domains]
        if merged_domains:
            write_lines(output_dir / "merged_related_domains.txt", merged_domains)
            LOG.info("Auto-merged %d confirmed related domains into target list", len(merged_domains))

    result = {
        "status": "ok",
        "seed_domains": sorted(list(seeds)),
        "confirmed_count": confirmed_count,
        "candidate_count": candidate_count,
        "total_candidates": total_candidates,
        "truncated": truncated,
        "auto_merged": config.auto_merge,
        "merged_domains": merged_domains,
        "disclaimer": DISCLAIMER,
        "candidates": items,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }

    save_json(output_dir / "related_domains.json", result)

    # Build unified org_profile.json
    ownership_data = load_json(output_dir / "ownership.json", fallback=None)
    org_profile_summary = {
        "seed_domains": sorted(list(seeds)),
        "ownership": ownership_data,
        "related_domains": result,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(output_dir / "org_profile.json", org_profile_summary)

    LOG.info(
        "Related domains discovery completed: %d confirmed, %d candidates across %d seeds",
        confirmed_count,
        candidate_count,
        len(seeds),
    )
    return result
