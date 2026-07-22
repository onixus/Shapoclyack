"""Typosquat / domain monitoring (Phase 8.4).

Two independent, opt-in, findings-only sub-checks:

1. Typosquat / look-alike domains: generate look-alike candidates of the
   org's seed domains (omission, adjacent transposition, keyboard-adjacent
   substitution, doubling/de-doubling, homoglyph substitution, TLD swap),
   DNS-resolve them (A/AAAA only), and report the ones that resolve as
   findings. A candidate that resolves means *someone* has registered it --
   these domains are never owned by the org and are never merged into scan
   scope. Resolution is passive DNS only (a single A/AAAA lookup per
   candidate) -- same risk class as ct.brute_force's DNS brute force: no
   traffic reaches the candidate domain's actual owner/registrant beyond an
   ordinary DNS query.

2. Dangling-CNAME / subdomain takeover heuristic: for the org's own
   already-in-scope FQDNs (scope_fqdns), resolve the CNAME chain and flag
   ones whose CNAME target matches a known vulnerable-service-pattern
   suffix (e.g. *.github.io, *.herokuapp.com, *.s3.amazonaws.com) AND has no
   A/AAAA record of its own -- a conservative "looks abandoned" gate.

SCOPE BOUNDARY: this module only flags a heuristic suffix-pattern match
plus DNS non-resolution. It never attempts to verify an actual takeover --
no HTTP requests to the third-party service, no claiming or registering
anything, no interaction with the flagged provider at all. The suffix list
is a curated, non-exhaustive sample of commonly-abused services, not a
guarantee of detection.

Both sub-checks are findings-only and non-scope-expanding: a discovered
typosquat domain or a flagged dangling CNAME is reported for human review,
never merged into scan scope and never acted upon. Disabled by default
(discovery.domain_monitor.enabled = false).
"""

from __future__ import annotations

import itertools
import json
import logging
from pathlib import Path
from typing import Any

from .config_schema import DomainMonitorConfig
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("octo-man.domain-monitor")

_KEYBOARD_ADJACENCY = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij",
    "i": "uok", "o": "ipl", "p": "ol", "a": "qsz", "s": "awdz", "d": "serfx", "f": "drtgc",
    "g": "ftyhv", "h": "gyujb", "j": "hikun", "k": "jiolm", "l": "kop", "z": "asx",
    "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}
_HOMOGLYPH_SUBS = (
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("0", "o"), ("o", "0"),
    ("1", "l"), ("l", "1"), ("5", "s"), ("s", "5"),
)
_TLD_SWAP_LIST = ("com", "net", "org", "co", "io", "info", "biz", "cc", "xyz")

# Curated, non-exhaustive sample of commonly-abused "dangling CNAME" service
# patterns. Absence from this list does not mean a target is safe; presence
# does not by itself confirm a takeover is possible -- see module docstring.
_CNAME_TAKEOVER_SUFFIXES = (
    "github.io", "herokuapp.com", "herokudns.com", "s3.amazonaws.com",
    "s3-website", "azurewebsites.net", "cloudfront.net", "wpengine.com",
    "unbouncepages.com", "readme.io", "surge.sh", "fastly.net",
    "pantheonsite.io", "zendesk.com",
)


def _split_domain(domain: str) -> tuple[str, str]:
    """Split "example.com" -> ("example", "com"). Multi-label TLDs (e.g.
    .co.uk) are not specially handled -- the last label is treated as the
    swappable TLD and everything before it as the label."""
    parts = domain.split(".")
    if len(parts) < 2:
        return domain, ""
    return ".".join(parts[:-1]), parts[-1]


def _omission_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i in range(len(label)):
        new_label = label[:i] + label[i + 1 :]
        if new_label:
            out.append(f"{new_label}.{tld}")
    return out


def _transposition_candidates(label: str, tld: str) -> list[str]:
    out = []
    chars = list(label)
    for i in range(len(chars) - 1):
        swapped = chars.copy()
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        out.append(f"{''.join(swapped)}.{tld}")
    return out


def _keyboard_adjacent_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        for adj in _KEYBOARD_ADJACENCY.get(ch.lower(), ""):
            new_label = label[:i] + adj + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _doubling_candidates(label: str, tld: str) -> list[str]:
    out = []
    for i, ch in enumerate(label):
        out.append(f"{label[:i] + ch + ch + label[i + 1:]}.{tld}")
    for i in range(len(label) - 1):
        if label[i] == label[i + 1]:
            new_label = label[:i] + label[i + 1 :]
            out.append(f"{new_label}.{tld}")
    return out


def _homoglyph_candidates(label: str, tld: str) -> list[str]:
    out = []
    for old, new in _HOMOGLYPH_SUBS:
        if old in label:
            out.append(f"{label.replace(old, new)}.{tld}")
    return out


def _tld_swap_candidates(label: str, tld: str) -> list[str]:
    out = []
    for new_tld in _TLD_SWAP_LIST:
        if new_tld != tld:
            out.append(f"{label}.{new_tld}")
    return out


def _round_robin(class_lists: list[list[str]]) -> list[str]:
    """Interleave several candidate-class lists round-robin (one from each
    class in turn, cycling back), deduping case-insensitively."""
    result: list[str] = []
    seen: set[str] = set()
    for item in itertools.chain.from_iterable(itertools.zip_longest(*class_lists)):
        if item is None:
            continue
        key = item.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _generate_typosquat_candidates(domain: str, max_candidates: int) -> list[str]:
    """Generate look-alike domain candidates for ``domain`` via six classes
    of typo/homoglyph generators, interleaved round-robin and capped at
    ``max_candidates``."""
    domain = domain.strip().lower().rstrip(".")
    label, tld = _split_domain(domain)
    if not label or not tld:
        return []

    class_lists = [
        _omission_candidates(label, tld),
        _transposition_candidates(label, tld),
        _keyboard_adjacent_candidates(label, tld),
        _doubling_candidates(label, tld),
        _homoglyph_candidates(label, tld),
        _tld_swap_candidates(label, tld),
    ]

    candidates = _round_robin(class_lists)
    candidates = [c for c in candidates if c.lower() != domain]
    return candidates[:max_candidates]


def _run_dnsx_a_aaaa(
    domains: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, list[str]]]:
    """Resolve A/AAAA records for a list of candidate domains via dnsx."""
    if not domains:
        return {}

    batch_dir = output_dir / "domain_monitor"
    batch_dir.mkdir(parents=True, exist_ok=True)
    targets_file = batch_dir / "typosquat_targets.txt"
    json_out = batch_dir / "typosquat_records.jsonl"
    write_lines(targets_file, sorted(set(domains)))

    run_command(
        [
            "dnsx",
            "-l",
            str(targets_file),
            "-a",
            "-aaaa",
            "-json",
            "-silent",
            "-o",
            str(json_out),
        ],
        timeout=timeout,
        retries=retries,
    )

    mapping: dict[str, dict[str, list[str]]] = {}
    if not json_out.exists():
        return mapping
    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        host = (parsed.get("host") or "").strip().rstrip(".").lower()
        if not host:
            continue
        mapping[host] = {
            "a": parsed.get("a") or [],
            "aaaa": parsed.get("aaaa") or [],
        }
    return mapping


def _run_dnsx_cname(
    fqdns: list[str],
    output_dir: Path,
    *,
    timeout: int,
    retries: int,
) -> dict[str, dict[str, Any]]:
    """Resolve CNAME chains (plus A/AAAA) for the org's own FQDNs via dnsx."""
    if not fqdns:
        return {}

    batch_dir = output_dir / "domain_monitor"
    batch_dir.mkdir(parents=True, exist_ok=True)
    targets_file = batch_dir / "cname_targets.txt"
    json_out = batch_dir / "cname_records.jsonl"
    write_lines(targets_file, sorted(set(fqdns)))

    run_command(
        [
            "dnsx",
            "-l",
            str(targets_file),
            "-cname",
            "-resp",
            "-json",
            "-silent",
            "-o",
            str(json_out),
        ],
        timeout=timeout,
        retries=retries,
    )

    mapping: dict[str, dict[str, Any]] = {}
    if not json_out.exists():
        return mapping
    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        host = (parsed.get("host") or "").strip().rstrip(".").lower()
        if not host:
            continue
        mapping[host] = {
            "cname": parsed.get("cname") or [],
            "a": parsed.get("a") or [],
            "aaaa": parsed.get("aaaa") or [],
        }
    return mapping


def _classify_typosquat(seed: str, candidate: str, record: dict) -> dict | None:
    a = record.get("a") or []
    aaaa = record.get("aaaa") or []
    if not a and not aaaa:
        return None
    return {
        "kind": "typosquat_registered",
        "seed": seed,
        "candidate": candidate,
        "a": a,
        "aaaa": aaaa,
    }


def _classify_dangling_cname(fqdn: str, record: dict) -> dict | None:
    if record.get("a") or record.get("aaaa"):
        return None
    for cname in record.get("cname") or []:
        target = str(cname).strip().rstrip(".").lower()
        for suffix in _CNAME_TAKEOVER_SUFFIXES:
            if target.endswith(suffix.lower()):
                return {
                    "kind": "dangling_cname",
                    "fqdn": fqdn,
                    "cname_target": target,
                    "matched_suffix": suffix,
                }
    return None


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "domain_monitor.json", result)
    lines: list[str] = []
    typosquat = result.get("typosquat") or {}
    for finding in typosquat.get("findings") or []:
        ips = ",".join((finding.get("a") or []) + (finding.get("aaaa") or []))
        lines.append(f"typosquat:{finding['seed']}:{finding['candidate']}:{ips}")
    dangling = result.get("dangling_cname") or {}
    for finding in dangling.get("findings") or []:
        lines.append(f"dangling_cname:{finding['fqdn']}:{finding['cname_target']}")
    write_lines(output_dir / "domain_monitor_findings.txt", lines)


def monitor_domains(
    domains: list[str],
    scope_fqdns: list[str],
    config: DomainMonitorConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Sync entry point: typosquat candidate resolution + dangling-CNAME
    heuristic over the org's seed domains / in-scope FQDNs."""
    result: dict[str, Any] = {
        "seed_domains": [],
        "typosquat": None,
        "dangling_cname": None,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "domain_monitor.disabled"
        _persist(output_dir, result)
        return result

    seeds = sorted({d.strip().lower().rstrip(".") for d in domains if d.strip()})
    if not seeds and not scope_fqdns:
        result["skipped_reason"] = "no_domains"
        _persist(output_dir, result)
        return result
    result["seed_domains"] = seeds

    if config.typosquat_enabled and seeds:
        candidate_seed_pairs: list[tuple[str, str]] = []
        all_candidates: list[str] = []
        for seed in seeds:
            candidates = _generate_typosquat_candidates(seed, config.max_candidates)
            all_candidates.extend(candidates)
            candidate_seed_pairs.extend((candidate, seed) for candidate in candidates)
        records = _run_dnsx_a_aaaa(
            all_candidates,
            output_dir,
            timeout=config.timeout_seconds,
            retries=config.retries,
        )
        findings = []
        for candidate, seed in candidate_seed_pairs:
            record = records.get(candidate.lower())
            if record is None:
                continue
            finding = _classify_typosquat(seed, candidate, record)
            if finding is not None:
                findings.append(finding)
        result["typosquat"] = {
            "candidates_checked": len(all_candidates),
            "findings": findings,
        }

    if config.dangling_cname_enabled and scope_fqdns:
        fqdns = sorted({f.strip().lower().rstrip(".") for f in scope_fqdns if f.strip()})
        records = _run_dnsx_cname(
            fqdns,
            output_dir,
            timeout=config.timeout_seconds,
            retries=config.retries,
        )
        findings = []
        for fqdn in fqdns:
            record = records.get(fqdn)
            if record is None:
                continue
            finding = _classify_dangling_cname(fqdn, record)
            if finding is not None:
                findings.append(finding)
        result["dangling_cname"] = {
            "checked": len(fqdns),
            "findings": findings,
        }

    _persist(output_dir, result)
    typosquat_count = len((result.get("typosquat") or {}).get("findings") or [])
    dangling_count = len((result.get("dangling_cname") or {}).get("findings") or [])
    LOG.info(
        "domain_monitor: %d seed domain(s) -> %d typosquat finding(s), %d dangling-CNAME finding(s)",
        len(seeds),
        typosquat_count,
        dangling_count,
    )
    return result


# Naming symmetry with other stage entry-point imports in main.py.
monitor_domains_sync = monitor_domains
