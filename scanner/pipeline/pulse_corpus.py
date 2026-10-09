"""Offline gap report: recorded Nmap XML vs recorded Pulse JSON (#541, ADR 0002).

The corpus lives in ``tests/fixtures/nmap_pulse_corpus/`` (``nmap/*.xml``,
``pulse/*.json``), recorded by ``record.sh`` on a compose stand while Nmap still
runs. This module reads it and counts, per ``host:port/proto``, where Pulse
differs from Nmap: service, product, version, CPE, TLS (protocols, suites,
certificate) and script findings. No network, no scanner binaries.

Parsing is not duplicated: Nmap XML goes through ``report._parse_nmap_xml`` and
``tls_posture``'s ``ssl-enum-ciphers`` / ``ssl-cert`` parsers (what the pipeline
itself uses), Pulse JSON through ``pulse_probe.parse_pulse_json``, and the
endpoint/OS comparison is ``pulse_shadow.compare_pulse_nmap`` run on artifacts
written the way the pipeline writes them.

The numbers are a measurement of the gap, not a quality bar: Nmap is the
reference only because it is what exists. Where the stand's ground truth differs
from Nmap's answer (e.g. Samba reported as 4.6.2) the report still scores
agreement with Nmap and says so in ``docs/pulse-backend.md``.
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from .pulse_probe import extract_pulse_tls, parse_pulse_json, write_pulse_artifacts
from .pulse_shadow import compare_pulse_nmap
from .report import _build_vulnerabilities, _parse_nmap_xml
from .tls_posture import (
    _WEAK_PROTOCOLS,
    _iter_ssl_scripts,
    _normalize_proto_label,
    _parse_ssl_cert_output,
    _parse_ssl_enum_ciphers_output,
)

SCHEMA = "octo.nmap_pulse_corpus_gap.v1"

# Names that are the same service under two labelling conventions: Pulse says
# "https" where Nmap says "http" with a TLS tunnel, Nmap's table says
# "ms-wbt-server" / "microsoft-ds" where Pulse says "rdp" / "smb".
_SERVICE_CANON = {
    "https": "http",
    "https-alt": "http",
    "ms-wbt-server": "rdp",
    "microsoft-ds": "smb",
    "postgres": "postgresql",
}

Key = tuple[str, int, str]  # (host, port, protocol)


def _canon_service(name: str) -> str:
    n = (name or "").strip().lower()
    return _SERVICE_CANON.get(n, n)


def _load_pulse(pulse_dir: Path) -> dict[str, dict[str, Any]]:
    """Read every ``pulse/*.json`` payload, keyed by file stem."""
    payloads: dict[str, dict[str, Any]] = {}
    for path in sorted(pulse_dir.glob("*.json")):
        payloads[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return payloads


def _pulse_endpoints(payload: dict[str, Any]) -> dict[Key, dict[str, Any]]:
    """Per-endpoint Pulse view: parsed record plus the raw ``open[]`` row (CPE lives there)."""
    services, _, _ = parse_pulse_json(payload)
    raw_rows = {
        (str(r.get("ip") or ""), int(r.get("port") or 0), str(r.get("protocol") or "tcp").lower()): r
        for r in payload.get("open") or []
        if isinstance(r, dict)
    }
    out: dict[Key, dict[str, Any]] = {}
    for s in services:
        raw = raw_rows.get((s.ip, s.port, s.protocol), {})
        cpe = raw.get("cpe") or []
        out[(s.ip, s.port, s.protocol)] = {
            "service": s.service,
            "product": s.product,
            "version": s.version,
            "cpe": [cpe] if isinstance(cpe, str) else [str(c) for c in cpe],
            "banner": s.banner,
            "detection_method": str(raw.get("detection_method") or ""),
        }
    return out


def _nmap_endpoints(services: list[dict]) -> dict[Key, dict[str, Any]]:
    out: dict[Key, dict[str, Any]] = {}
    for s in services:
        out[(s["host"], int(s["port"]), s["protocol"] or "tcp")] = {
            "service": s["service"],
            "product": s["product"],
            "version": s["version"],
            "extrainfo": s["extrainfo"],
            "cpe": list(s["cpe"]),
        }
    return out


def _product_match(nmap_product: str, pulse_product: str) -> bool:
    """Equal, or one is a leading part of the other ("Microsoft IIS" / "Microsoft IIS httpd")."""
    a, b = nmap_product.strip().lower(), pulse_product.strip().lower()
    return bool(a and b and (a == b or a.startswith(b + " ") or b.startswith(a + " ")))


def _version_class(nmap_version: str, pulse_version: str) -> str:
    """exact | base_only | mismatch | missing_in_pulse | not_in_nmap."""
    n, p = nmap_version.strip(), pulse_version.strip()
    if not n:
        return "not_in_nmap"
    if not p:
        return "missing_in_pulse"
    if n == p:
        return "exact"
    # Nmap keeps the distribution revision in `version` ("8.2p1 Ubuntu 4ubuntu0.13");
    # Pulse stops at the upstream version. Same release, less information.
    if n.startswith(p + " "):
        return "base_only"
    return "mismatch"


def _tls_nmap(nmap_dir: Path) -> dict[tuple[str, int], dict[str, Any]]:
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for host, port, script_id, output in _iter_ssl_scripts(nmap_dir):
        entry = out.setdefault((host, int(port)), {"versions": {}, "cn": None})
        if script_id == "ssl-enum-ciphers":
            for v in _parse_ssl_enum_ciphers_output(output):
                entry["versions"][v["version"]] = {
                    "ciphers": len(v["ciphers"]),
                    "least_strength": v["least_strength"],
                }
        elif script_id == "ssl-cert":
            subject = _parse_ssl_cert_output(output).get("subject") or ""
            entry["cn"] = subject.split("commonName=", 1)[1].split("/")[0] if "commonName=" in subject else None
    return out


def _tls_pulse(payloads: dict[str, dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    out: dict[tuple[str, int], dict[str, Any]] = {}
    for payload in payloads.values():
        for row in extract_pulse_tls(payload):
            key = (str(row.get("ip") or ""), int(row.get("port") or 0))
            versions = {_normalize_proto_label(str(p)) for p in row.get("accepts_weak_protocols") or []}
            if row.get("negotiated_protocol"):
                versions.add(_normalize_proto_label(str(row["negotiated_protocol"])))
            out[key] = {"versions": versions, "cn": row.get("subject_cn")}
    return out


def _tls_section(nmap_dir: Path, payloads: dict[str, dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    nm, pu = _tls_nmap(nmap_dir), _tls_pulse(payloads)
    both = sorted(set(nm) & set(pu))
    rows: list[dict[str, Any]] = []
    proto_equal = weak_agree = cn_match = 0
    for key in sorted(set(nm) | set(pu)):
        n, p = nm.get(key), pu.get(key)
        n_versions = set(n["versions"]) if n else set()
        p_versions = set(p["versions"]) if p else set()
        row = {
            "endpoint": f"{key[0]}:{key[1]}",
            "nmap_protocols": sorted(n_versions),
            "pulse_protocols": sorted(p_versions),
            "nmap_ciphers": sum(v["ciphers"] for v in n["versions"].values()) if n else 0,
            "nmap_least_strength": sorted({v["least_strength"] for v in n["versions"].values() if v["least_strength"]}) if n else [],
        }
        if key in both:
            same = n_versions == p_versions
            proto_equal += same
            weak_agree += (n_versions & set(_WEAK_PROTOCOLS)) == (p_versions & set(_WEAK_PROTOCOLS))
            cn_match += bool(n["cn"] and p["cn"] and n["cn"] == p["cn"])
            row["protocol_sets_equal"] = same
        rows.append(row)
    summary = {
        "nmap_endpoints": len(nm),
        "pulse_endpoints": len(pu),
        "both": len(both),
        "protocol_sets_equal": proto_equal,
        "weak_protocol_verdict_agrees": weak_agree,
        "nmap_weak_protocol_endpoints": sum(1 for v in nm.values() if set(v["versions"]) & set(_WEAK_PROTOCOLS)),
        "pulse_weak_protocol_endpoints": sum(1 for v in pu.values() if v["versions"] & set(_WEAK_PROTOCOLS)),
        "nmap_cipher_suites_enumerated": sum(r["nmap_ciphers"] for r in rows),
        "pulse_cipher_suites_enumerated": 0,  # Pulse reports the negotiated protocol only (no suite list in tls[])
        "cert_cn_match": cn_match,
    }
    return summary, rows


def compare_corpus(corpus_dir: Path) -> dict[str, Any]:
    """Build the gap report for one corpus directory (``nmap/`` + ``pulse/``)."""
    nmap_dir, pulse_dir = corpus_dir / "nmap", corpus_dir / "pulse"
    n_services, _, n_scripts = _parse_nmap_xml(nmap_dir)
    payloads = _load_pulse(pulse_dir)
    # The adapter-shaped run: TCP (banners, --os sinfp, --cve) plus the UDP probe.
    primary = {name: p for name, p in payloads.items() if name in ("tcp", "udp")}

    nmap_eps = _nmap_endpoints(n_services)
    pulse_eps: dict[Key, dict[str, Any]] = {}
    for payload in primary.values():
        pulse_eps.update(_pulse_endpoints(payload))

    rows: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for key in sorted(set(nmap_eps) | set(pulse_eps)):
        n, p = nmap_eps.get(key), pulse_eps.get(key)
        row: dict[str, Any] = {"endpoint": f"{key[0]}:{key[1]}/{key[2]}", "nmap": n, "pulse": p}
        if n and p:
            counts["both"] += 1
            svc_ok = _canon_service(n["service"]) == _canon_service(p["service"])
            counts["service_match" if svc_ok else "service_mismatch"] += 1
            row["service_match"] = svc_ok
            if n["product"]:
                counts["product_in_nmap"] += 1
                if not p["product"]:
                    counts["product_missing_in_pulse"] += 1
                elif _product_match(n["product"], p["product"]):
                    counts["product_match"] += 1
                else:
                    counts["product_mismatch"] += 1
            vclass = _version_class(n["version"], p["version"])
            row["version_class"] = vclass
            counts["version_" + vclass] += 1
        elif n:
            counts["only_nmap"] += 1
        else:
            counts["only_pulse"] += 1
        if n and n["cpe"]:
            counts["cpe_endpoints_nmap"] += 1
        if p and p["cpe"]:
            counts["cpe_endpoints_pulse"] += 1
        rows.append(row)

    tls_summary, tls_rows = _tls_section(nmap_dir, payloads)

    # Script findings. Nmap: every per-port script that printed something, and the
    # CVEs its vuln/vulners scripts name. Pulse: its findings, by class.
    port_scripts = [s for s in n_scripts if s["port"] and s["output"]]
    nmap_cves = {(s["host"], s["port"], v["cve"]) for s in port_scripts for v in _build_vulnerabilities([s])}
    pulse_findings: list[Any] = []
    for payload in primary.values():
        _, _, cves = parse_pulse_json(payload)
        pulse_findings.extend(cves)
    pulse_cves = {(c.ip, str(c.port), c.cve_id) for c in pulse_findings if c.cve_id}
    scripts_summary = {
        "nmap_port_script_outputs": len(port_scripts),
        "nmap_distinct_script_ids": len({s["script_id"] for s in port_scripts}),
        "nmap_flagged_vulnerable": sum(1 for s in port_scripts if s["vulnerable"]),
        "pulse_findings": len(pulse_findings),
        "pulse_findings_by_class": dict(sorted(Counter(c.finding_class for c in pulse_findings).items())),
        "pulse_scripts_run_findings": len((payloads.get("tcp-scripts") or {}).get("findings") or []),
        "cve_both": len(nmap_cves & pulse_cves),
        "cve_only_nmap": len(nmap_cves - pulse_cves),
        "cve_only_pulse": len(pulse_cves - nmap_cves),
    }

    # Endpoint set and OS family: the pipeline's own shadow comparison, run on
    # Pulse artifacts written the way the pipeline writes them.
    with tempfile.TemporaryDirectory() as tmp:
        services, os_records = [], []
        for payload in primary.values():
            s, o, _ = parse_pulse_json(payload)
            services += s
            os_records += o
        write_pulse_artifacts(Path(tmp), services, os_records, [])
        shadow = compare_pulse_nmap(Path(tmp), nmap_dir)

    summary = {
        "endpoints": {
            "nmap": len(nmap_eps),
            "pulse": len(pulse_eps),
            "both": counts["both"],
            "only_nmap": counts["only_nmap"],
            "only_pulse": counts["only_pulse"],
        },
        "service": {"match": counts["service_match"], "mismatch": counts["service_mismatch"]},
        "product": {
            "nmap_has_product": counts["product_in_nmap"],
            "match": counts["product_match"],
            "mismatch": counts["product_mismatch"],
            "missing_in_pulse": counts["product_missing_in_pulse"],
        },
        "version": {
            "exact": counts["version_exact"],
            "base_only": counts["version_base_only"],
            "mismatch": counts["version_mismatch"],
            "missing_in_pulse": counts["version_missing_in_pulse"],
            "not_in_nmap": counts["version_not_in_nmap"],
        },
        "cpe": {
            "endpoints_nmap": counts["cpe_endpoints_nmap"],
            "endpoints_pulse": counts["cpe_endpoints_pulse"],
        },
        "tls": tls_summary,
        "scripts": scripts_summary,
        "os": {
            "hosts_nmap": shadow["os"]["nmap_hosts"],
            "hosts_pulse": shadow["os"]["pulse_hosts"],
            "hosts_with_both": shadow["os"]["hosts_with_both"],
            "family_agree": shadow["os"]["family_agree"],
            "family_disagree": shadow["os"]["family_disagree_count"],
        },
        "shadow_endpoints_jaccard": shadow["endpoints"]["jaccard"],
    }
    return {"schema": SCHEMA, "summary": summary, "endpoints": rows, "tls": tls_rows}


def format_table(report: dict[str, Any]) -> str:
    """Plain-text summary: one ``section.key  value`` line per counter."""
    lines: list[str] = []
    for section, values in report["summary"].items():
        if isinstance(values, dict):
            for key, value in values.items():
                lines.append(f"{section}.{key:<34} {value}")
        else:
            lines.append(f"{section:<41} {values}")
    return "\n".join(lines)
