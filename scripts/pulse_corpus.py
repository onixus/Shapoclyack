"""Offline gap report: recorded Nmap XML vs recorded Pulse JSON (#541, ADR 0002).

The corpus lives in ``tests/fixtures/nmap_pulse_corpus/`` (``nmap/*.xml``,
``pulse/*.json``), recorded by ``record.sh`` on a compose stand while Nmap still
runs. This module reads it and counts, per ``host:port/proto``, where Pulse
differs from Nmap: service, product, version, CPE, TLS (protocols, suites,
certificate) and script findings. No network, no scanner binaries.

Parsing is not duplicated: Nmap XML goes through ``legacy_nmap.parse_nmap_xml`` and
``tls_posture``'s ``ssl-enum-ciphers`` / ``ssl-cert`` parsers (what the pipeline
itself uses), Pulse JSON through ``pulse_probe.parse_pulse_json``, and the
endpoint/OS comparison is ``compare_pulse_nmap`` below (the former
``pulse_shadow`` module, removed with the Nmap stage in #548), run on artifacts
written the way the pipeline writes them.

Lives in ``scripts/`` (imported by the CLI next to it and by the test with
``scripts/`` on ``sys.path``, as ``enrichment_bundle`` is), not in
``scanner/pipeline``, because the scanner package is copied into the production
images and nothing there calls this. It therefore reaches into private names;
a rename in these modules breaks this file, and ``tests/test_nmap_pulse_corpus.py``
is what notices:

- ``legacy_nmap``: ``parse_nmap_xml``
- ``report``: ``_build_vulnerabilities``
- ``tls_posture``: ``_WEAK_PROTOCOLS``, ``_iter_ssl_scripts``,
  ``_normalize_proto_label``, ``_parse_ssl_cert_output``,
  ``_parse_ssl_enum_ciphers_output``

The ``nse_vuln`` section (#547) does the same for Nmap's ``vuln`` category: every
script of it that printed on the stand, and where it goes now (a Nuclei template,
a Rhai plugin, TLS grading, version matching, or a stated refusal).

The numbers are a measurement of the gap, not a quality bar: Nmap is the
reference only because it is what exists. Where the stand's ground truth differs
from Nmap's answer (e.g. Samba reported as 4.6.2) the report still scores
agreement with Nmap and says so in ``docs/pulse-backend.md``.
"""

from __future__ import annotations

import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from scanner.pipeline.pulse_plugins import PLUGINS_DIR
from scanner.pipeline.pulse_probe import extract_pulse_tls, parse_pulse_json, write_pulse_artifacts
from scanner.pipeline.legacy_nmap import parse_nmap_xml
from scanner.pipeline.protocol import format_endpoint
from scanner.pipeline.report import _build_vulnerabilities
from scanner.pipeline.tls_posture import (
    _WEAK_PROTOCOLS,
    _iter_ssl_scripts,
    _normalize_proto_label,
    _parse_ssl_cert_output,
    _parse_ssl_enum_ciphers_output,
)

SCHEMA = "octo.nmap_pulse_corpus_gap.v1"


def _endpoint_key(host: str, port: str | int, protocol: str = "tcp") -> str:
    proto = (protocol or "tcp").lower()
    if proto in ("tcpsyn", "syn"):
        proto = "tcp"
    return format_endpoint(host, str(port), proto)


def _services_from_pulse(output_dir: Path) -> set[str]:
    path = output_dir / "services.json"
    if not path.exists():
        return set()
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(rows, list):
        return set()
    keys: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or row.get("host") or "").strip()
        port = row.get("port")
        if not ip or port is None:
            continue
        proto = str(row.get("protocol") or "tcp")
        keys.add(_endpoint_key(ip, port, proto))
    return keys


def _services_from_nmap(nmap_dir: Path) -> set[str]:
    services, _, _ = parse_nmap_xml(nmap_dir)
    keys: set[str] = set()
    for row in services:
        host = str(row.get("host") or "")
        port = row.get("port") or ""
        proto = str(row.get("protocol") or "tcp")
        if host and port:
            keys.add(_endpoint_key(host, port, proto))
    return keys


def _os_from_pulse(output_dir: Path) -> dict[str, dict[str, Any]]:
    path = output_dir / "os.json"
    if not path.exists():
        return {}
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(rows, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = str(row.get("ip") or "").strip()
        if not ip:
            continue
        out[ip] = {
            "family": str(row.get("family") or ""),
            "detail": str(row.get("detail") or ""),
            "confidence": row.get("confidence"),
            "source": str(row.get("source") or "pulse"),
        }
    return out


def _os_from_nmap(nmap_dir: Path) -> dict[str, dict[str, Any]]:
    _, os_matches, _ = parse_nmap_xml(nmap_dir)
    out: dict[str, dict[str, Any]] = {}
    for row in os_matches:
        host = str(row.get("host") or "")
        if not host or host in out:
            continue  # first/best match only
        acc = row.get("accuracy") or "0"
        try:
            conf = int(float(acc))
        except (TypeError, ValueError):
            conf = 0
        name = str(row.get("name") or "")
        family = name.split()[0] if name else ""
        out[host] = {
            "family": family,
            "detail": name,
            "confidence": conf,
            "source": "nmap",
        }
    return out


def _family_agree(a: str, b: str) -> bool:
    a = (a or "").strip().lower()
    b = (b or "").strip().lower()
    if not a or not b or a == "unknown" or b == "unknown":
        return False
    return a == b or a in b or b in a


def compare_pulse_nmap(output_dir: Path, nmap_dir: Path | None = None) -> dict[str, Any]:
    """Build a comparison dict for one run directory."""
    nmap_dir = nmap_dir or (output_dir / "nmap")
    pulse_eps = _services_from_pulse(output_dir)
    nmap_eps = _services_from_nmap(nmap_dir)
    only_pulse = sorted(pulse_eps - nmap_eps)
    only_nmap = sorted(nmap_eps - pulse_eps)
    both = sorted(pulse_eps & nmap_eps)

    pulse_os = _os_from_pulse(output_dir)
    nmap_os = _os_from_nmap(nmap_dir)
    os_hosts = sorted(set(pulse_os) | set(nmap_os))
    os_agree = 0
    os_disagree: list[dict[str, Any]] = []
    for host in os_hosts:
        p = pulse_os.get(host)
        n = nmap_os.get(host)
        if p and n and _family_agree(str(p.get("family")), str(n.get("family"))):
            os_agree += 1
        elif p and n:
            os_disagree.append(
                {
                    "host": host,
                    "pulse": p,
                    "nmap": n,
                }
            )

    both_count = len(both)
    union = len(pulse_eps | nmap_eps)
    jaccard = (both_count / union) if union else 1.0

    return {
        "schema": "octo.pulse_nmap_diff.v1",
        "endpoints": {
            "pulse_count": len(pulse_eps),
            "nmap_count": len(nmap_eps),
            "both_count": both_count,
            "only_pulse_count": len(only_pulse),
            "only_nmap_count": len(only_nmap),
            "jaccard": round(jaccard, 4),
            "only_pulse_sample": only_pulse[:50],
            "only_nmap_sample": only_nmap[:50],
        },
        "os": {
            "pulse_hosts": len(pulse_os),
            "nmap_hosts": len(nmap_os),
            "hosts_with_both": sum(1 for h in os_hosts if h in pulse_os and h in nmap_os),
            "family_agree": os_agree,
            "family_disagree_count": len(os_disagree),
            "family_disagree_sample": os_disagree[:20],
        },
        "pulse_present": bool(pulse_eps or pulse_os or (output_dir / "services.json").exists()),
        "nmap_present": nmap_dir.exists() and any(nmap_dir.rglob("*.xml")),
    }


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

#: The NSE scripts of ``default,safe`` that identified something on this stand
#: (#544, ADR 0002), and what Shapoclyack's Rhai plugins do about each. ``plugin``
#: is the file stem; ``None`` means nothing does, and ``why`` is the reason
#: Frozen v1.3.0 recording map, not current candidate capability. Binary/UDP
#: and native 1.4.0 helpers are described separately in ``docs/pulse-plugins.md``;
#: do not rewrite recorded evidence/counts as candidate acceptance.
RECORDED_NSE_PLUGIN_MAP: dict[str, dict[str, str | None]] = {
    "ssh2-enum-algos": {"plugin": "shapo_ssh_algorithms", "covers": "weak algorithms only, not the full lists"},
    "ssh-hostkey": {"plugin": None, "why": "key fingerprints need the key exchange: binary packets"},
    "ftp-anon": {"plugin": "shapo_ftp_anonymous", "covers": "login accepted or not; no directory listing (needs a data connection)"},
    "ftp-syst": {"plugin": None, "why": "informational (SYST reply); not a finding"},
    "smb2-security-mode": {
        "plugin": None, "why": "SMB2 negotiate starts with 0xFE: a byte the sandbox cannot send",
        "nuclei": "smb-signing-not-required",  # the network pass (nuclei_network.NETWORK_RULES), #547
    },
    "smb-security-mode": {"plugin": None, "why": "SMB1 negotiate starts with 0xFF: a byte the sandbox cannot send"},
    "smb-protocols": {"plugin": None, "why": "SMB negotiate: a byte the sandbox cannot send"},
    "rdp-enum-encryption": {"plugin": None, "why": "X.224 request carries 0xE0: a byte the sandbox cannot send"},
    "rdp-ntlm-info": {"plugin": None, "why": "CredSSP/NTLM over X.224: bytes the sandbox cannot send"},
    "snmp-info": {"plugin": None, "why": "SNMP is UDP; the sandbox opens TCP only"},
    "http-trace": {"plugin": "shapo_http_trace", "covers": "TRACE echo over plain HTTP only; HTTPS is out of the sandbox's reach"},
}
#: Plugins with no NSE script behind them: what they report beyond Nmap's default,safe.
RECORDED_PLUGIN_ONLY = {
    "shapo_cleartext_services": "services that cannot start TLS (Nmap's default,safe has no such check)",
    "shapo_ssh_banner": "protocol 1 / end-of-life OpenSSH from the banner (Pulse's CVE rules overlap)",
    "shapo_smb_exposure": "reachability of SMB/NetBIOS only (Pulse's own exposure rules overlap)",
    "shapo_remote_admin_exposure": "reachability of RDP/VNC only (Pulse's own exposure rules overlap)",
}


#: Where each NSE script of the ``vuln`` category goes (#547, ADR 0002;
#: ``docs/nse-vuln-coverage.md`` has the reasoning and the live checks). One row
#: per script that printed on the stand, plus ``smb-vuln-ms17-010`` (it ran, said
#: nothing: Samba is not affected) and the non-``vuln`` scripts the issue names
#: (``related``). ``categories`` are read from ``/usr/share/nmap/scripts/<id>.nse``
#: of the stand's Nmap 7.93. ``destination`` is one of :data:`VULN_DESTINATIONS`;
#: ``ref`` names the template, plugin or mechanism, ``why`` the limit or refusal.
#: Template ids were looked up in nuclei-templates v9.9.4 (the image's pin).
VULN_DESTINATIONS = ("nuclei_network", "nuclei_web", "plugin", "tls", "version_match", "gap", "refused")
RECORDED_NSE_VULN_MAP: dict[str, dict[str, Any]] = {
    "vulners": {
        "categories": ["vuln", "safe", "external"], "destination": "version_match",
        "ref": "retro_match (API, offline NVD ranges) first; pulse --cve second",
        "why": "CVE by version, not a probe",
    },
    "http-vuln-cve2011-3192": {
        "categories": ["vuln", "safe"], "destination": "refused",
        "why": "judged from a many-range Range reply: flagged nginx 1.27 and 1.18 on the stand, never the Apache; a version fix is a version match",
    },
    "http-slowloris-check": {
        "categories": ["vuln", "safe"], "destination": "refused",
        "why": "holds connections open to starve the server: a DoS check, against the non-destructive posture (nuclei's dos tag is excluded for the same reason)",
    },
    "http-trace": {
        "categories": ["vuln", "discovery", "safe"], "destination": "plugin", "ref": "shapo_http_trace",
        "why": "plain HTTP only; nuclei http-trace is info, below the default severity floor",
    },
    "http-litespeed-sourcecode-download": {
        "categories": ["vuln", "intrusive", "exploit"], "destination": "refused",
        "why": "CVE-2010-2333 exploit probe; on the stand it 'found' the catch-all stub's index page",
    },
    "http-phpmyadmin-dir-traversal": {
        "categories": ["vuln", "exploit"], "destination": "refused",
        "why": "CVE-2005-3299 traversal exploit; the stand's output was UNKNOWN (unable to test) with the stub's page as evidence",
    },
    "http-majordomo2-dir-traversal": {
        "categories": ["intrusive", "vuln", "exploit"], "destination": "nuclei_web", "ref": "CVE-2011-0049",
        "why": "medium, tags cve,lfi: inside the default sweep's floor",
    },
    "http-vuln-cve2017-1001000": {
        "categories": ["vuln", "safe"], "destination": "refused",
        "why": "WordPress 4.7.0/4.7.1 REST write probe; no Nuclei template in v9.9.4 and a write request is not ours to send",
    },
    "http-csrf": {
        "categories": ["intrusive", "exploit", "vuln"], "destination": "refused",
        "why": "crawler/DAST: out of scope (nuclei's dast/ templates carry the fuzz tag, excluded)",
    },
    "http-dombased-xss": {
        "categories": ["intrusive", "exploit", "vuln"], "destination": "refused",
        "why": "crawler/DAST: out of scope",
    },
    "http-stored-xss": {
        "categories": ["intrusive", "exploit", "vuln"], "destination": "refused",
        "why": "crawler/DAST that submits forms: out of scope",
    },
    "ssl-ccs-injection": {
        "categories": ["vuln", "safe"], "destination": "tls", "ref": "#545",
        "why": "TLS handshake level; no Nuclei template either. Timed out on the stand's RDP stub",
    },
    "smb-vuln-ms10-054": {
        "categories": ["vuln", "intrusive", "dos"], "destination": "refused",
        "why": "dos category (malformed SMB request); the posture excludes it",
    },
    "smb-vuln-ms10-061": {
        "categories": ["vuln", "intrusive"], "destination": "gap",
        "why": "print-spooler RPC over SMB: binary protocol, no Nuclei template; GenDec#38",
    },
    "samba-vuln-cve-2012-1182": {
        "categories": ["vuln", "intrusive"], "destination": "version_match",
        "ref": "retro_match / pulse --cve",
        "why": "the probe is a malformed RPC call (intrusive); the affected range (Samba < 3.6.4) is a version question",
    },
    "smb-vuln-ms17-010": {
        "categories": ["vuln", "safe"], "destination": "gap",
        "why": "SMB1 transaction probe: binary, GenDec#38; v9.9.4 has no Nuclei template for MS17-010",
    },
    # --- named by the issue, not in the vuln category ---
    "smb2-security-mode": {
        "categories": ["safe", "discovery", "default"], "destination": "nuclei_network", "ref": "smb-signing-not-required",
        "related": True,
    },
    "smb-protocols": {
        "categories": ["safe", "discovery"], "destination": "gap",
        "why": "dialect list; nuclei smb-version-detect/samba-detect are info, below the floor, and report less",
        "related": True,
    },
    "rdp-enum-encryption": {
        "categories": ["safe", "discovery"], "destination": "gap",
        "why": "NLA/CredSSP/security-layer needs the X.224 handshake (0xE0): GenDec#38; nuclei rdp-detect only detects",
        "related": True,
    },
    "http-methods": {
        "categories": ["default", "safe"], "destination": "plugin", "ref": "shapo_http_trace",
        "why": "TRACE only; PUT/DELETE/CONNECT are not probed",
        "related": True,
    },
    "http-malware-host": {
        "categories": ["malware", "safe"], "destination": "refused",
        "why": "heuristics for an infected site; printed 'false' on the stand",
        "related": True,
    },
}


# Source capability accounting is separate from the frozen v1.3.0 observations.
# These registrations do not add measurements to tcp-plugins.json or close its gaps.
NSE_PLUGIN_MAP = dict(RECORDED_NSE_PLUGIN_MAP)
NSE_PLUGIN_MAP.update({
    "ssh-hostkey": {"plugin": "shapo_ssh_hostkey", "covers": "verified curve25519/Ed25519 host key only"},
    "smb2-security-mode": {"plugin": "shapo_smb_signing", "covers": "SMB2 selected negotiation signing flags"},
    "smb-security-mode": {"plugin": "shapo_smb1", "covers": "SMB1 negotiation only"},
    "smb-protocols": {"plugin": "shapo_smb_protocols", "covers": "bounded SMB1/SMB2 dialect offers, partial errors explicit"},
    "rdp-enum-encryption": {"plugin": "shapo_rdp_negotiation", "covers": "security layer selection only, not full encryption enumeration"},
    "rdp-ntlm-info": {"plugin": "shapo_rdp_ntlm_info", "covers": "unauthenticated type2 host inventory only"},
    "snmp-info": {"plugin": "shapo_snmp_info", "covers": "standalone UDP sysDescr/sysName GET only"},
    "smb-vuln-ms17-010": {"plugin": "shapo_ms17_010", "covers": "positive read-only status hypothesis; other results UNKNOWN"},
    "vnc-info": {"plugin": "shapo_vnc_security", "covers": "advertised RFB security types only, no authentication"},
})
PLUGIN_ONLY = dict(RECORDED_PLUGIN_ONLY)
PLUGIN_ONLY.update({
    "shapo_rsync_modules": "unauthenticated listing only; module and file access untested",
    "shapo_zookeeper_envi": "unauthenticated envi diagnostic only; znode access untested",
    "shapo_redis_info": "unauthenticated INFO SERVER only; key and write access untested",
    "shapo_memcached_stats": "unauthenticated TCP stats only; item and UDP access untested",
})
NSE_VULN_MAP = {key: dict(value) for key, value in RECORDED_NSE_VULN_MAP.items()}
NSE_VULN_MAP["smb-vuln-ms17-010"].update(destination="plugin", ref="shapo_ms17_010")
NSE_VULN_MAP["smb-protocols"].update(destination="plugin", ref="shapo_smb_protocols")


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


def _plugin_findings(payload: dict[str, Any]) -> list[Any]:
    """The Rhai plugin findings of the adapter-shaped run with ``--script-dir``."""
    return [c for c in parse_pulse_json(payload)[2] if c.finding_class == "plugin_script"]


def _weak_ssh_names() -> set[str]:
    """The algorithm names ``shapo_ssh_algorithms`` calls weak, read from the plugin itself."""
    text = (PLUGINS_DIR / "shapo_ssh_algorithms.rhai").read_text(encoding="utf-8")
    names: set[str] = set()
    for fn in ("broken_algorithms", "deprecated_algorithms"):
        body = text.split(f"fn {fn}()", 1)[1].split("]", 1)[0]
        names.update(re.findall(r'"([^"]+)"', body))
    return names


def _plugins_section(
    corpus_dir: Path, n_scripts: list[dict[str, Any]], findings: list[Any]
) -> dict[str, Any]:
    """Where the plugins stand against the NSE scripts that ran on the same stand.

    For each NSE script in :data:`RECORDED_NSE_PLUGIN_MAP` that printed output: how many
    endpoints, which plugin answers it (or why none can), and, where both sides
    give a verdict, whether they agree per endpoint. A verdict is "weak
    algorithm present" for ``ssh2-enum-algos`` (Nmap's output read against the
    plugin's own list of weak names) and "anonymous login allowed" for
    ``ftp-anon``. Everything else is coverage by name only.
    """
    pulse_dir = corpus_dir / "pulse"
    files = [
        line.split()[1]
        for line in (pulse_dir / "plugins.sha256").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if (pulse_dir / "plugins.sha256").is_file() else []
    stderr_path = pulse_dir / "tcp-plugins.stderr"
    errors = (
        sum(1 for line in stderr_path.read_text(encoding="utf-8").splitlines() if "plugin error" in line)
        if stderr_path.is_file() else None
    )

    by_plugin = Counter(c.match_reason.removeprefix("rhai script ") for c in findings)
    flagged = {
        plugin: {(c.ip, c.port) for c in findings if c.match_reason == f"rhai script {plugin}"}
        for plugin in by_plugin
    }
    weak = _weak_ssh_names()
    nse: dict[str, Any] = {}
    for script_id, mapping in RECORDED_NSE_PLUGIN_MAP.items():
        # Host-level scripts (the SMB ones) have no port: they count as one "endpoint" per host.
        rows = [
            s for s in n_scripts
            if s["script_id"] == script_id and s["output"] and (s["port"] or mapping["plugin"] is None)
        ]
        if not rows:
            continue
        entry: dict[str, Any] = {"endpoints": len(rows), "plugin": mapping["plugin"]}
        if mapping.get("nuclei"):
            entry["nuclei"] = mapping["nuclei"]
        if mapping["plugin"] is None:
            entry["not_covered"] = mapping["why"]
        else:
            entry["covers"] = mapping["covers"]
            agree = 0
            for row in rows:
                if script_id == "ssh2-enum-algos":
                    nmap_says = bool(set(re.findall(r"[A-Za-z0-9@._+-]+", row["output"])) & weak)
                elif script_id == "ftp-anon":
                    nmap_says = "login allowed" in row["output"].lower()
                elif script_id == "http-trace":
                    nmap_says = "trace is enabled" in row["output"].lower()
                else:
                    continue
                plugin_says = (row["host"], int(row["port"])) in flagged.get(mapping["plugin"], set())
                agree += nmap_says == plugin_says
            entry["verdict_agrees"] = agree
        nse[script_id] = entry
    return {
        "files": len(files),
        "errors": errors,
        "findings_by_plugin": dict(sorted(by_plugin.items())),
        "plugin_only": sorted(p for p in RECORDED_PLUGIN_ONLY if p in by_plugin),
        "nse": nse,
    }


def _nse_vuln_section(n_scripts: list[dict[str, Any]], findings: list[Any]) -> dict[str, Any]:
    """Nmap's ``vuln`` scripts of the stand, and historical destinations (:data:`RECORDED_NSE_VULN_MAP`).

    ``endpoints`` is how many hosts/ports printed something, ``flagged`` how many of
    those Nmap itself marked VULNERABLE. ``plugin_flags`` is filled for a
    ``plugin`` destination: how many of the endpoints the plugin reports too.
    Nmap's XML carries no categories, so the map is the list; a recording that
    adds a ``vuln`` script has to add its row (the pinned numbers change).
    """
    flagged = {
        plugin: {(c.ip, c.port) for c in findings if c.match_reason == f"rhai script {plugin}"}
        for plugin in {c.match_reason.removeprefix("rhai script ") for c in findings}
    }
    scripts: dict[str, Any] = {}
    by_destination: Counter[str] = Counter()
    for script_id, mapping in RECORDED_NSE_VULN_MAP.items():
        rows = [s for s in n_scripts if s["script_id"] == script_id and s["output"]]
        entry: dict[str, Any] = {
            "vuln": "vuln" in mapping["categories"],
            "endpoints": len(rows),
            "flagged": sum(1 for s in rows if s["vulnerable"]),
            "destination": mapping["destination"],
        }
        if mapping["destination"] == "plugin":
            plugin = mapping["ref"]
            entry["plugin_flags"] = sum(
                1 for s in rows if s["port"] and (s["host"], int(s["port"])) in flagged.get(plugin, set())
            )
        scripts[script_id] = entry
        if entry["vuln"]:
            by_destination[mapping["destination"]] += 1
    vuln_ids = {i for i, m in RECORDED_NSE_VULN_MAP.items() if "vuln" in m["categories"]}
    vuln_rows = [s for s in n_scripts if s["output"] and s["script_id"] in vuln_ids]
    return {
        "vuln_scripts": sum(1 for e in scripts.values() if e["vuln"]),
        "vuln_scripts_printed": sum(1 for e in scripts.values() if e["vuln"] and e["endpoints"]),
        "vuln_outputs": len(vuln_rows),
        "vuln_flagged_by_nmap": sum(1 for s in vuln_rows if s["vulnerable"]),
        "by_destination": {d: by_destination[d] for d in VULN_DESTINATIONS if by_destination[d]},
        "scripts": scripts,
    }


def compare_corpus(corpus_dir: Path) -> dict[str, Any]:
    """Build the gap report for one corpus directory (``nmap/`` + ``pulse/``)."""
    nmap_dir, pulse_dir = corpus_dir / "nmap", corpus_dir / "pulse"
    n_services, _, n_scripts = parse_nmap_xml(nmap_dir)
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
    plugin_findings = _plugin_findings(payloads.get("tcp-plugins") or {})
    scripts_summary = {
        "nmap_port_script_outputs": len(port_scripts),
        "nmap_distinct_script_ids": len({s["script_id"] for s in port_scripts}),
        "nmap_flagged_vulnerable": sum(1 for s in port_scripts if s["vulnerable"]),
        "pulse_findings": len(pulse_findings),
        "pulse_findings_by_class": dict(sorted(Counter(c.finding_class for c in pulse_findings).items())),
        "pulse_plugin_findings": len(plugin_findings),
        "cve_both": len(nmap_cves & pulse_cves),
        "cve_only_nmap": len(nmap_cves - pulse_cves),
        "cve_only_pulse": len(pulse_cves - nmap_cves),
    }

    # Endpoint set and OS family: the endpoint/OS comparison, run on
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
        "plugins": _plugins_section(corpus_dir, n_scripts, plugin_findings),
        "nse_vuln": _nse_vuln_section(n_scripts, plugin_findings),
        "os": {
            "hosts_nmap": shadow["os"]["nmap_hosts"],
            "hosts_pulse": shadow["os"]["pulse_hosts"],
            "hosts_with_both": shadow["os"]["hosts_with_both"],
            "family_agree": shadow["os"]["family_agree"],
            "family_disagree": shadow["os"]["family_disagree_count"],
        },
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
