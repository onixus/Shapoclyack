"""Shadow-mode comparison: Pulse artifacts vs Nmap XML from the same run.

Writes ``diff_pulse_nmap.json`` under the run output dir. Pure offline compare
(no extra scanning). Used when both backends produced data (hybrid, or
``service_probe.shadow`` / ``OCTO_PULSE_SHADOW=1`` with nmap default).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .report import _parse_nmap_xml


def _endpoint_key(host: str, port: str | int, protocol: str = "tcp") -> str:
    proto = (protocol or "tcp").lower()
    if proto in ("tcpsyn", "syn"):
        proto = "tcp"
    return f"{host}:{port}/{proto}"


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
    services, _, _ = _parse_nmap_xml(nmap_dir)
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
    _, os_matches, _ = _parse_nmap_xml(nmap_dir)
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


def write_pulse_nmap_diff(
    output_dir: Path,
    nmap_dir: Path | None = None,
    *,
    extra: dict[str, Any] | None = None,
) -> Path:
    """Compare and write ``diff_pulse_nmap.json``. Returns path written."""
    diff = compare_pulse_nmap(output_dir, nmap_dir)
    if extra:
        diff["meta"] = extra
    path = output_dir / "diff_pulse_nmap.json"
    path.write_text(json.dumps(diff, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    ep = diff["endpoints"]
    os_ = diff["os"]
    logging.info(
        "pulse/nmap shadow: endpoints jaccard=%.3f pulse=%s nmap=%s only_pulse=%s only_nmap=%s; "
        "os agree=%s disagree=%s",
        ep["jaccard"],
        ep["pulse_count"],
        ep["nmap_count"],
        ep["only_pulse_count"],
        ep["only_nmap_count"],
        os_["family_agree"],
        os_["family_disagree_count"],
    )
    return path
