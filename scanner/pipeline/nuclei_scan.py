"""Nuclei template-based vulnerability/misconfig scanning.

Runs against already-discovered open web ports (``open_ports.txt``) -- same
candidate-endpoint selection as ``fingerprint.py``, no new port scan. Shells
out to the ``nuclei`` binary (built from source at a pinned version tag, see
``Dockerfile``) against a pinned ``nuclei-templates`` checkout, and parses
its JSONL output.

CVE-tagged matches (``info.classification.cve-id``) are split out as
``cve_findings`` in a shape compatible with ``report.py``'s
``vulnerabilities.json`` rows (``host``/``port``/``cve``/``cvss``/``severity``/
``script_id``, tagged ``source: "nuclei"``), so the caller
(``scanner/main.py``) can merge them into the same list that
``nmap-vulners``/``vulscan`` findings populate -- CVSS4/EPSS/KEV enrichment
and risk scoring then treat them identically. Non-CVE matches (exposed
panels, misconfig, tech detection) are reported only in ``nuclei.json``.

SAFETY: disabled by default (``nuclei.enabled = false``). Template scope is
capped by ``severities``/``exclude_tags`` (conservative by default -- see
``NucleiConfig``), and the candidate endpoint list is capped by
``max_targets`` -- past the cap, remaining endpoints are skipped and the run
is flagged "truncated". Never raises: a missing ``templates_dir``, missing
``nuclei`` binary, or a failed/timed-out invocation all degrade to a clean
``skipped_reason`` rather than failing the scan (same fail-soft convention
as ``fingerprint.py``/``tls_posture.py``).
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from .config_schema import NucleiConfig
from .protocol import is_ipv6, parse_endpoint
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("octo-man.nuclei")

_SEVERITY_CVSS_FLOOR = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
}


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
    hostpart = f"[{host}]" if is_ipv6(host) else host
    return f"{scheme}://{hostpart}:{port}/"


def _parse_result_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cve_ids = classification.get("cve-id") or []
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids]
    return {
        "host": str(raw.get("host") or ""),
        "port": str(raw.get("port") or ""),
        "matched_at": str(raw.get("matched-at") or ""),
        "template_id": str(raw.get("template-id") or ""),
        "name": str(info.get("name") or ""),
        "severity": str(info.get("severity") or "unknown").lower(),
        "tags": [str(t) for t in (info.get("tags") or [])],
        "cve": [str(c) for c in cve_ids if c],
        "cvss_score": classification.get("cvss-score"),
    }


def _to_vulnerability_row(finding: dict[str, Any]) -> dict[str, Any] | None:
    if not finding["cve"] or not finding["host"]:
        return None
    cvss = finding.get("cvss_score")
    if not isinstance(cvss, (int, float)):
        cvss = _SEVERITY_CVSS_FLOOR.get(finding["severity"])
    return {
        "host": finding["host"],
        "port": finding["port"],
        "cve": str(finding["cve"][0]).upper(),
        "cvss": cvss,
        "severity": finding["severity"],
        "script_id": f"nuclei:{finding['template_id']}",
        "source": "nuclei",
    }


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "nuclei.json", result)
    lines = [f"{f['host']}:{f['port']}:{f['template_id']}:{f['severity']}" for f in result["findings"]]
    write_lines(output_dir / "nuclei_findings.txt", lines)


def run_nuclei_scan(
    open_ports: list[str],
    config: NucleiConfig,
    output_dir: Path,
) -> dict[str, Any]:
    """Run nuclei against already-open web ports. Never raises."""
    result: dict[str, Any] = {
        "targets_considered": 0,
        "checked_count": 0,
        "findings": [],
        "cve_findings": [],
        "truncated": False,
        "skipped_reason": None,
    }
    if not config.enabled:
        result["skipped_reason"] = "nuclei.disabled"
        _persist(output_dir, result)
        return result

    if shutil.which("nuclei") is None:
        result["skipped_reason"] = "nuclei_binary_missing"
        _persist(output_dir, result)
        return result

    templates_dir = Path(config.templates_dir)
    if not templates_dir.is_dir():
        result["skipped_reason"] = "templates_dir_missing"
        _persist(output_dir, result)
        return result

    candidates = _candidate_endpoints(open_ports, set(config.http_ports), set(config.https_ports))
    result["targets_considered"] = len(candidates)
    if not candidates:
        result["skipped_reason"] = "no_web_ports"
        _persist(output_dir, result)
        return result

    truncated = len(candidates) > config.max_targets
    candidates = candidates[: config.max_targets]
    result["truncated"] = truncated

    targets_file = output_dir / "nuclei_targets.txt"
    jsonl_file = output_dir / "nuclei_raw.jsonl"
    urls = [_build_url(host, port, scheme) for host, port, scheme in candidates]
    write_lines(targets_file, urls)
    jsonl_file.unlink(missing_ok=True)

    command = [
        "nuclei",
        "-list", str(targets_file),
        "-templates", str(templates_dir),
        "-severity", ",".join(config.severities),
        "-exclude-tags", ",".join(config.exclude_tags),
        "-jsonl-export", str(jsonl_file),
        "-rate-limit", str(config.rate_limit),
        "-concurrency", str(config.concurrency),
        "-timeout", str(config.timeout_seconds),
        "-retries", str(config.retries),
        "-disable-update-check",
        "-silent",
        "-no-color",
    ]  # fmt: skip

    try:
        run_command(command, timeout=config.overall_timeout_seconds, retries=0, check=False)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("nuclei scan failed for %d endpoint(s): %s", len(candidates), exc)
        result["skipped_reason"] = "nuclei_run_failed"
        _persist(output_dir, result)
        return result

    findings: list[dict[str, Any]] = []
    cve_findings: list[dict[str, Any]] = []
    if jsonl_file.is_file():
        for line in jsonl_file.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = _parse_result_line(line)
            if raw is None:
                continue
            finding = _to_finding(raw)
            findings.append(finding)
            vuln_row = _to_vulnerability_row(finding)
            if vuln_row is not None:
                cve_findings.append(vuln_row)

    result["checked_count"] = len(candidates)
    result["findings"] = findings
    result["cve_findings"] = cve_findings
    _persist(output_dir, result)
    LOG.info(
        "nuclei: %d endpoint(s) scanned -> %d finding(s) (%d with CVE)%s",
        len(candidates),
        len(findings),
        len(cve_findings),
        " [truncated]" if truncated else "",
    )
    return result
