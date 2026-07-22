from __future__ import annotations

import json
import logging
from pathlib import Path

from .protocol import parse_endpoint
from .report import SEVERITY_ORDER
from .utils import load_json, read_lines, save_json

_CERT_ISSUE_KINDS = ("cert_expired", "cert_expiring_soon")


def resolve_previous_run_dir(
    *,
    output_base: Path,
    state_base: Path,
    previous_run_dir: str = "",
    compare_run_id: str = "",
    per_run_output: bool = True,
) -> Path | None:
    """Locate a prior run directory for report diffs.

    Must be called *before* ``resolve_run_paths`` overwrites ``latest_run.json``.
    """
    if previous_run_dir:
        candidate = Path(previous_run_dir)
        return candidate if candidate.is_dir() else None

    if compare_run_id:
        candidate = output_base / "runs" / compare_run_id
        return candidate if candidate.is_dir() else None

    if not per_run_output:
        # Flat layout has no distinct previous run directory.
        return None

    pointer = state_base / "latest_run.json"
    if not pointer.exists():
        return None
    run_id = json.loads(pointer.read_text(encoding="utf-8")).get("run_id")
    if not run_id:
        return None
    candidate = output_base / "runs" / str(run_id)
    return candidate if candidate.is_dir() else None


def _vuln_key(item: dict) -> str:
    host = str(item.get("host") or "")
    port = str(item.get("port") or "")
    cve = str(item.get("cve") or item.get("script_id") or "")
    return f"{host}|{port}|{cve}"


def _load_vulns(run_dir: Path) -> dict[str, dict]:
    raw = load_json(run_dir / "vulnerabilities.json", fallback=[])
    if not isinstance(raw, list):
        return {}
    return {_vuln_key(item): item for item in raw if isinstance(item, dict)}


def _set_diff(current: set[str], previous: set[str]) -> dict[str, list[str]]:
    return {
        "added": sorted(current - previous),
        "removed": sorted(previous - current),
    }


def _load_tls_findings(run_dir: Path) -> dict[tuple[str, str], dict]:
    raw = load_json(run_dir / "tls_posture.json", fallback={})
    findings = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(findings, list):
        return {}
    return {
        (str(item.get("host")), str(item.get("port"))): item
        for item in findings
        if isinstance(item, dict)
    }


def _diff_cert_expiring(current_dir: Path, previous_dir: Path) -> list[dict]:
    """A cert_expiring event fires the run a host:port's TLS posture *first*
    shows a cert_expired/cert_expiring_soon issue — not on every run it's
    still present, since tls_posture.py re-evaluates from scratch each time
    (no cross-run memory of its own)."""
    current = _load_tls_findings(current_dir)
    previous = _load_tls_findings(previous_dir)
    events: list[dict] = []
    for host, port in sorted(current):
        finding = current[(host, port)]
        issues = {issue.get("kind"): issue for issue in (finding.get("issues") or [])}
        prev_finding = previous.get((host, port))
        prev_kinds = (
            {issue.get("kind") for issue in (prev_finding.get("issues") or [])} if prev_finding else set()
        )
        for issue_kind in _CERT_ISSUE_KINDS:
            if issue_kind not in issues or issue_kind in prev_kinds:
                continue
            events.append(
                {
                    "kind": "cert_expiring",
                    "issue_kind": issue_kind,
                    "host": host,
                    "port": port,
                    "days": issues[issue_kind].get("days"),
                    "not_after": (finding.get("cert") or {}).get("not_after"),
                }
            )
    return events


def compute_report_diff(current_dir: Path, previous_dir: Path) -> dict:
    """Compare key artifacts between two run directories."""
    current_alive = set(read_lines(current_dir / "alive_ips.txt"))
    previous_alive = set(read_lines(previous_dir / "alive_ips.txt"))
    current_ports = set(read_lines(current_dir / "open_ports.txt"))
    previous_ports = set(read_lines(previous_dir / "open_ports.txt"))
    current_vulns = _load_vulns(current_dir)
    previous_vulns = _load_vulns(previous_dir)

    hosts = _set_diff(current_alive, previous_alive)
    ports = _set_diff(current_ports, previous_ports)
    vuln_keys = _set_diff(set(current_vulns), set(previous_vulns))

    added_vulns = [current_vulns[key] for key in vuln_keys["added"]]
    removed_vulns = [previous_vulns[key] for key in vuln_keys["removed"]]
    added_vulns.sort(
        key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity", "unknown")), 0), item.get("cvss") or 0.0),
        reverse=True,
    )
    removed_vulns.sort(
        key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity", "unknown")), 0), item.get("cvss") or 0.0),
        reverse=True,
    )

    current_summary = load_json(current_dir / "summary.json", fallback={})
    previous_summary = load_json(previous_dir / "summary.json", fallback={})
    summary_delta: dict[str, dict[str, int]] = {}
    for key in (
        "alive_hosts",
        "open_host_port_pairs",
        "potential_vulnerabilities",
        "vulnerable_hosts",
    ):
        cur = int(current_summary.get(key, 0) or 0) if isinstance(current_summary, dict) else 0
        prev = int(previous_summary.get(key, 0) or 0) if isinstance(previous_summary, dict) else 0
        summary_delta[key] = {"current": cur, "previous": prev, "delta": cur - prev}

    # Normalized asset-level events (Phase 10.1): one {"kind": ..., "host": ...}
    # dict per new_asset/new_open_port/new_cve/cert_expiring occurrence, so a
    # future event bus (Phase 10.2) can publish each verbatim to
    # events.asset.{kind} without per-field-type translation. Removals don't
    # get an event kind here — only new/positive occurrences do, matching the
    # five kinds ROADMAP Phase 10.1 names (decommissioned_host is emitted
    # separately, at PATCH /assets/{id} write-time — see api/services/assets.py).
    events: list[dict] = []
    for ip in hosts["added"]:
        events.append({"kind": "new_asset", "host": ip})
    for line in ports["added"]:
        parsed = parse_endpoint(line)
        if parsed is None:
            continue
        events.append(
            {
                "kind": "new_open_port",
                "host": parsed.host,
                "port": parsed.port,
                "protocol": parsed.protocol,
            }
        )
    for vuln in added_vulns:
        events.append({**vuln, "kind": "new_cve"})
    events.extend(_diff_cert_expiring(current_dir, previous_dir))

    has_changes = bool(events or hosts["removed"] or ports["removed"] or removed_vulns)

    return {
        "current_run_dir": str(current_dir),
        "previous_run_dir": str(previous_dir),
        "has_changes": has_changes,
        "hosts": hosts,
        "ports": ports,
        "vulnerabilities": {
            "added": added_vulns,
            "removed": removed_vulns,
            "added_count": len(added_vulns),
            "removed_count": len(removed_vulns),
        },
        "events": events,
        "summary_delta": summary_delta,
        "counts": {
            "hosts_added": len(hosts["added"]),
            "hosts_removed": len(hosts["removed"]),
            "ports_added": len(ports["added"]),
            "ports_removed": len(ports["removed"]),
            "vulns_added": len(added_vulns),
            "vulns_removed": len(removed_vulns),
            "events": len(events),
        },
    }


def _format_vuln_line(item: dict) -> str:
    location = f"{item.get('host')}:{item.get('port')}" if item.get("port") else str(item.get("host") or "")
    cve = item.get("cve") or item.get("script_id") or "unknown"
    severity = str(item.get("severity") or "unknown").upper()
    cvss = f" CVSS {item['cvss']}" if item.get("cvss") is not None else ""
    return f"- [{severity}] {location} {cve}{cvss}"


def _format_event_line(event: dict) -> str:
    kind = event.get("kind", "unknown")
    host = str(event.get("host") or "")
    if kind == "new_open_port":
        return f"- [{kind}] {host}:{event.get('port')}/{event.get('protocol')}"
    if kind == "cert_expiring":
        return f"- [{kind}] {host}:{event.get('port')} {event.get('issue_kind')} (days={event.get('days')})"
    if kind == "new_cve":
        return _format_vuln_line(event)
    return f"- [{kind}] {host}"


def render_diff_markdown(diff: dict) -> str:
    counts = diff.get("counts") or {}
    lines = [
        "# Scan Diff",
        "",
        f"- Previous run: `{diff.get('previous_run_dir', '')}`",
        f"- Current run: `{diff.get('current_run_dir', '')}`",
        f"- Changes detected: {'yes' if diff.get('has_changes') else 'no'}",
        "",
        "## Counts",
        f"- Hosts: +{counts.get('hosts_added', 0)} / -{counts.get('hosts_removed', 0)}",
        f"- Open ports: +{counts.get('ports_added', 0)} / -{counts.get('ports_removed', 0)}",
        f"- Vulnerabilities: +{counts.get('vulns_added', 0)} / -{counts.get('vulns_removed', 0)}",
        "",
        "## Hosts added",
    ]
    hosts = diff.get("hosts") or {}
    added_hosts = hosts.get("added") or []
    if added_hosts:
        lines.extend(f"- {host}" for host in added_hosts[:100])
        if len(added_hosts) > 100:
            lines.append(f"- ... and {len(added_hosts) - 100} more")
    else:
        lines.append("- none")

    lines += ["", "## Hosts removed"]
    removed_hosts = hosts.get("removed") or []
    if removed_hosts:
        lines.extend(f"- {host}" for host in removed_hosts[:100])
        if len(removed_hosts) > 100:
            lines.append(f"- ... and {len(removed_hosts) - 100} more")
    else:
        lines.append("- none")

    lines += ["", "## Ports added"]
    ports = diff.get("ports") or {}
    added_ports = ports.get("added") or []
    if added_ports:
        lines.extend(f"- {port}" for port in added_ports[:100])
        if len(added_ports) > 100:
            lines.append(f"- ... and {len(added_ports) - 100} more")
    else:
        lines.append("- none")

    lines += ["", "## Ports removed"]
    removed_ports = ports.get("removed") or []
    if removed_ports:
        lines.extend(f"- {port}" for port in removed_ports[:100])
        if len(removed_ports) > 100:
            lines.append(f"- ... and {len(removed_ports) - 100} more")
    else:
        lines.append("- none")

    vulns = diff.get("vulnerabilities") or {}
    lines += ["", "## Vulnerabilities added"]
    added = vulns.get("added") or []
    if added:
        lines.extend(_format_vuln_line(item) for item in added[:50])
        if len(added) > 50:
            lines.append(f"- ... and {len(added) - 50} more")
    else:
        lines.append("- none")

    lines += ["", "## Vulnerabilities removed"]
    removed = vulns.get("removed") or []
    if removed:
        lines.extend(_format_vuln_line(item) for item in removed[:50])
        if len(removed) > 50:
            lines.append(f"- ... and {len(removed) - 50} more")
    else:
        lines.append("- none")

    lines += ["", "## Events"]
    events = diff.get("events") or []
    if events:
        lines.extend(_format_event_line(event) for event in events[:100])
        if len(events) > 100:
            lines.append(f"- ... and {len(events) - 100} more")
    else:
        lines.append("- none")

    return "\n".join(lines) + "\n"


def write_report_diff(
    current_dir: Path,
    previous_dir: Path,
    *,
    markdown: bool = True,
) -> dict:
    diff = compute_report_diff(current_dir, previous_dir)
    save_json(current_dir / "diff.json", diff)
    if markdown:
        (current_dir / "diff.md").write_text(render_diff_markdown(diff), encoding="utf-8")
    logging.info(
        "Report diff vs %s: hosts +%s/-%s, ports +%s/-%s, vulns +%s/-%s, events %s",
        previous_dir,
        diff["counts"]["hosts_added"],
        diff["counts"]["hosts_removed"],
        diff["counts"]["ports_added"],
        diff["counts"]["ports_removed"],
        diff["counts"]["vulns_added"],
        diff["counts"]["vulns_removed"],
        diff["counts"]["events"],
    )
    return diff
