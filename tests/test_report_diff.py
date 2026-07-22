from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.report_diff import (
    compute_report_diff,
    resolve_previous_run_dir,
    write_report_diff,
)


def _write_run(run_dir: Path, *, alive: list[str], ports: list[str], vulns: list[dict]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_ips.txt").write_text("\n".join(alive) + "\n", encoding="utf-8")
    (run_dir / "open_ports.txt").write_text("\n".join(ports) + "\n", encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns, indent=2) + "\n", encoding="utf-8")
    (run_dir / "summary.json").write_text(
        json.dumps(
            {
                "alive_hosts": len(alive),
                "open_host_port_pairs": len(ports),
                "potential_vulnerabilities": len(vulns),
                "vulnerable_hosts": len({v["host"] for v in vulns}),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def test_compute_report_diff_detects_added_and_removed(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(
        prev,
        alive=["10.0.0.1", "10.0.0.2"],
        ports=["10.0.0.1:22", "10.0.0.2:80"],
        vulns=[
            {
                "host": "10.0.0.1",
                "port": "22",
                "cve": "CVE-2020-1",
                "cvss": 9.8,
                "severity": "critical",
                "script_id": "vulners",
            }
        ],
    )
    _write_run(
        cur,
        alive=["10.0.0.2", "10.0.0.3"],
        ports=["10.0.0.2:80", "10.0.0.3:443"],
        vulns=[
            {
                "host": "10.0.0.3",
                "port": "443",
                "cve": "CVE-2021-2",
                "cvss": 7.5,
                "severity": "high",
                "script_id": "vulners",
            }
        ],
    )

    diff = compute_report_diff(cur, prev)
    assert diff["has_changes"] is True
    assert diff["hosts"]["added"] == ["10.0.0.3"]
    assert diff["hosts"]["removed"] == ["10.0.0.1"]
    assert diff["ports"]["added"] == ["10.0.0.3:443"]
    assert diff["ports"]["removed"] == ["10.0.0.1:22"]
    assert diff["counts"]["vulns_added"] == 1
    assert diff["counts"]["vulns_removed"] == 1
    assert diff["summary_delta"]["alive_hosts"]["delta"] == 0


def test_write_report_diff_artifacts(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(prev, alive=["10.0.0.1"], ports=["10.0.0.1:22"], vulns=[])
    _write_run(cur, alive=["10.0.0.1", "10.0.0.2"], ports=["10.0.0.1:22"], vulns=[])

    diff = write_report_diff(cur, prev, markdown=True)
    assert (cur / "diff.json").exists()
    assert (cur / "diff.md").exists()
    assert "Hosts added" in (cur / "diff.md").read_text(encoding="utf-8")
    assert diff["hosts"]["added"] == ["10.0.0.2"]


def test_resolve_previous_run_dir_from_pointer(tmp_path: Path):
    output_base = tmp_path / "output"
    state_base = tmp_path / "state"
    run_dir = output_base / "runs" / "run-a"
    run_dir.mkdir(parents=True)
    state_base.mkdir(parents=True)
    (state_base / "latest_run.json").write_text(json.dumps({"run_id": "run-a"}), encoding="utf-8")

    found = resolve_previous_run_dir(
        output_base=output_base,
        state_base=state_base,
        per_run_output=True,
    )
    assert found == run_dir


def test_compute_report_diff_emits_normalized_events(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(
        prev,
        alive=["10.0.0.1", "10.0.0.2"],
        ports=["10.0.0.1:22"],
        vulns=[],
    )
    _write_run(
        cur,
        alive=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        ports=["10.0.0.1:22", "10.0.0.3:443/tcp"],
        vulns=[
            {
                "host": "10.0.0.3",
                "port": "443",
                "cve": "CVE-2021-2",
                "cvss": 7.5,
                "severity": "high",
                "script_id": "vulners",
            }
        ],
    )

    diff = compute_report_diff(cur, prev)
    kinds = [event["kind"] for event in diff["events"]]
    assert kinds.count("new_asset") == 1
    assert kinds.count("new_open_port") == 1
    assert kinds.count("new_cve") == 1
    assert diff["counts"]["events"] == 3
    assert diff["has_changes"] is True

    new_asset_event = next(e for e in diff["events"] if e["kind"] == "new_asset")
    assert new_asset_event["host"] == "10.0.0.3"

    new_port_event = next(e for e in diff["events"] if e["kind"] == "new_open_port")
    assert new_port_event == {
        "kind": "new_open_port",
        "host": "10.0.0.3",
        "port": "443",
        "protocol": "tcp",
    }

    new_cve_event = next(e for e in diff["events"] if e["kind"] == "new_cve")
    assert new_cve_event["cve"] == "CVE-2021-2"
    assert new_cve_event["host"] == "10.0.0.3"


def _write_tls_posture(run_dir: Path, findings: list[dict]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "tls_posture.json").write_text(
        json.dumps({"targets_considered": len(findings), "checked_count": len(findings), "findings": findings, "truncated": False, "skipped_reason": None}),
        encoding="utf-8",
    )


def test_compute_report_diff_emits_cert_expiring_event_on_first_occurrence(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(prev, alive=["10.0.0.1"], ports=["10.0.0.1:443"], vulns=[])
    _write_run(cur, alive=["10.0.0.1"], ports=["10.0.0.1:443"], vulns=[])
    _write_tls_posture(prev, [{"host": "10.0.0.1", "port": "443", "cert": {"not_after": "2026-08-01T00:00:00"}, "issues": []}])
    _write_tls_posture(
        cur,
        [
            {
                "host": "10.0.0.1",
                "port": "443",
                "cert": {"not_after": "2026-08-01T00:00:00"},
                "issues": [{"kind": "cert_expiring_soon", "severity": "medium", "days": 10}],
            }
        ],
    )

    diff = compute_report_diff(cur, prev)
    cert_events = [e for e in diff["events"] if e["kind"] == "cert_expiring"]
    assert len(cert_events) == 1
    assert cert_events[0]["issue_kind"] == "cert_expiring_soon"
    assert cert_events[0]["host"] == "10.0.0.1"
    assert cert_events[0]["days"] == 10
    assert cert_events[0]["not_after"] == "2026-08-01T00:00:00"
    assert diff["has_changes"] is True  # cert-only change, no host/port/vuln delta


def test_compute_report_diff_no_repeat_cert_expiring_event(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(prev, alive=["10.0.0.1"], ports=["10.0.0.1:443"], vulns=[])
    _write_run(cur, alive=["10.0.0.1"], ports=["10.0.0.1:443"], vulns=[])
    finding = {
        "host": "10.0.0.1",
        "port": "443",
        "cert": {"not_after": "2026-08-01T00:00:00"},
        "issues": [{"kind": "cert_expiring_soon", "severity": "medium", "days": 10}],
    }
    # Already flagged in the previous run too — not a *new* occurrence.
    _write_tls_posture(prev, [finding])
    _write_tls_posture(cur, [finding])

    diff = compute_report_diff(cur, prev)
    assert [e for e in diff["events"] if e["kind"] == "cert_expiring"] == []
    assert diff["has_changes"] is False


def test_render_diff_markdown_includes_events_section(tmp_path: Path):
    prev = tmp_path / "prev"
    cur = tmp_path / "cur"
    _write_run(prev, alive=["10.0.0.1"], ports=[], vulns=[])
    _write_run(cur, alive=["10.0.0.1", "10.0.0.2"], ports=[], vulns=[])

    diff = write_report_diff(cur, prev, markdown=True)
    markdown = (cur / "diff.md").read_text(encoding="utf-8")
    assert "## Events" in markdown
    assert "new_asset" in markdown
    assert diff["events"][0]["kind"] == "new_asset"


def test_resolve_previous_run_dir_compare_run_id(tmp_path: Path):
    output_base = tmp_path / "output"
    run_dir = output_base / "runs" / "explicit"
    run_dir.mkdir(parents=True)
    found = resolve_previous_run_dir(
        output_base=output_base,
        state_base=tmp_path / "state",
        compare_run_id="explicit",
        per_run_output=True,
    )
    assert found == run_dir
