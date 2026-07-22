from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_scan import (
    _candidate_endpoints,
    _to_finding,
    _to_vulnerability_row,
    run_nuclei_scan,
)


def _fake_which_present(name: str) -> str | None:
    return "/usr/local/bin/nuclei" if name == "nuclei" else None


def test_candidate_endpoints_dedupes_and_classifies_scheme():
    candidates = _candidate_endpoints(
        ["10.0.0.1:80/tcp", "10.0.0.1:443/tcp", "10.0.0.1:80/tcp", "10.0.0.2:22/tcp"],
        http_ports={80},
        https_ports={443},
    )
    assert candidates == [("10.0.0.1", 80, "http"), ("10.0.0.1", 443, "https")]


def test_to_finding_extracts_cve_and_severity():
    raw = {
        "template-id": "cve-2021-44228",
        "host": "10.0.0.1",
        "port": "8080",
        "matched-at": "http://10.0.0.1:8080/",
        "info": {
            "name": "Log4Shell",
            "severity": "Critical",
            "tags": ["cve", "cve2021", "rce"],
            "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
        },
    }
    finding = _to_finding(raw)
    assert finding["severity"] == "critical"
    assert finding["cve"] == ["CVE-2021-44228"]
    assert finding["cvss_score"] == 10.0


def test_to_vulnerability_row_none_without_cve():
    finding = _to_finding({"host": "10.0.0.1", "port": "80", "info": {"severity": "info"}})
    assert _to_vulnerability_row(finding) is None


def test_to_vulnerability_row_falls_back_to_severity_floor_without_cvss():
    finding = _to_finding(
        {
            "host": "10.0.0.1",
            "port": "80",
            "template-id": "some-cve-check",
            "info": {"severity": "high", "classification": {"cve-id": ["CVE-2020-1"]}},
        }
    )
    row = _to_vulnerability_row(finding)
    assert row == {
        "host": "10.0.0.1",
        "port": "80",
        "cve": "CVE-2020-1",
        "cvss": 7.5,
        "severity": "high",
        "script_id": "nuclei:some-cve-check",
        "source": "nuclei",
    }


def test_run_nuclei_scan_disabled(tmp_path: Path):
    config = NucleiConfig(enabled=False)
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei.disabled"
    assert json.loads((tmp_path / "nuclei.json").read_text(encoding="utf-8"))["skipped_reason"] == "nuclei.disabled"


def test_run_nuclei_scan_no_web_ports(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:22/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "no_web_ports"


def test_run_nuclei_scan_binary_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda name: None)
    config = NucleiConfig(enabled=True)
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei_binary_missing"


def test_run_nuclei_scan_templates_dir_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    config = NucleiConfig(enabled=True, templates_dir=str(tmp_path / "does-not-exist"))
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "templates_dir_missing"


def test_run_nuclei_scan_run_failure_is_fail_soft(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        raise TimeoutError("nuclei took too long")

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:80/tcp"], config, tmp_path)
    assert result["skipped_reason"] == "nuclei_run_failed"


def test_run_nuclei_scan_parses_jsonl_and_splits_cve_findings(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        jsonl_path = Path(command[command.index("-jsonl-export") + 1])
        rows = [
            {
                "template-id": "cve-2021-44228",
                "host": "10.0.0.1",
                "port": "8080",
                "info": {
                    "name": "Log4Shell",
                    "severity": "critical",
                    "tags": ["cve"],
                    "classification": {"cve-id": ["CVE-2021-44228"], "cvss-score": 10.0},
                },
            },
            {
                "template-id": "exposed-panel-generic",
                "host": "10.0.0.1",
                "port": "8080",
                "info": {"name": "Exposed Admin Panel", "severity": "info", "tags": ["panel"]},
            },
        ]
        jsonl_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir))
    result = run_nuclei_scan(["10.0.0.1:8080/tcp"], config, tmp_path)

    assert result["skipped_reason"] is None
    assert len(result["findings"]) == 2
    assert len(result["cve_findings"]) == 1
    cve_row = result["cve_findings"][0]
    assert cve_row["cve"] == "CVE-2021-44228"
    assert cve_row["cvss"] == 10.0
    assert cve_row["severity"] == "critical"
    assert cve_row["source"] == "nuclei"
    assert (tmp_path / "nuclei.json").exists()
    assert (tmp_path / "nuclei_findings.txt").exists()


def test_run_nuclei_scan_truncates_over_max_targets(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", _fake_which_present)
    templates_dir = tmp_path / "templates"
    templates_dir.mkdir()

    def fake_run_command(command, **kwargs):
        jsonl_path = Path(command[command.index("-jsonl-export") + 1])
        jsonl_path.write_text("", encoding="utf-8")
        return MagicMock()

    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", fake_run_command)
    open_ports = [f"10.0.0.{i}:80/tcp" for i in range(1, 6)]
    config = NucleiConfig(enabled=True, templates_dir=str(templates_dir), max_targets=2)
    result = run_nuclei_scan(open_ports, config, tmp_path)
    assert result["targets_considered"] == 5
    assert result["checked_count"] == 2
    assert result["truncated"] is True
