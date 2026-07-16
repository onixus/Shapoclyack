"""Tests for business PDF report generation."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.pdf_report import write_business_pdf


def _seed_run(tmp_path: Path) -> Path:
    (tmp_path / "summary.json").write_text(
        json.dumps(
            {
                "total_targets": 10,
                "alive_hosts": 2,
                "alive_hosts_with_names": 1,
                "open_host_port_pairs": 4,
                "nmap_open_services": 3,
                "os_detected_hosts": 1,
                "potential_vulnerabilities": 2,
                "vulnerable_hosts": 1,
                "vulnerabilities_by_severity": {
                    "critical": 1,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                },
                "top_services": [["ssh", 1], ["http", 2]],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.5",
                    "port": "22",
                    "script_id": "vulners",
                    "cve": "CVE-2016-10012",
                    "cvss": 9.8,
                    "severity": "critical",
                },
                {
                    "host": "10.0.0.5",
                    "port": "80",
                    "script_id": "http-csrf",
                    "cve": "CVE-2018-15473",
                    "cvss": 5.3,
                    "severity": "medium",
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "diff.json").write_text(
        json.dumps(
            {
                "counts": {
                    "hosts_added": 1,
                    "hosts_removed": 0,
                    "ports_added": 2,
                    "ports_removed": 0,
                    "vulns_added": 1,
                    "vulns_removed": 0,
                },
                "vulnerabilities": {
                    "added": [
                        {
                            "host": "10.0.0.5",
                            "port": "22",
                            "cve": "CVE-2016-10012",
                            "severity": "critical",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "run_meta.json").write_text(
        json.dumps({"run_id": "pdf-run-1", "mode": "balanced"}),
        encoding="utf-8",
    )
    return tmp_path


def test_write_business_pdf_creates_valid_pdf(tmp_path: Path):
    out_dir = _seed_run(tmp_path)
    path = write_business_pdf(
        out_dir,
        run_id="pdf-run-1",
        title="Octo-man Security Scan Report",
        org_name="Acme Security",
        max_vulnerabilities=10,
    )
    assert path == out_dir / "summary.pdf"
    assert path.exists()
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 500


def test_write_business_pdf_works_with_empty_artifacts(tmp_path: Path):
    path = write_business_pdf(tmp_path, run_id="empty")
    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")
