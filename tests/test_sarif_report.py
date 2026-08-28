"""Unit tests for OASIS SARIF v2.1.0 export."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.report import build_reports
from scanner.pipeline.sarif_report import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    _format_target_uri,
    _sarif_level,
    build_sarif_report,
)


def test_sarif_level_mapping():
    assert _sarif_level("critical") == "error"
    assert _sarif_level("high") == "error"
    assert _sarif_level("medium") == "warning"
    assert _sarif_level("low") == "note"
    assert _sarif_level("unknown") == "note"
    assert _sarif_level(None) == "note"


def test_format_target_uri():
    assert _format_target_uri("10.0.0.1", 443) == "https://10.0.0.1:443/"
    assert _format_target_uri("10.0.0.1", 80) == "http://10.0.0.1:80/"
    assert _format_target_uri("10.0.0.1", 22) == "tcp://10.0.0.1:22"
    assert _format_target_uri("example.com", None) == "host://example.com"


def test_build_sarif_report_structure(tmp_path: Path):
    vulns = [
        {
            "host": "192.168.1.10",
            "port": "8080",
            "cve": "CVE-2021-44228",
            "cvss": 10.0,
            "severity": "critical",
            "script_id": "nuclei:cve-2021-44228",
            "source": "nuclei",
            "cwe": ["CWE-20", "CWE-400"],
        },
        {
            "host": "192.168.1.10",
            "port": "443",
            "cve": None,
            "cvss": 5.0,
            "severity": "medium",
            "script_id": "tls_posture:cert_expired",
            "source": "tls_posture",
            "cwe": [],
        },
    ]

    doc = build_sarif_report(tmp_path, vulns, tool_version="1.2.3")
    assert doc["version"] == SARIF_VERSION
    assert doc["$schema"] == SARIF_SCHEMA_URI
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Shapoclyack"
    assert run["tool"]["driver"]["version"] == "1.2.3"

    rules = run["tool"]["driver"]["rules"]
    assert len(rules) == 2
    rule_ids = {r["id"] for r in rules}
    assert "CVE-2021-44228" in rule_ids
    assert "tls_posture:cert_expired" in rule_ids

    results = run["results"]
    assert len(results) == 2
    assert results[0]["ruleId"] == "CVE-2021-44228"
    assert results[0]["level"] == "error"
    assert "http://192.168.1.10:8080/" in results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    assert results[1]["ruleId"] == "tls_posture:cert_expired"
    assert results[1]["level"] == "warning"
    assert "https://192.168.1.10:443/" in results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]

    sarif_file = tmp_path / "sarif.json"
    assert sarif_file.is_file()
    saved = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert saved["version"] == SARIF_VERSION


def test_build_reports_emits_sarif_json(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    extra_vulns = [
        {
            "host": "10.0.0.5",
            "port": "80",
            "cve": "CVE-2023-1234",
            "cvss": 7.5,
            "severity": "high",
            "script_id": "nuclei:cve-2023-1234",
            "source": "nuclei",
        }
    ]

    build_reports(
        output_dir=tmp_path,
        total_targets=1,
        alive_hosts=["10.0.0.5"],
        open_ports=["10.0.0.5:80/tcp"],
        nmap_dir=nmap_dir,
        markdown_summary=True,
        html_summary=False,
        csv_export=False,
        json_export=True,
        sarif_export=True,
        cvss4_enabled=False,
        geoip_enabled=False,
        asn_enabled=False,
        extra_vulnerabilities=extra_vulns,
    )

    sarif_file = tmp_path / "sarif.json"
    assert sarif_file.is_file()
    data = json.loads(sarif_file.read_text(encoding="utf-8"))
    assert len(data["runs"][0]["results"]) == 1
    assert data["runs"][0]["results"][0]["ruleId"] == "CVE-2023-1234"
