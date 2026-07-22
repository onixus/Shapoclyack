from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.report import (
    _build_vulnerabilities,
    _extract_cves,
    _parse_nmap_xml,
    _severity,
    build_reports,
)

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.x" accuracy="95"/>
      <osmatch name="Linux 4.x" accuracy="88"/>
    </os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
        <script id="vulners" output="cpe:/a:openbsd:openssh:7.4:&#10;    CVE-2018-15473    5.3    https://vulners.com/cve/CVE-2018-15473&#10;    CVE-2016-10012    9.8    https://vulners.com/cve/CVE-2016-10012"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="State: VULNERABLE"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def _setup(tmp_path: Path) -> Path:
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "10.0.0.5.xml").write_text(SAMPLE_XML, encoding="utf-8")
    return nmap_dir


def test_severity_thresholds():
    assert _severity(9.8) == "critical"
    assert _severity(7.5) == "high"
    assert _severity(5.0) == "medium"
    assert _severity(2.0) == "low"
    assert _severity(None) == "unknown"


def test_extract_cves_with_and_without_scores():
    output = "CVE-2016-10012 9.8 url\nplain mention CVE-2018-15473 elsewhere"
    cves = dict(_extract_cves(output))
    assert cves["CVE-2016-10012"] == 9.8
    assert cves["CVE-2018-15473"] is None or isinstance(cves["CVE-2018-15473"], float)


def test_parse_nmap_xml_extracts_services_os_and_scripts(tmp_path: Path):
    nmap_dir = _setup(tmp_path)
    services, os_matches, scripts = _parse_nmap_xml(nmap_dir)

    assert {s["port"] for s in services} == {"22", "445"}  # closed port excluded
    assert len(os_matches) == 2
    assert any(s["vulnerable"] for s in scripts)


def test_build_vulnerabilities_ranks_by_severity():
    findings = [
        {"host": "h", "port": "22", "script_id": "vulners", "output": "CVE-2016-10012 9.8 url\nCVE-2018-15473 5.3 url", "vulnerable": True},
        {"host": "h", "port": "445", "script_id": "smb-vuln", "output": "State: VULNERABLE", "vulnerable": True},
    ]
    vulns = _build_vulnerabilities(findings)
    assert vulns[0]["severity"] == "critical"
    assert vulns[0]["cve"] == "CVE-2016-10012"
    # VULNERABLE-without-CVE is still reported as unknown severity
    assert any(v["cve"] is None and v["severity"] == "unknown" for v in vulns)


def test_build_reports_writes_vuln_and_os_artifacts(tmp_path: Path):
    nmap_dir = _setup(tmp_path)
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    build_reports(
        output_dir=output_dir,
        total_targets=10,
        alive_hosts=["10.0.0.5"],
        open_ports=["10.0.0.5:22", "10.0.0.5:445"],
        nmap_dir=nmap_dir,
        markdown_summary=True,
        html_summary=True,
        csv_export=True,
        json_export=True,
    )

    summary = json.loads((output_dir / "summary.json").read_text(encoding="utf-8"))
    assert summary["os_detected_hosts"] == 1
    assert summary["vulnerabilities_by_severity"]["critical"] == 1
    assert summary["potential_vulnerabilities"] >= 2
    assert summary["vulnerable_hosts"] == 1

    vulns = json.loads((output_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert vulns[0]["severity"] == "critical"

    assert (output_dir / "vulnerabilities.csv").exists()
    alive = json.loads((output_dir / "alive_hosts.json").read_text(encoding="utf-8"))
    assert alive[0]["host"] == "10.0.0.5"
    # Best OS match by accuracy (95 > 88), matching summary's os_detected_hosts.
    assert alive[0]["os_name"] == "Linux 5.x"
    assert alive[0]["os_accuracy"] == 95

    md = (output_dir / "summary.md").read_text(encoding="utf-8")
    assert "Vulnerabilities" in md
    assert "CRITICAL" in md
