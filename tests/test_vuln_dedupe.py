"""Phase 4.2: vulnerability merge/dedupe across Pulse + Nuclei + NSE."""

from __future__ import annotations

from scanner.pipeline.report import _dedupe_vulnerabilities
from scanner.pipeline.service_schema import CveRecord, cves_to_extra_vulnerabilities


def test_dedupe_keeps_first_host_port_cve():
    rows = [
        {"host": "10.0.0.1", "port": "22", "cve": "CVE-2023-0001", "source": "pulse", "cvss": 7.5, "severity": "high"},
        {"host": "10.0.0.1", "port": "22", "cve": "cve-2023-0001", "source": "nuclei", "cvss": 9.0, "severity": "critical"},
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "nuclei", "cvss": 5.0, "severity": "medium"},
    ]
    out = _dedupe_vulnerabilities(rows)
    assert len(out) == 2
    assert out[0]["source"] == "pulse"
    assert out[1]["port"] == "443"


def test_dedupe_keeps_the_dropped_rows_detectors():
    """One finding, but both stages looked: a verification has to re-check
    both (#451), so the kept row names the other one."""
    rows = [
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "pulse", "script_id": "pulse:local"},
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "nuclei", "script_id": "nuclei:CVE-2023-0001"},
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "nuclei", "script_id": "nuclei:CVE-2023-0001"},
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "pulse", "script_id": "pulse:local"},
        {"host": "10.0.0.1", "port": "80", "cve": "CVE-2023-0002", "source": "pulse", "script_id": "pulse:local"},
    ]
    out = _dedupe_vulnerabilities(rows)
    assert [row["port"] for row in out] == ["443", "80"]
    assert out[0]["also_detected_by"] == [{"source": "nuclei", "script_id": "nuclei:CVE-2023-0001"}]
    assert "also_detected_by" not in out[1]


def test_dedupe_non_cve_uses_script_id():
    rows = [
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "http-vuln-x", "severity": "unknown"},
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "http-vuln-x", "severity": "unknown"},
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "other", "severity": "unknown"},
    ]
    assert len(_dedupe_vulnerabilities(rows)) == 2


def test_pulse_cve_source_tag():
    rows = cves_to_extra_vulnerabilities(
        [
            CveRecord(
                cve_id="CVE-2024-1",
                ip="1.2.3.4",
                port=22,
                service="ssh",
                cvss=8.0,
                severity="HIGH",
                title="t",
                summary="s",
                match_reason="banner",
                source="local",
            )
        ]
    )
    assert rows[0]["source"] == "pulse"
    assert rows[0]["script_id"] == "pulse:local"


def test_default_nuclei_enabled():
    from pathlib import Path

    import yaml

    from scanner.pipeline.config_schema import NucleiConfig, load_config

    assert NucleiConfig().enabled is True
    cfg = load_config(yaml.safe_load(Path("scanner/config/default.yaml").read_text(encoding="utf-8")))
    assert cfg.nuclei.enabled is True
    assert cfg.service_probe.backend == "pulse"
    assert cfg.service_probe.pulse.cve is True


def test_nse_rows_keep_the_protocol_nmap_saw_them_on(tmp_path):
    """A UDP finding must never be judged by a TCP re-check (#451): the row
    says which one it was."""
    from scanner.pipeline.report import _build_vulnerabilities, _parse_nmap_xml

    nmap = tmp_path / "nmap"
    nmap.mkdir()
    (nmap / "udp_10.0.0.1.xml").write_text(
        '<?xml version="1.0"?><nmaprun args="nmap -sU --script vulners -p 123 10.0.0.1">'
        '<host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
        '<port protocol="udp" portid="123"><state state="open"/>'
        '<script id="vulners" output="CVE-2023-0001 7.5"/></port>'
        '<port protocol="tcp" portid="443"><state state="open"/>'
        '<script id="vulners" output="CVE-2023-0002 9.8"/></port>'
        "</ports></host></nmaprun>",
        encoding="utf-8",
    )
    _services, _os, scripts = _parse_nmap_xml(nmap)
    rows = {row["cve"]: row for row in _build_vulnerabilities(scripts)}
    assert rows["CVE-2023-0001"]["protocol"] == "udp"
    assert rows["CVE-2023-0002"]["protocol"] == "tcp"
