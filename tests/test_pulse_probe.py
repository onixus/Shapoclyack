"""Unit tests for Pulse probe adapter (no live network / no pulse binary)."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.pulse_probe import (
    build_pulse_command,
    load_service_artifacts,
    parse_pulse_json,
    write_pulse_artifacts,
)
from scanner.pipeline.service_schema import ServiceRecord


SAMPLE_PULSE = {
    "open": [
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "port": 22,
            "protocol": "tcp",
            "open": True,
            "service": "ssh",
            "latency_ms": 3,
            "banner": "SSH-2.0-OpenSSH_8.9",
        },
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "port": 80,
            "protocol": "tcp",
            "open": True,
            "service": "http",
            "latency_ms": 1,
            "banner": None,
        },
    ],
    "os": [
        {
            "host": "10.0.0.5",
            "ip": "10.0.0.5",
            "family": "Linux",
            "detail": "Linux 3.x",
            "confidence": 72,
            "source": "nmap-os-db-low",
            "ttl": 64,
            "matches": [{"name": "Linux 3.x", "accuracy": 0.72, "family": "Linux"}],
        }
    ],
    "cves": [
        {
            "cve_id": "CVE-2023-0001",
            "ip": "10.0.0.5",
            "port": 22,
            "service": "ssh",
            "cvss": 7.5,
            "severity": "HIGH",
            "title": "CVE-2023-0001",
            "summary": "example",
            "match_reason": "banner",
            "source": "local",
            "refs": ["https://nvd.nist.gov/vuln/detail/CVE-2023-0001"],
        }
    ],
    "stats": {"total": 2, "open": 2, "closed": 0, "elapsed_ms": 10, "rate_pps": 200.0},
}


def test_parse_pulse_json_services_os_cves():
    services, os_recs, cves = parse_pulse_json(SAMPLE_PULSE)
    assert len(services) == 2
    assert services[0].port == 22
    assert services[0].banner.startswith("SSH")
    assert len(os_recs) == 1
    assert os_recs[0].source == "nmap-os-db-low"
    assert os_recs[0].confidence == 72
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-0001"


def test_write_and_load_artifacts(tmp_path: Path):
    services, os_recs, cves = parse_pulse_json(SAMPLE_PULSE)
    write_pulse_artifacts(tmp_path, services, os_recs, cves, raw=SAMPLE_PULSE)
    assert (tmp_path / "services.json").exists()
    assert (tmp_path / "os.json").exists()
    assert (tmp_path / "pulse_cves.json").exists()
    assert (tmp_path / "pulse" / "raw.json").exists()

    loaded = load_service_artifacts(tmp_path)
    assert loaded is not None
    findings, os_matches, vulns = loaded
    assert len(findings) == 2
    assert findings[0]["host"] == "10.0.0.5"
    assert findings[0]["service"] == "ssh"
    assert len(os_matches) == 1
    assert os_matches[0]["accuracy"] == "72"
    assert len(vulns) == 1
    assert vulns[0]["cve"] == "CVE-2023-0001"
    assert vulns[0]["severity"] == "high"


def test_load_missing_returns_none(tmp_path: Path):
    assert load_service_artifacts(tmp_path) is None


def test_build_pulse_command_flags():
    hosts = Path("/tmp/hosts.txt")
    cmd = build_pulse_command(
        bin_path="pulse",
        hosts_file=hosts,
        ports=[22, 80, 443],
        concurrency=100,
        rate=500,
        adaptive=True,
        host_parallel=4,
        timeout_ms=800,
        banner=True,
        os_detect=True,
        os_mode="auto",
        cve=True,
        cve_online=False,
        syn=False,
        checkpoint=Path("/tmp/x.ckpt"),
        max_hosts=1000,
    )
    assert cmd[0] == "pulse"
    assert "--targets-file" in cmd
    assert "-p" in cmd
    assert "22,80,443" in cmd
    assert "--adaptive" in cmd
    assert "--host-parallel" in cmd
    assert "-b" in cmd
    assert "--os" in cmd
    assert "--cve" in cmd
    assert "--checkpoint" in cmd
    assert "-f" in cmd and "json" in cmd


def test_service_record_roundtrip():
    s = ServiceRecord(ip="1.2.3.4", port=443, service="https", banner="x")
    d = s.model_dump(mode="json")
    assert d["schema_version"] == "octo.service.v1"
    again = ServiceRecord.model_validate(d)
    assert again.port == 443
