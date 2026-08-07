"""Unit tests for Pulse probe adapter (no live network / no pulse binary)."""

from __future__ import annotations

from pathlib import Path

from scanner.pipeline.pulse_probe import (
    build_pulse_command,
    load_service_artifacts,
    parse_pulse_json,
    write_pulse_artifacts,
)
from scanner.pipeline.service_schema import (
    ServiceRecord,
    cves_to_extra_vulnerabilities,
    finding_key,
)


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


# Pulse's full finding taxonomy (pulse.scan.v2): a confirmed version match, an
# unverified NVD keyword hit, and a CVE-less exposure observation.
SAMPLE_FINDINGS = {
    "meta": {"scanner": "pulse", "schema": "pulse.scan.v2", "ruleset": "2026.07.29-h1"},
    "open": [],
    "findings": [
        {
            "cve_id": "CVE-2021-44228",
            "ip": "10.0.0.5",
            "port": 8080,
            "service": "http",
            "cvss": 10.0,
            "severity": "critical",
            "title": "Log4Shell",
            "finding_class": "version_cve",
            "confidence": 90,
            "requires_confirmation": False,
            "evidence": "Server: Apache/2.4 log4j/2.14",
            "ruleset_version": "2026.07.29-h1",
            "epss": 0.97,
            "in_kev": True,
        },
        {
            "cve_id": "CVE-2019-0708",
            "ip": "10.0.0.5",
            "port": 3389,
            "service": "rdp",
            "cvss": 9.8,
            "severity": "critical",
            "title": "BlueKeep",
            "finding_class": "keyword_cve",
            "confidence": 40,
            "requires_confirmation": True,
        },
        {
            "cve_id": "",
            "ip": "10.0.0.5",
            "port": 445,
            "service": "smb",
            "cvss": 5.0,
            "severity": "medium",
            "title": "EternalBlue (SMBv1 RCE)",
            "summary": "SMBv1 remote code execution.",
            "finding_class": "exposure",
            "confidence": 45,
            "requires_confirmation": True,
        },
    ],
    "stats": {},
}


def test_exposure_findings_survive_parsing():
    """CVE-less classes used to be dropped outright, losing every
    reachable-service observation Pulse makes."""
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    assert [c.finding_class for c in cves] == ["version_cve", "keyword_cve", "exposure"]

    exposure = cves[2]
    assert exposure.cve_id == ""
    assert exposure.requires_confirmation is True
    assert exposure.confidence == 45


def test_hypothesis_metadata_and_enrichment_reach_the_report_shape():
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    rows = cves_to_extra_vulnerabilities(cves)

    confirmed = rows[0]
    assert confirmed["cve"] == "CVE-2021-44228"
    assert confirmed["epss"] == 0.97
    assert confirmed["in_kev"] is True
    assert confirmed["requires_confirmation"] is False
    assert confirmed["evidence"].startswith("Server:")

    unverified = rows[1]
    assert unverified["finding_class"] == "keyword_cve"
    assert unverified["confidence"] == 40
    assert unverified["requires_confirmation"] is True

    # A CVE-less finding keeps an empty `cve` and is identified by a synthetic
    # script_id, so the report dedupe and ClickHouse key stay distinct per
    # port/title instead of collapsing every exposure on a host into one row.
    exposure = rows[2]
    assert exposure["cve"] == ""
    assert exposure["script_id"] == "pulse:exposure:445:eternalblue-smbv1-rce"
    assert exposure["severity"] == "medium"


def test_finding_key_is_stable_and_distinct_per_port():
    _, _, cves = parse_pulse_json(SAMPLE_FINDINGS)
    exposure = cves[2]
    assert finding_key(exposure) == finding_key(exposure.model_copy())
    other_port = exposure.model_copy(update={"port": 139})
    assert finding_key(other_port) != finding_key(exposure)
    # A finding with a real CVE keys on the CVE itself.
    assert finding_key(cves[0]) == "CVE-2021-44228"


def test_rows_without_cve_or_class_are_still_skipped():
    _, _, cves = parse_pulse_json({"findings": [{"ip": "10.0.0.5", "port": 22}]})
    assert cves == []


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
    assert vulns[0]["source"] == "pulse"
    assert vulns[0]["script_id"].startswith("pulse:")


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


def test_run_pulse_probe_targets_hostname_for_sni(tmp_path: Path, monkeypatch):
    """The chunk targets file carries hostnames where known.

    Pulse connecting to a bare IP sends no SNI, so hosts serving multiple
    certificates reject the handshake — no banner, no product, no version, and
    therefore no CVE can ever match. Pulse accepts domains as targets and
    reports both `host` and `ip` per row, so results stay IP-keyed.
    """
    from scanner.pipeline.pulse_probe import run_pulse_probe

    captured: list[list[str]] = []

    class _Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run_command(command, **kwargs):
        captured.append(command)
        return _Completed()

    monkeypatch.setattr("scanner.pipeline.pulse_probe.run_command", fake_run_command)
    monkeypatch.setattr(
        "scanner.pipeline.pulse_probe.resolve_pulse_bin", lambda _: "/usr/local/bin/pulse"
    )

    run_pulse_probe(
        ["10.0.0.1:443/tcp", "10.0.0.2:443/tcp"],
        output_dir=tmp_path,
        hostnames_map={
            "10.0.0.1": {"primary": "web.example"},
            "10.0.0.2": {},
        },
    )

    hosts_file = tmp_path / "pulse" / "chunk_0000.hosts.txt"
    # write_lines sorts and dedupes, so compare as a set.
    targets = set(hosts_file.read_text(encoding="utf-8").split())
    assert targets == {"web.example", "10.0.0.2"}
    assert "10.0.0.1" not in targets, "named host must be probed by name, not IP"
    assert captured, "pulse was never invoked"
