"""A run directory recorded before the Nmap stage was removed is still readable (#548).

``tests/fixtures/legacy_nmap_run/`` holds only what the old stage left
(``nmap/tcp/*.xml``). Nothing writes that directory any more, but the platform
keeps past runs, so every reader of it has to keep giving the answers it gave:
the report, the TLS posture stage, the evidence sidecar and the verification
coverage rules. Pinned together here, from one directory, so that "the readers
agree on what an old run says" is one assertion and not four files' worth of
separately-built XML.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from api.services import verification_coverage as coverage
from scanner.pipeline import evidence_artifacts as ea
from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.legacy_nmap import parse_nmap_xml
from scanner.pipeline.report import build_reports
from scanner.pipeline.tls_posture import check_tls_posture

FIXTURE = Path(__file__).parent / "fixtures" / "legacy_nmap_run"
HOST = "10.0.0.5"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    """A private copy: the readers write next to what they read."""
    target = tmp_path / "run"
    shutil.copytree(FIXTURE, target)
    return target


def test_the_parser_reads_services_os_and_scripts(run_dir):
    services, os_matches, scripts = parse_nmap_xml(run_dir / "nmap")

    assert {(s["port"], s["protocol"], s["service"]) for s in services} == {
        ("22", "tcp", "ssh"),
        ("443", "tcp", "https"),
        ("445", "tcp", "microsoft-ds"),
    }  # the closed port is not a service
    ssh = next(s for s in services if s["port"] == "22")
    assert (ssh["product"], ssh["version"], ssh["cpe"]) == (
        "OpenSSH",
        "8.2p1 Ubuntu 4ubuntu0.5",
        ["cpe:/a:openbsd:openssh:8.2p1"],
    )
    assert ssh["extrainfo"] == "Ubuntu Linux; protocol 2.0"
    assert [m["name"] for m in os_matches] == ["Linux 5.4 - 5.15", "Linux 4.15"]
    assert {(s["port"], s["script_id"], s["vulnerable"]) for s in scripts} == {
        ("22", "vulners", True),
        ("443", "ssl-cert", False),
        ("445", "smb-vuln-ms17-010", True),
    }
    assert all(s["protocol"] == "tcp" for s in scripts)


def test_the_report_of_an_old_run_keeps_nmap_services_and_nse_findings(run_dir):
    out = run_dir / "reports"
    out.mkdir()
    build_reports(
        output_dir=out,
        total_targets=1,
        alive_hosts=[HOST],
        open_ports=[f"{HOST}:22", f"{HOST}:443", f"{HOST}:445"],
        nmap_dir=run_dir / "nmap",
        markdown_summary=True,
        html_summary=False,
        csv_export=True,
        json_export=True,
        cvss4_enabled=False,
        geoip_enabled=False,
        asn_enabled=False,
        report_primary=False,
    )

    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert summary["nmap_open_services"] == 3
    assert summary["os_detected_hosts"] == 1
    vulns = json.loads((out / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert {(v["port"], v["cve"], v["source"], v["script_id"]) for v in vulns} == {
        ("22", "CVE-2016-10012", "nmap-nse", "vulners"),
        ("22", "CVE-2018-15473", "nmap-nse", "vulners"),
        ("445", None, "nmap-nse", "smb-vuln-ms17-010"),
    }
    assert vulns[0]["cve"] == "CVE-2016-10012" and vulns[0]["severity"] == "critical"
    alive = json.loads((out / "alive_hosts.json").read_text(encoding="utf-8"))
    assert (alive[0]["os_name"], alive[0]["os_accuracy"]) == ("Linux 5.4 - 5.15", 95)


def test_the_tls_posture_stage_still_grades_the_certificate_of_an_old_run(run_dir):
    from datetime import datetime, timezone

    config = TlsPostureConfig(enabled=True, probe_fallback=False)
    result = check_tls_posture(
        run_dir / "nmap", config, run_dir, now=datetime(2026, 7, 22, tzinfo=timezone.utc)
    )

    assert result["source"] == "nmap-nse"
    assert result["checked_count"] == 1
    finding = result["findings"][0]
    assert (finding["host"], finding["port"], finding["source"]) == (HOST, "443", "nmap-nse")
    assert {"cert_expired", "self_signed"} <= {issue["kind"] for issue in finding["issues"]}


def test_the_evidence_sidecar_of_an_old_run_lists_the_nse_reports(run_dir):
    result = ea.write_evidence_artifact(run_dir, tenant_id="tenant", run_id="run")

    rows = [obs for finding in result["findings"] for obs in finding["observations"]]
    assert {r["source"] for r in rows} == {"nmap-nse"}
    assert {(r["rule_id"], r["cve"]) for r in rows} == {
        ("vulners", "CVE-2016-10012"),
        ("vulners", "CVE-2018-15473"),
        ("smb-vuln-ms17-010", None),
    }
    assert all(r["engine_version"] == "7.95" for r in rows)
    assert {d["code"] for d in result["diagnostics"] if d["artifact"].startswith("nmap/")} == {"read"}


def test_verification_coverage_still_counts_a_named_nse_script_as_a_look(run_dir):
    runs = coverage.RunCoverage(run_dir)

    def gaps(script: str, port: str):
        entry = {"detector": coverage.NMAP_NSE, "ref": script, "host": HOST, "port": port, "protocol": "tcp"}
        return runs.gaps([entry], port=port, asset_hosts={HOST})

    assert gaps("vulners", "22") == []
    assert gaps("ssl-cert", "443") == []
    # A script the run did not name is not a look, and neither is a closed port.
    assert [g["reason"] for g in gaps("http-vuln-cve2017-5638", "443")] != []
    assert [g["reason"] for g in gaps("vulners", "8080")] != []
