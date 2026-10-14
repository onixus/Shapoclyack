"""Offline fixtures exercise classification, canonical identity and tracker workflows."""
import json
import pytest
from pydantic import ValidationError
from scanner.pipeline.config_schema import NucleiConfig
from scanner.pipeline.nuclei_scan import _to_finding, _non_cve_row, nuclei_vulnerability_rows
from scanner.pipeline.production_evidence import combine, merge, scoped
from api.services.vulnerabilities import finding_key, observation_finding_key
from tests.conftest import requires_postgres


def fixture_row(template="exposed-config", severity="high", url="https://10.0.0.5/config"):
    finding = _to_finding({"host": "10.0.0.5", "port": "443", "matched-at": url,
        "template-id": template, "type": "http", "timestamp": "2026-10-01T00:00:00Z",
        "info": {"name": "Public configuration", "severity": severity, "tags": "misconfig,exposure"}})
    config = NucleiConfig(non_cve_rules={template: {"rule_id": "public-config-v1",
        "issue_type": "misconfiguration", "remediation": "Restrict access to the configuration object."}})
    return finding, _non_cve_row(finding, config)


def test_explicit_review_and_severity_are_both_required():
    finding, row = fixture_row()
    assert row["cve"] is None and row["cvss"] is None
    assert finding["classification"] == "actionable"
    assert finding["tags"] == ["misconfig", "exposure"]
    assert row["requires_confirmation"] is False
    assert _non_cve_row(finding, NucleiConfig()) is None
    assert finding["classification"] == "hypothesis"
    for severity in ["info", "unknown"]:
        finding, row = fixture_row(severity=severity)
        assert row is None and finding["classification"] == "inventory"
    with pytest.raises(ValidationError):
        NucleiConfig(non_cve_rules={"t": {"rule_id": "r", "remediation": " "}})


def test_resume_does_not_invent_historical_tasks():
    assert nuclei_vulnerability_rows({"findings": [fixture_row()[0]]}) == []
    row = fixture_row()[1]
    assert nuclei_vulnerability_rows({"actionable_findings": [row]}) == [row]


def test_precise_identity_separates_tenant_protocol_authority_object_and_keeps_rule_stable():
    row = fixture_row()[1]
    def key(entry=row, tenant="t", asset="a"):
        return observation_finding_key(tenant_id=tenant, asset_id=asset, entry=entry)
    assert key() != key(tenant="u") != key(asset="b")
    variants = [{**row, "matched_at": "https://10.0.0.5/other"},
        {**row, "http_authority": "another.example:443"},
        {**row, "matched_at": "", "protocol": "udp"},
        {**row, "affected_object": "database-a"}]
    for variant in variants:
        assert key() != key(variant)
        assert len(combine([row, variant])) == 2
    renamed = {**row, "template_id": "new-template-name", "script_id": "nuclei:new-template-name"}
    assert key() == key(renamed)
    assert len(combine([row, renamed])) == 1
    cve = {**row, "cve": "CVE-2024-0001"}
    assert key(cve) == finding_key(asset_id="a", cve=cve["cve"], script_id=cve["script_id"], port="443")


def test_evidence_history_replay_and_report_counters(tmp_path):
    from scanner.pipeline.report import build_reports
    row = fixture_row()[1]
    source = combine([row])[0]
    first = scoped(source["finding_evidence"], tenant_id="t", run_id="run-1")
    second = scoped(source["finding_evidence"], tenant_id="t", run_id="run-2")
    assert merge(first, first)["observation_count"] == 1
    assert merge(first, second)["observation_count"] == 2
    build_reports(tmp_path, 1, ["10.0.0.5"], [], tmp_path / "nmap", True, False, True, True,
        extra_vulnerabilities=[row], cvss4_enabled=False, geoip_enabled=False, asn_enabled=False)
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["cve_findings"] == 0 and summary["non_cve_findings"] == 1
    persisted = json.loads((tmp_path / "vulnerabilities.json").read_text())[0]
    assert persisted["cve"] is None and persisted["remediation"] == row["remediation"]
    import csv
    csv_row = next(csv.DictReader((tmp_path / "vulnerabilities.csv").open()))
    assert csv_row["cve"] == "" and csv_row["finding_type"] == "misconfiguration"
    assert csv_row["remediation"] == row["remediation"] and csv_row["finding_evidence"]
    markdown = (tmp_path / "summary.md").read_text()
    assert row["remediation"] in markdown and "misconfiguration" in markdown


@requires_postgres
def test_non_cve_uses_existing_owner_sla_history_regression_and_filters(tmp_path):
    from api.services import vulnerabilities as vulns, runs
    from api.db.engine import get_session
    from api.db import models
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    row = fixture_row()[1]
    settings, tenant = _seed(tmp_path, findings=combine([row]))
    with get_session(settings.postgres_url) as session:
        asset = session.query(models.Asset).filter_by(tenant_id=tenant).first()
        asset.owner_email = "owner@example.com"
        asset.business_unit = "security"
    first = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-1")
    assert first.created == 1
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-1")
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant,
        finding_type="misconfiguration", detector_source="nuclei")
    assert total == 1
    finding = items[0]
    assert finding["cve"] is None and finding["assignee"] == "owner@example.com"
    assert finding["owner_team"] == "security" and finding["sla_days"] == vulns.DEFAULT_SLA_DAYS["high"]
    assert finding["observation_count"] == 1 and finding["remediation"]
    assert "verification_target" not in json.dumps(finding)
    api = runs.get_vulnerabilities(settings, "run-1", tenant_id=tenant)[0]
    assert api.finding_type == "misconfiguration" and api.remediation
    vulns.transition(settings, tenant_id=tenant, vuln_id=finding["vuln_id"], to_state="CLOSED")
    _write_run(settings.output_dir, "run-2", _HOSTS, combine([row]))
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-2")
    assert stats.reopened == 1
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding["vuln_id"])
    assert current["finding_key"] == finding["finding_key"]
    assert current["observation_count"] == 2 and current["reopen_count"] == 1
    summary = vulns.summary(settings, tenant_id=tenant)
    assert (summary["cve_findings"], summary["non_cve_findings"]) == (0, 1)
    from datetime import UTC, datetime, timedelta
    vulns.request_exception(settings, tenant_id=tenant, vuln_id=finding["vuln_id"],
        until=datetime.now(UTC) + timedelta(days=30), reason="Vendor scheduled fix", actor="requester")
    accepted = vulns.approve_exception(settings, tenant_id=tenant, vuln_id=finding["vuln_id"], actor="approver")
    _write_run(settings.output_dir, "run-3", _HOSTS, combine([row]))
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-3")
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding["vuln_id"])
    assert current["exception_until"] == accepted["exception_until"]
    vulns.mark_false_positive(settings, tenant_id=tenant, vuln_id=finding["vuln_id"],
        reason="Fixture intentionally public", suppress_days=30, actor="reviewer")
    _write_run(settings.output_dir, "run-4", _HOSTS, combine([row]))
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-4")
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding["vuln_id"])
    assert current["state"] == "CLOSED" and current["fp_suppressed"] and stats.reopened == 0
    # Retrying an old publication must not erase current ownership or replay lifecycle actions.
    count = current["observation_count"]
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-1")
    current = vulns.get_vulnerability(settings, tenant_id=tenant, vuln_id=finding["vuln_id"])
    assert current["observation_count"] == count and current["last_seen_run_id"] == "run-4"


def test_real_raw_invocation_binding_preserves_virtual_host_isolation():
    config = NucleiConfig(non_cve_rules={"exposed-config": {"rule_id": "config-v1", "remediation": "Restrict access."}})
    raw = {"host": "10.0.0.5", "port": "443", "matched-at": "https://10.0.0.5/config",
        "template-id": "exposed-config", "type": "http", "info": {"severity": "high"}}
    rows = []
    for name in ["a.example", "b.example"]:
        bound = {**raw, "shapoclyack_input": {"schema": "octo.nuclei_input.v1", "ip": "10.0.0.5", "port": 443,
            "authority": name + ":443", "sni": name}}
        row = _non_cve_row(_to_finding(bound), config)
        assert row["http_authority"] == name + ":443" and row["sni"] == name
        rows.append(row)
    assert len(combine(rows)) == 2
    assert observation_finding_key(tenant_id="t", asset_id="a", entry=rows[0]) != observation_finding_key(tenant_id="t", asset_id="a", entry=rows[1])
    raw["shapoclyack_input"] = {"schema": "octo.nuclei_input.v1", "ip": "10.0.0.6", "port": 443,
        "authority": "a.example:443", "sni": "a.example"}
    assert _non_cve_row(_to_finding(raw), config) is None


def test_scanner_emits_only_actionable_rows_from_current_execution(tmp_path, monkeypatch):
    import subprocess
    from pathlib import Path
    from scanner.pipeline.nuclei_scan import run_nuclei_scan
    templates = tmp_path / "templates"
    templates.mkdir()
    raw = [{"host": "10.0.0.5", "port": "443", "matched-at": "https://10.0.0.5/config",
            "template-id": "exposed-config", "info": {"severity": "high"}},
           {"host": "10.0.0.5", "port": "443", "matched-at": "https://10.0.0.5/",
            "template-id": "tech-detect", "info": {"severity": "info"}}]
    def execute(command, **kwargs):
        Path(command[command.index("-jsonl-export") + 1]).write_text("\n".join(json.dumps(r) for r in raw))
        return subprocess.CompletedProcess(command, 0, "", "")
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.shutil.which", lambda _: "nuclei")
    monkeypatch.setattr("scanner.pipeline.nuclei_scan.run_command", execute)
    result = run_nuclei_scan(["10.0.0.5:443/tcp"], NucleiConfig(templates_dir=str(templates), network_templates=False,
        non_cve_rules={"exposed-config": {"rule_id": "config-v1", "remediation": "Restrict access."}}), tmp_path)
    assert [r["classification"] for r in result["findings"]] == ["actionable", "inventory"]
    assert len(nuclei_vulnerability_rows(result)) == 1
    assert nuclei_vulnerability_rows(result)[0]["cve"] is None


@pytest.mark.parametrize("source,script", [("pulse", "pulse:exposure"), ("nuclei", "nuclei:network-old")])
def test_legacy_report_display_classification_cannot_rename_backlog(tmp_path, source, script):
    from scanner.pipeline.report import build_reports
    from scanner.pipeline.report_diff import _vuln_key
    from scanner.pipeline.non_cve_policy import actionable
    legacy = {"host": "10.0.0.5", "port": "443", "protocol": "tcp", "source": source,
              "script_id": script, "cve": None, "severity": "high", "cvss": None}
    old_key = finding_key(asset_id="a", cve=None, script_id=script, port="443")
    build_reports(tmp_path, 1, ["10.0.0.5"], [], tmp_path / "nmap", False, False, False, True,
        extra_vulnerabilities=[legacy], cvss4_enabled=False, geoip_enabled=False, asn_enabled=False)
    exported = json.loads((tmp_path / "vulnerabilities.json").read_text())[0]
    assert exported["finding_type"] == "exposure" and not actionable(exported)
    assert observation_finding_key(tenant_id="t", asset_id="a", entry=exported) == old_key
    assert _vuln_key(exported) == _vuln_key(legacy)
    assert len(combine([legacy, {**exported, "affected_object": "one"}])) == 1


@requires_postgres
def test_legacy_non_cve_report_preserves_registered_identity_and_workflow(tmp_path):
    from api.services import vulnerabilities as vulns
    from tests.test_vuln_lifecycle import _seed, _write_run, _HOSTS
    from scanner.pipeline.report import build_reports
    legacy = {"host": "10.0.0.5", "port": "443", "protocol": "tcp", "source": "nuclei",
              "script_id": "nuclei:network-old", "cve": None, "severity": "high", "cvss": None}
    settings, tenant = _seed(tmp_path, findings=[legacy])
    vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-1")
    first = vulns.list_vulnerabilities(settings, tenant_id=tenant)[0][0]
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    build_reports(report_dir, 1, ["10.0.0.5"], [], report_dir / "nmap", False, False, False, True,
        extra_vulnerabilities=[legacy], cvss4_enabled=False, geoip_enabled=False, asn_enabled=False)
    exported = json.loads((report_dir / "vulnerabilities.json").read_text())
    _write_run(settings.output_dir, "run-2", _HOSTS, exported)
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant, run_id="run-2")
    items, total = vulns.list_vulnerabilities(settings, tenant_id=tenant)
    assert stats.created == 0 and total == 1
    assert items[0]["finding_key"] == first["finding_key"]
    assert items[0]["vuln_id"] == first["vuln_id"] and items[0]["due_at"] == first["due_at"]
