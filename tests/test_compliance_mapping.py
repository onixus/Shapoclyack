"""Compliance mapping (Sprint 4): signals, catalogues, posture and the API.

The assertions worth having here are the ones about what compliance software
gets wrong: a control that passes because there is no data, a score presented
as compliance with the whole standard, an accepted risk silently counted as a
failure, and a closed finding keeping a control red forever.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.services import vulnerabilities as vulns
from api.services.compliance import frameworks as catalog
from api.services.compliance import service as compliance
from api.services.compliance import signals as sig
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

_HOSTS = [{"host": "8.8.8.8", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "8.8.8.8", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8, "severity": "critical"},
    {
        "host": "8.8.8.8",
        "port": "23",
        "script_id": "telnet-encryption",
        "cvss": 7.5,
        "severity": "high",
    },
    {
        "host": "8.8.8.8",
        "port": "443",
        "script_id": "ssl-dh-params",
        "cvss": 5.0,
        "severity": "medium",
    },
    # An administrative port with no evidence about reachability. A public
    # address is not that evidence (#171), so this stays `unknown` and must not
    # fail the "reachable from an untrusted network" controls on its own.
    {
        "host": "8.8.8.8",
        "port": "22",
        "script_id": "ssh-hostkey",
        "cvss": 2.0,
        "severity": "low",
    },
]

# The same finding with the exposure observation the controls are written
# about. `network_exposure` on the entry is the explicit source in
# `resolve_network_exposure`.
_EXPOSED_ADMIN = {
    "host": "8.8.8.8",
    "port": "3389",
    "script_id": "rdp-enum-encryption",
    "cvss": 7.0,
    "severity": "high",
    "network_exposure": "external",
}


def _seed(tmp_path: Path, findings: list[dict] | None = None):
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = make_settings(tmp_path)
    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps(_FINDINGS if findings is None else findings), encoding="utf-8"
    )

    tenants_service.load_tenants(settings)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return settings, tenant_id


# ---------------------------------------------------------------- signals


def test_classifier_reads_the_finding_not_its_severity():
    raised = sig.classify_finding(
        {"cve": "CVE-2024-0001", "script_id": "ssl-dh-params", "port": "443", "in_kev": True},
        sla_reading="breached",
    )
    assert sig.UNPATCHED_CVE in raised
    assert sig.WEAK_CRYPTOGRAPHY in raised
    assert sig.KNOWN_EXPLOITED in raised
    assert sig.OVERDUE_REMEDIATION in raised
    # Nothing said the service was internet-facing, so nothing may claim it is.
    assert sig.INTERNET_EXPOSED not in raised


def test_a_finding_without_a_cve_is_not_an_unpatched_cve():
    assert sig.UNPATCHED_CVE not in sig.classify_finding({"cve": "", "title": "banner grab"})
    # "CVE-lookalike" strings from a scanner's own id space must not count.
    assert sig.UNPATCHED_CVE not in sig.classify_finding({"cve": "CVE-BAD"})


def test_asset_context_gaps_are_signals_of_their_own():
    raised = sig.classify_asset({"status": "stale", "owner_email": "", "environment": ""})
    assert raised == {sig.UNOWNED_ASSET, sig.UNCLASSIFIED_ASSET, sig.STALE_ASSET}
    assert not sig.classify_asset(
        {"status": "active", "owner_email": "a@b.c", "environment": "prod"}
    )


def test_every_catalogued_control_references_a_real_signal():
    for framework in catalog.FRAMEWORKS.values():
        for control in framework.controls:
            # Either form is a way to fail the control; a control with neither
            # is a documentation entry that can never be assessed.
            assert control.all_signals, f"{control.control_id} has no signals"
            assert set(control.all_signals) <= set(sig.SIGNALS)
            for group in control.combinations:
                assert len(group) >= 2, f"{control.control_id} has a one-signal combination"


# ---------------------------------------------------------------- posture


def test_controls_fail_on_their_own_evidence(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    posture = compliance.assess(settings, framework_id="iso-27001-2022", tenant_id=tenant_id)
    by_id = {entry["control_id"]: entry for entry in posture["controls"]}

    # A.8.8 is technical vulnerabilities: the critical CVE is its evidence.
    assert by_id["A.8.8"]["status"] == compliance.FAILED
    assert by_id["A.8.8"]["failing_count"] >= 1
    # A.8.24 is cryptography: the weak-DH finding, not the CVE.
    assert by_id["A.8.24"]["status"] == compliance.FAILED
    # A.8.21 is network services: telnet.
    assert by_id["A.8.21"]["status"] == compliance.FAILED


def test_severity_floor_keeps_a_control_off_informational_findings(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    posture = compliance.assess(settings, framework_id="pci-dss-4.0", tenant_id=tenant_id)
    by_id = {entry["control_id"]: entry for entry in posture["controls"]}
    # 6.3.3 is the patch window and only counts findings past their deadline;
    # a freshly registered finding is inside its SLA.
    assert by_id["6.3.3"]["status"] == compliance.PASSED


def test_score_is_over_assessed_controls_and_an_empty_estate_scores_nothing(
    tmp_path, monkeypatch
):
    from api.services import tenants as tenants_service

    # Built for the truncation, not the HTTP surface: this test needs a tenant
    # that exists and an estate that is genuinely empty.
    configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    posture = compliance.assess(
        settings, framework_id="cis-controls-v8", tenant_id=tenants_service.DEFAULT_TENANT_ID
    )
    # No findings, no assets, no inventory: nothing is assessed, and the score
    # is None rather than a 100% that means "we looked at nothing".
    assert posture["controls_assessed"] == 0
    assert posture["coverage_score"] is None
    assert all(
        entry["status"] == compliance.NOT_ASSESSED and entry["not_assessed_reason"]
        for entry in posture["controls"]
    )


def test_closed_findings_stop_failing_and_accepted_risk_is_separated(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    rows, _total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    telnet = next(row for row in rows if row["script_id"] == "telnet-encryption")

    vulns.set_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=telnet["vuln_id"],
        until=datetime.now(UTC) + timedelta(days=30),
        reason="compensating control",
        actor="admin",
    )
    posture = compliance.assess(settings, framework_id="iso-27001-2022", tenant_id=tenant_id)
    by_id = {entry["control_id"]: entry for entry in posture["controls"]}
    # Accepted risk is visible to an auditor but is not a failure: the
    # framework's own risk-acceptance process is what covers it.
    assert by_id["A.8.21"]["status"] == compliance.PASSED
    assert by_id["A.8.21"]["accepted_count"] == 1


# The controls written about "an admin service reachable from an untrusted
# network". Failing these on an internal SSH port is the difference between a
# compliance page an auditor reads and one every tenant learns to ignore.
_PAIRED_CONTROLS = (
    ("pci-dss-4.0", "1.2.1"),
    ("cis-controls-v8", "4.6"),
    ("cis-controls-v8", "12.2"),
    ("iso-27001-2022", "A.8.20"),
)


def test_an_admin_port_alone_does_not_fail_the_exposure_controls(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    for framework_id, control_id in _PAIRED_CONTROLS:
        posture = compliance.assess(settings, framework_id=framework_id, tenant_id=tenant_id)
        by_id = {entry["control_id"]: entry for entry in posture["controls"]}
        assert by_id[control_id]["status"] == compliance.PASSED, control_id

    # Telnet is still a failure of CIS 12.2 on its own: the conjunction covers
    # the admin-service half of that control, not the cleartext-protocol half.
    cis = compliance.assess(settings, framework_id="cis-controls-v8", tenant_id=tenant_id)
    assert {entry["control_id"]: entry for entry in cis["controls"]}["12.2"]["signals"] == [
        sig.INSECURE_PROTOCOL
    ]


def test_an_admin_port_observed_as_internet_facing_fails_them(tmp_path):
    settings, tenant_id = _seed(tmp_path, findings=[*_FINDINGS, _EXPOSED_ADMIN])
    for framework_id, control_id in _PAIRED_CONTROLS:
        posture = compliance.assess(settings, framework_id=framework_id, tenant_id=tenant_id)
        by_id = {entry["control_id"]: entry for entry in posture["controls"]}
        assert by_id[control_id]["status"] == compliance.FAILED, control_id


def test_external_scanning_control_is_not_a_restatement_of_the_internal_one(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    posture = compliance.assess(settings, framework_id="pci-dss-4.0", tenant_id=tenant_id)
    by_id = {entry["control_id"]: entry for entry in posture["controls"]}
    # A critical CVE with no exposure observation fails 11.3.1 (internal scans)
    # and says nothing about 11.3.2 (external ones).
    assert by_id["11.3.1"]["status"] == compliance.FAILED
    assert by_id["11.3.2"]["status"] == compliance.PASSED


def test_a_tenant_whose_findings_are_all_closed_is_still_assessed(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    rows, _total = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    for row in rows:
        vulns.transition(
            settings,
            tenant_id=tenant_id,
            vuln_id=row["vuln_id"],
            to_state="CLOSED",
            actor="operator",
        )

    posture = compliance.assess(settings, framework_id="iso-27001-2022", tenant_id=tenant_id)
    by_id = {entry["control_id"]: entry for entry in posture["controls"]}
    # Assessed and passing — not "not assessed". The estate was looked at and
    # the findings were fixed, which is the opposite of no data.
    assert by_id["A.8.8"]["status"] == compliance.PASSED
    assert posture["open_findings"] == 0


def test_control_evidence_lists_everything_not_just_the_sample(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    detail = compliance.control_evidence(
        settings, framework_id="iso-27001-2022", control_id="A.8.8", tenant_id=tenant_id
    )
    assert detail["framework_id"] == "iso-27001-2022"
    assert detail["evidence"]
    assert all(item["kind"] in {"finding", "asset", "software"} for item in detail["evidence"])
    assert compliance.control_evidence(
        settings, framework_id="iso-27001-2022", control_id="A.9.9", tenant_id=tenant_id
    ) is None


# -------------------------------------------------------------------- API


def test_api_lists_frameworks_and_returns_posture(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")

    frameworks = client.get("/api/compliance/frameworks", headers=viewer)
    assert frameworks.status_code == 200
    ids = {entry["framework_id"] for entry in frameworks.json()}
    assert ids == {"pci-dss-4.0", "cis-controls-v8", "iso-27001-2022"}
    # The scope note is the anti-overclaim guard; it must reach the client.
    assert all(entry["scope_note"] for entry in frameworks.json())

    posture = client.get("/api/compliance/pci-dss-4.0", headers=viewer)
    assert posture.status_code == 200
    body = posture.json()
    assert body["controls"]
    assert body["controls_total"] == len(body["controls"])

    assert client.get("/api/compliance/nist-800-53", headers=viewer).status_code == 404


def test_api_control_detail_and_auth(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    viewer = auth_headers(client, "viewer")

    detail = client.get("/api/compliance/iso-27001-2022/controls/A.8.8", headers=viewer)
    assert detail.status_code == 200
    assert detail.json()["control_id"] == "A.8.8"

    assert client.get("/api/compliance/iso-27001-2022/controls/A.0.0", headers=viewer).status_code == 404
    assert client.get("/api/compliance/pci-dss-4.0").status_code == 401
