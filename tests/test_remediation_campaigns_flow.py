"""The campaign workflow against the real registration, lifecycle and
verification paths (#579 acceptance scenario).

Nothing here fakes a verdict: findings come from ``register_findings_from_run``,
verification goes through ``trigger_verification`` and is judged by the same
run ingest that closes findings in production, and a recurrence is a later run
that reports a closed finding again.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import assets as assets_service
from api.services import remediation_campaigns as campaigns
from api.services import tenants as tenants_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import approve_scan_scope, requires_postgres
from tests.test_vuln_lifecycle import _settings, _write_run

pytestmark = requires_postgres

HOSTS = [
    {"host": "10.0.0.5", "hostname": "web5.example.com"},
    {"host": "10.0.0.6", "hostname": "web6.example.com"},
    {"host": "10.0.0.7", "hostname": "web7.example.com"},
]
SHARED = {"port": "80", "cve": "CVE-2024-0001", "severity": "high"}
SAME_FIX = {"port": "443", "cve": "CVE-2024-0002", "severity": "medium"}
PANEL = {
    "host": "10.0.0.5", "port": "8080", "script_id": "nuclei:exposed-panel", "source": "nuclei",
    "template_id": "exposed-panel", "finding_type": "exposure", "severity": "medium",
    "title": "Exposed admin panel",
}
FINDINGS = [
    {"host": "10.0.0.5", **SHARED},
    {"host": "10.0.0.6", **SHARED},
    {"host": "10.0.0.7", **SHARED},
    {"host": "10.0.0.5", **SAME_FIX},
    {"host": "10.0.0.6", **SAME_FIX},
    PANEL,
]
KEYS = ["cve:CVE-2024-0001", "cve:CVE-2024-0002", "tpl:nuclei:exposed-panel"]


@pytest.fixture
def fleet(tmp_path):
    settings = _settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    approve_scan_scope(settings)
    _write_run(settings.output_dir, "run-1", HOSTS, FINDINGS)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return settings, tenant_id


def _finding(settings, tenant_id, cve=None, host_port=None, template=None):
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, limit=100)
    for item in items:
        if cve and item["cve"] != cve:
            continue
        if template and item.get("template_id") != template:
            continue
        if host_port and item["port"] != host_port[1]:
            continue
        if host_port:
            asset = item["asset_id"]
            from sqlalchemy import select

            with get_session(settings.postgres_url) as session:
                ip = session.execute(
                    select(models.AssetIdentifier.identifier_value).where(
                        models.AssetIdentifier.asset_id == asset,
                        models.AssetIdentifier.identifier_type == "ip",
                    )
                ).scalar_one_or_none()
            if ip != host_port[0]:
                continue
        return item
    raise AssertionError(f"no finding for {cve} {host_port} {template}")


def _to_fixing(settings, tenant_id, vuln_id):
    for state in (vuln_states.ACKNOWLEDGED, vuln_states.PLANNED, vuln_states.FIXING):
        vulns.transition(settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=state, actor="alice")


def _verification_run(settings, tenant_id, vuln_id, run_id, *, alive, findings, pulse_ports=(80, 443, 8080)):
    """Give the finding's own verification job a finished run with this content."""
    job_id = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)["verification_job_id"]
    assert job_id, "the finding was not dispatched for verification"
    _write_run(settings.output_dir, run_id, [{"host": h} for h in alive], findings)
    pulse = settings.output_dir / "runs" / run_id / "pulse"
    pulse.mkdir(parents=True, exist_ok=True)
    (pulse / "raw.json").write_text(
        json.dumps(
            {
                "adapter": {"cve": True},
                "completion": {
                    "schema": "octo.pulse_completion.v1",
                    "hosts": {h: {"ports": sorted(pulse_ports), "returncode": 0} for h in alive},
                },
            }
        ),
        encoding="utf-8",
    )
    with get_session(settings.postgres_url) as session:
        job = session.get(models.Job, job_id)
        job.run_id = run_id
        job.status = "succeeded"
        job.finished_at = datetime.now(UTC).replace(tzinfo=None)
    return vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)


def _set_job_status(settings, tenant_id, vuln_id, status):
    job_id = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=vuln_id)["verification_job_id"]
    with get_session(settings.postgres_url) as session:
        session.get(models.Job, job_id).status = status


def _categories(settings, tenant_id, cid):
    return campaigns.get_campaign(settings, tenant_id=tenant_id, campaign_id=cid)["progress"]["categories"]


def test_shared_cve_same_fix_and_non_cve_through_partial_fix_unreachable_asset_and_recurrence(fleet):
    settings, tenant_id = fleet
    campaign = campaigns.create_campaign(
        settings, tenant_id=tenant_id, actor="alice", audit=None, name="openssl rollout",
        description="upgrade openssl on the web tier and close the admin panel",
        selection={"problem_keys": KEYS},
    )
    cid = campaign["campaign_id"]
    assert campaign["snapshot_size"] == 6
    assert campaign["progress"]["categories"]["open"] == 6
    assert campaign["progress"]["assets"] == 3

    a5 = _finding(settings, tenant_id, cve="CVE-2024-0001", host_port=("10.0.0.5", "80"))
    a6 = _finding(settings, tenant_id, cve="CVE-2024-0001", host_port=("10.0.0.6", "80"))
    a7 = _finding(settings, tenant_id, cve="CVE-2024-0001", host_port=("10.0.0.7", "80"))
    b5 = _finding(settings, tenant_id, cve="CVE-2024-0002", host_port=("10.0.0.5", "443"))
    b6 = _finding(settings, tenant_id, cve="CVE-2024-0002", host_port=("10.0.0.6", "443"))
    panel = _finding(settings, tenant_id, template="exposed-panel")
    for item in (a5, a6, a7, b5, b6, panel):
        _to_fixing(settings, tenant_id, item["vuln_id"])
    assert _categories(settings, tenant_id, cid)["fixing"] == 6

    # Verification for five of them; the dispatch for the sixth is refused
    # (scanning disabled), which must not undo the five that went out.
    batch = [a5, a6, b5, b6, panel]
    sent = campaigns.verify_members(
        settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None,
        vuln_ids=[i["vuln_id"] for i in batch],
    )
    assert sent["summary"] == {"dispatched": 5}
    settings.allow_scan_start = False
    refused = campaigns.verify_members(
        settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None,
        vuln_ids=[a7["vuln_id"]],
    )
    settings.allow_scan_start = True
    assert refused["results"][0]["outcome"] == "failed"
    assert "disabled" in refused["results"][0]["detail"]
    categories = _categories(settings, tenant_id, cid)
    assert categories["awaiting_verification"] == 5 and categories["unavailable"] == 1

    # Verdicts, judged by the production ingest.
    ok = _verification_run(settings, tenant_id, a5["vuln_id"], "v1", alive=["10.0.0.5"], findings=[])
    assert ok.verification_passed == 1
    still = _verification_run(
        settings, tenant_id, a6["vuln_id"], "v2", alive=["10.0.0.6"],
        findings=[{"host": "10.0.0.6", **SHARED}],
    )
    assert still.verification_passed == 0
    _verification_run(settings, tenant_id, b5["vuln_id"], "v3", alive=["10.0.0.5"], findings=[])
    # The panel was found by a nuclei template; this run's Pulse evidence cannot
    # show that template re-ran, so it is inconclusive and is never closed.
    _verification_run(settings, tenant_id, panel["vuln_id"], "v4", alive=["10.0.0.5"], findings=[])

    progress = campaigns.get_campaign(settings, tenant_id=tenant_id, campaign_id=cid)["progress"]
    assert progress["categories"] == {
        "open": 0,
        "fixing": 1,                 # a6: still observed, back to work
        "awaiting_verification": 1,  # b6: dispatched, no verdict yet
        "verified": 2,               # a5, b5: a run that looked found nothing
        "accepted_risk": 0,
        "false_positive": 0,
        "closed_unverified": 0,
        "unavailable": 2,            # a7 refused dispatch; panel inconclusive
    }
    assert progress["total"] == 6 == sum(progress["categories"].values())
    by_id = {m["vuln_id"]: m for m in campaigns.list_members(
        settings, tenant_id=tenant_id, campaign_id=cid, limit=50)[0]}
    assert by_id[a7["vuln_id"]]["last_verify"]["outcome"] == "failed"
    assert by_id[panel["vuln_id"]]["verification"]["kind"] == "verification_inconclusive"
    assert by_id[panel["vuln_id"]]["verification"]["gaps"]  # what was not covered is shown
    assert by_id[a6["vuln_id"]]["verification"]["kind"] == "verification_failed"
    assert by_id[a5["vuln_id"]]["machine_verified"] is True

    # Competing ticket sync cannot close the finding whose verdict is pending.
    vulns.set_ticket(settings, tenant_id=tenant_id, vuln_id=b6["vuln_id"], system="jira",
                     key="SEC-6", url=None, actor="alice", verify_repository=False)
    _set_job_status(settings, tenant_id, b6["vuln_id"], "running")
    vulns.apply_ticket_status(settings, tenant_id=tenant_id, vuln_id=b6["vuln_id"],
                              suggested_state="CLOSED", raw_status="Done")
    held = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=b6["vuln_id"])
    assert held["state"] == vuln_states.VERIFYING and held["machine_verified"] is False
    events, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=b6["vuln_id"])
    synced = next(e for e in events if e["kind"] == "ticket_synced")
    assert synced["detail"]["applied"] is False and synced["detail"]["held_for_verification"] is True
    assert campaigns.get_campaign(settings, tenant_id=tenant_id, campaign_id=cid)["progress"]["tickets"] == {
        "linked_findings": 1, "distinct_tickets": 1}

    # Rediscovery: the verified b5 is observed again by a later routine scan.
    _write_run(settings.output_dir, "rescan", [{"host": "10.0.0.5"}], [{"host": "10.0.0.5", **SAME_FIX}])
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="rescan")
    assert stats.reopened == 1
    back = campaigns.get_campaign(settings, tenant_id=tenant_id, campaign_id=cid)
    assert back["progress"]["categories"]["verified"] == 1
    assert back["progress"]["categories"]["open"] == 1
    assert back["progress"]["recurred"] == 1
    assert back["status"] == "active"
    assert sum(back["progress"]["categories"].values()) == back["progress"]["total"] == 6
    again = next(m for m in campaigns.list_members(
        settings, tenant_id=tenant_id, campaign_id=cid, limit=50)[0] if m["vuln_id"] == b5["vuln_id"])
    assert again["recurred"] is True and again["state"] == "OPEN" and again["machine_verified"] is False
    # The finding's own SLA restarted under the standard rule; the campaign did nothing to it.
    assert vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=b5["vuln_id"])["reopen_count"] == 1


def test_a_partial_failure_in_a_verification_batch_keeps_what_succeeded(fleet, monkeypatch):
    settings, tenant_id = fleet
    cid = campaigns.create_campaign(
        settings, tenant_id=tenant_id, actor="alice", audit=None, name="batch",
        selection={"problem_keys": ["cve:CVE-2024-0001"]},
    )["campaign_id"]
    items = [_finding(settings, tenant_id, cve="CVE-2024-0001", host_port=(h, "80"))
             for h in ("10.0.0.5", "10.0.0.6", "10.0.0.7")]
    for item in items:
        _to_fixing(settings, tenant_id, item["vuln_id"])
    boom = items[1]["vuln_id"]
    real = vulns.trigger_verification

    def flaky(settings_, **kwargs):
        if kwargs["vuln_id"] == boom:
            raise RuntimeError("sensor bus fell over")
        return real(settings_, **kwargs)

    monkeypatch.setattr(vulns, "trigger_verification", flaky)
    report = campaigns.verify_members(settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None)

    outcomes = {r["id"]: r["outcome"] for r in report["results"]}
    assert outcomes[items[0]["vuln_id"]] == "dispatched" and outcomes[items[2]["vuln_id"]] == "dispatched"
    assert outcomes[boom] == "failed"
    assert "sensor bus" in next(r for r in report["results"] if r["id"] == boom)["detail"]
    states = {i["vuln_id"]: vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=i["vuln_id"])["state"]
              for i in items}
    assert states[items[0]["vuln_id"]] == states[items[2]["vuln_id"]] == vuln_states.VERIFYING
    assert states[boom] == vuln_states.FIXING
    events, _ = campaigns.list_events(settings, tenant_id=tenant_id, campaign_id=cid)
    requested = next(e for e in events if e["kind"] == "verification_requested")
    assert requested["detail"]["summary"] == {"dispatched": 2, "failed": 1}


def test_verification_reports_conflict_unsupported_and_the_per_request_limit(fleet, monkeypatch):
    settings, tenant_id = fleet
    cid = campaigns.create_campaign(
        settings, tenant_id=tenant_id, actor="alice", audit=None, name="mixed",
        selection={"problem_keys": ["cve:CVE-2024-0001"]},
    )["campaign_id"]
    items = [_finding(settings, tenant_id, cve="CVE-2024-0001", host_port=(h, "80"))
             for h in ("10.0.0.5", "10.0.0.6", "10.0.0.7")]
    # Not in FIXING: the lifecycle does not allow VERIFYING from OPEN.
    report = campaigns.verify_members(
        settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None,
        vuln_ids=[items[0]["vuln_id"], "vln_not_a_member"],
    )
    results = {r["id"]: r for r in report["results"]}
    assert results[items[0]["vuln_id"]]["outcome"] == "conflict"
    assert "cannot move from OPEN to VERIFYING" in results[items[0]["vuln_id"]]["detail"]
    assert results["vln_not_a_member"]["outcome"] == "not_member"
    # With no ids, only what is legally ready is attempted (nothing is in FIXING).
    nothing = campaigns.verify_members(settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None)
    assert nothing["results"] == [] and nothing["summary"] == {}

    # A software-inventory finding is not verified by a scan: said so, not attempted.
    with get_session(settings.postgres_url) as session:
        session.get(models.Vulnerability, items[1]["vuln_id"]).source = "endpoint_software"
    _to_fixing(settings, tenant_id, items[1]["vuln_id"])
    unsupported = campaigns.verify_members(
        settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None,
        vuln_ids=[items[1]["vuln_id"]],
    )
    assert unsupported["results"][0]["outcome"] == "unsupported"
    assert _categories(settings, tenant_id, cid)["unavailable"] == 1

    # The cap: more candidates than one request may dispatch are deferred, not dropped.
    monkeypatch.setattr(campaigns, "MAX_VERIFY_PER_REQUEST", 1)
    _to_fixing(settings, tenant_id, items[0]["vuln_id"])
    _to_fixing(settings, tenant_id, items[2]["vuln_id"])
    capped = campaigns.verify_members(
        settings, tenant_id=tenant_id, campaign_id=cid, actor="alice", audit=None,
        vuln_ids=[items[0]["vuln_id"], items[2]["vuln_id"]],
    )
    assert sorted(r["outcome"] for r in capped["results"]) == ["deferred", "dispatched"]


def test_verify_over_http_is_idempotent_and_needs_operator(tmp_path, monkeypatch):
    from tests.conftest import auth_headers, configured_client, make_settings

    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    operator = auth_headers(client, "operator")
    _write_run(settings.output_dir, "run-1", HOSTS, FINDINGS)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    created = client.post(
        "/api/remediation-campaigns",
        json={"name": "http", "selection": {"problem_keys": ["cve:CVE-2024-0002"]}},
        headers=operator,
    ).json()
    cid = created["campaign_id"]
    for item in campaigns.list_members(settings, tenant_id=tenant_id, campaign_id=cid, limit=10)[0]:
        _to_fixing(settings, tenant_id, item["vuln_id"])

    headers = {**operator, "Idempotency-Key": "verify-1"}
    first = client.post(f"/api/remediation-campaigns/{cid}/verify", json={}, headers=headers)
    second = client.post(f"/api/remediation-campaigns/{cid}/verify", json={}, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["summary"] == {"dispatched": 2}
    assert second.json()["replayed"] is True and second.json()["summary"] == {"dispatched": 2}
    # The replay dispatched nothing: still exactly two verification jobs.
    with get_session(settings.postgres_url) as session:
        from sqlalchemy import func, select

        started = session.execute(
            select(func.count()).select_from(models.VulnerabilityEvent)
            .where(models.VulnerabilityEvent.kind == "verification_started")
        ).scalar_one()
    assert started == 2
    viewer = auth_headers(client, "viewer")
    assert client.post(f"/api/remediation-campaigns/{cid}/verify", json={}, headers=viewer).status_code == 403


def test_a_dead_verification_job_does_not_pin_a_finding_against_its_ticket(fleet):
    """``verification_job_id`` is never cleared: only a *live* job holds the finding."""
    settings, tenant_id = fleet
    item = _finding(settings, tenant_id, cve="CVE-2024-0001", host_port=("10.0.0.5", "80"))
    _to_fixing(settings, tenant_id, item["vuln_id"])
    vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=item["vuln_id"], actor="alice")
    vulns.set_ticket(settings, tenant_id=tenant_id, vuln_id=item["vuln_id"], system="jira",
                     key="SEC-1", url=None, actor="alice", verify_repository=False)

    _set_job_status(settings, tenant_id, item["vuln_id"], "failed")  # died with its sensor
    vulns.apply_ticket_status(settings, tenant_id=tenant_id, vuln_id=item["vuln_id"],
                              suggested_state="CLOSED", raw_status="Done")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=item["vuln_id"])
    assert after["state"] == vuln_states.CLOSED and after["machine_verified"] is False
    events, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=item["vuln_id"])
    synced = next(e for e in events if e["kind"] == "ticket_synced")
    assert synced["detail"]["applied"] is True and "held_for_verification" not in synced["detail"]
