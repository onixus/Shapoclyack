"""Distinct operator/campaign entry points must not dispatch two native checks."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import agents, assets, jobs, vulnerabilities
from tests.conftest import requires_postgres
from tests import test_operator_actions as action_tests
from tests.test_vuln_lifecycle import _write_run

env = action_tests.env
_confirm = action_tests._confirm


def _campaign_request(env, campaign_id):
    client, _settings, _operator, admin, _session = env
    response = client.post(f"/api/remediation-campaigns/{campaign_id}/verify", headers=admin, json={})
    assert response.status_code == 200, response.text
    return response.json()


@pytest.fixture
def finding(env):
    client, settings, operator, _admin, session = env
    _write_run(settings.output_dir, "cross-entry-finding", [{"host": "127.0.0.1"}], [
        {"host": "127.0.0.1", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8,
         "severity": "critical", "source": "nuclei", "script_id": "CVE-2024-0001"}])
    assets.upsert_assets_from_run(settings, tenant_id="default", run_id="cross-entry-finding")
    vulnerabilities.register_findings_from_run(settings, tenant_id="default", run_id="cross-entry-finding")
    vuln_id = vulnerabilities.list_vulnerabilities(settings, tenant_id="default")[0][0]["vuln_id"]
    vulnerabilities.transition(settings, tenant_id="default", vuln_id=vuln_id, to_state="FIXING", actor="operator")
    agents.register_agent(hostname="cross-entry-verifier", tenant_id="default", version="99.0.0",
        capabilities=["scan_policy", "config_overlay.v1", "config_overlay.v2"])
    response = client.post("/api/remediation-campaigns", headers=operator,
        json={"name": "cross-entry", "selection": {"vuln_ids": [vuln_id]}})
    assert response.status_code == 201, response.text
    campaign_id = response.json()["campaign_id"]
    response = client.post(f"/api/operator/sessions/{session}/proposals?tenant_id=default", headers=operator,
        json={"action": "verify_finding", "arguments": {"vuln_id": vuln_id}})
    assert response.status_code == 201, response.text
    proposal = response.json()
    return settings, vuln_id, campaign_id, proposal


@requires_postgres
def test_campaign_and_confirmed_operator_verify_one_finding_dispatch_one_job(env, finding, monkeypatch):
    settings, vuln_id, campaign_id, proposal = finding

    # Both old entry paths can pass their FIXING check before either job insert.
    # With a real per-finding claim the first waits briefly, then proceeds alone.
    at_dispatch = threading.Barrier(2)
    original = jobs.start_scan
    def overlapping_dispatch(*args, **kwargs):
        try:
            at_dispatch.wait(timeout=2)
        except threading.BrokenBarrierError:
            pass
        return original(*args, **kwargs)
    monkeypatch.setattr(jobs, "start_scan", overlapping_dispatch)
    with ThreadPoolExecutor(max_workers=2) as pool:
        campaign = pool.submit(_campaign_request, env, campaign_id)
        confirmed = pool.submit(_confirm, env, proposal)
        campaign_result = campaign.result(timeout=20)
        confirmation = confirmed.result(timeout=20)
    assert confirmation.status_code == 200, confirmation.text
    assert jobs.list_jobs(settings)[1] == 1, (campaign_result, confirmation.json())
    with get_session(settings.postgres_url) as db:
        assert db.scalar(select(func.count()).select_from(models.VulnerabilityEvent).where(
            models.VulnerabilityEvent.vuln_id == vuln_id,
            models.VulnerabilityEvent.kind == "verification_started")) == 1
    finding = vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert finding["state"] == "VERIFYING" and not finding["machine_verified"]
    assert finding["verification_job_id"] == jobs.list_jobs(settings)[0][0].job_id


@requires_postgres
@pytest.mark.parametrize("terminal", [None, "succeeded", "failed", "cancelled", "cancelling"])
def test_committed_job_before_lost_receipt_reconciles_other_entry_without_new_scan(env, finding, monkeypatch, terminal):
    settings, vuln_id, campaign_id, proposal = finding
    original = jobs.start_scan
    def committed_then_disconnected(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("Lost response after durable job commit")
    monkeypatch.setattr(jobs, "start_scan", committed_then_disconnected)
    response = _confirm(env, proposal)
    assert response.status_code == 200 and response.json()["status"] == "unknown"
    assert jobs.list_jobs(settings)[1] == 1
    first_job = jobs.list_jobs(settings)[0][0]
    assert vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)["state"] == "FIXING"
    with get_session(settings.postgres_url) as db:
        row = db.get(models.Vulnerability, vuln_id)
        # Attribution changes are not a new verification epoch.
        row.assignee = "another-owner"
        row.updated_at = row.updated_at.replace(microsecond=(row.updated_at.microsecond + 1) % 1000000)
        if terminal:
            # Fault fixture: the real persisted job ended during recorder loss;
            # no scanner result/coverage or machine-verified verdict is invented.
            db.get(models.Job, first_job.job_id).status = terminal
    monkeypatch.setattr(jobs, "start_scan", original)
    result = _campaign_request(env, campaign_id)
    assert jobs.list_jobs(settings)[1] == 1
    current = vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert not current["machine_verified"]
    if terminal:
        assert current["state"] == "FIXING" and current["verification_job_id"] is None
        assert result["summary"] == {"failed": 1}
        detail = json.loads(result["results"][0]["detail"])
        assert detail["requires_reconciliation"] and detail["job_id"] == first_job.job_id
        assert detail["job_status"] == terminal
    else:
        assert result["summary"] == {"dispatched": 1}
        assert current["state"] == "VERIFYING" and current["verification_job_id"] == first_job.job_id
        with get_session(settings.postgres_url) as db:
            events = list(db.scalars(select(models.VulnerabilityEvent).where(
                models.VulnerabilityEvent.vuln_id == vuln_id,
                models.VulnerabilityEvent.kind == "verification_started")))
            assert len(events) == 1 and events[0].detail["reconciled"] is True


@requires_postgres
def test_new_lifecycle_epoch_can_request_a_new_native_verification(env, finding):
    settings, vuln_id, _campaign_id, proposal = finding
    response = _confirm(env, proposal)
    assert response.status_code == 200 and response.json()["status"] == "succeeded"
    first = response.json()["execution"]["result"]["job_id"]
    with get_session(settings.postgres_url) as db:
        db.get(models.Job, first).status = "failed"  # controlled terminal fault fixture
    vulnerabilities.transition(settings, tenant_id="default", vuln_id=vuln_id, to_state="FIXING", actor="operator")
    result = vulnerabilities.trigger_verification(settings, tenant_id="default", vuln_id=vuln_id, actor="admin")
    assert result["verification_job_id"] != first and jobs.list_jobs(settings)[1] == 2


@requires_postgres
@pytest.mark.parametrize("gate", ["disabled", "scope_removed", "stale_plan"])
def test_reconciliation_cannot_bypass_current_native_admission(env, finding, monkeypatch, gate):
    settings, vuln_id, _campaign_id, proposal = finding
    original = jobs.start_scan
    def committed_then_disconnected(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("Lost response after durable job commit")
    monkeypatch.setattr(jobs, "start_scan", committed_then_disconnected)
    assert _confirm(env, proposal).json()["status"] == "unknown"
    monkeypatch.setattr(jobs, "start_scan", original)
    kwargs = {}
    blocked = replace(settings, allow_scan_start=False) if gate == "disabled" else settings
    if gate == "scope_removed":
        response = env[0].put("/api/tenants/default/scan-scope", headers=env[3],
            json={"entries": [{"kind": "cidr", "effect": "allow", "value": "10.0.0.0/8"}]})
        assert response.status_code == 200, response.text
    elif gate == "stale_plan":
        kwargs["expected_plan_sha256"] = "0" * 64
    with pytest.raises(vulnerabilities.VerificationDispatchError):
        vulnerabilities.trigger_verification(blocked, tenant_id="default", vuln_id=vuln_id, actor="admin", **kwargs)
    assert jobs.list_jobs(settings)[1] == 1
    assert vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)["state"] == "FIXING"


def test_single_process_fallback_is_keyed_and_releases_claim(monkeypatch):
    monkeypatch.setattr(vulnerabilities, "get_engine", lambda _: SimpleNamespace(dialect=SimpleNamespace(name="sqlite")))
    settings = SimpleNamespace(postgres_url="unused-test-url")
    with vulnerabilities._verification_dispatch_claim(settings, "tenant", "finding"):
        with pytest.raises(vulnerabilities.VerificationDispatchError, match="already in progress"):
            with vulnerabilities._verification_dispatch_claim(settings, "tenant", "finding"):
                pytest.fail("Same finding must not enter twice")
        with vulnerabilities._verification_dispatch_claim(settings, "tenant", "other-finding"):
            pass
    with vulnerabilities._verification_dispatch_claim(settings, "tenant", "finding"):
        pass


@requires_postgres
@pytest.mark.parametrize("terminal", ["succeeded", "cancelled"])
def test_first_dispatch_already_finished_before_finding_receipt_does_not_park(env, finding, monkeypatch, terminal):
    settings, vuln_id, _campaign_id, _proposal = finding
    original = jobs.start_scan
    def finished_before_return(*args, **kwargs):
        job = original(*args, **kwargs)
        with get_session(settings.postgres_url) as db:
            db.get(models.Job, job.job_id).status = terminal
        return job  # Deliberately stale QUEUED response, as a real race can be.
    monkeypatch.setattr(jobs, "start_scan", finished_before_return)
    with pytest.raises(vulnerabilities.VerificationReconciliationRequired) as error:
        vulnerabilities.trigger_verification(settings, tenant_id="default", vuln_id=vuln_id, actor="admin")
    assert error.value.job_status == terminal and error.value.requires_reconciliation
    assert jobs.list_jobs(settings)[1] == 1
    assert error.value.job_id == jobs.list_jobs(settings)[0][0].job_id
    current = vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert current["state"] == "FIXING" and current["verification_job_id"] is None and not current["machine_verified"]


@requires_postgres
def test_new_confirmed_operator_intent_reports_known_terminal_job_without_replay(env, finding, monkeypatch):
    settings, vuln_id, _campaign_id, proposal = finding
    original = jobs.start_scan
    def committed_then_disconnected(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("Lost response after durable job commit")
    monkeypatch.setattr(jobs, "start_scan", committed_then_disconnected)
    assert _confirm(env, proposal).json()["status"] == "unknown"
    first = jobs.list_jobs(settings)[0][0].job_id
    with get_session(settings.postgres_url) as db:
        db.get(models.Job, first).status = "succeeded"
    monkeypatch.setattr(jobs, "start_scan", original)
    client, _settings, operator, _admin, session = env
    fresh = client.post(f"/api/operator/sessions/{session}/proposals?tenant_id=default", headers=operator,
        json={"action": "verify_finding", "arguments": {"vuln_id": vuln_id}}).json()
    confirmation = _confirm(env, fresh)
    assert confirmation.status_code == 200, confirmation.text
    execution = confirmation.json()["execution"]
    assert confirmation.json()["status"] == execution["status"] == "unknown"
    assert execution["requires_reconciliation"] is True
    assert execution["job_id"] == first and execution["job_status"] == "succeeded"
    assert _confirm(env, fresh).json()["execution"] == execution
    assert jobs.list_jobs(settings)[1] == 1
    current = vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)
    assert current["state"] == "FIXING" and current["verification_job_id"] is None and not current["machine_verified"]
