"""Confirmed actions use real admission and durable claims, never real probes."""
from datetime import timedelta

import json

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import jobs, quotas, scan_queue
from api.services.local_operator import actions, store
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres


@pytest.mark.parametrize("body", [
    {"action": "shell", "arguments": {}},
    {"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80", "quota_exempt": True}},
    {"action": "start_scan", "arguments": {"ports": "80"}},
    {"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80", "priority": 100}},
    {"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80", "tenant_id": "foreign"}},
    {"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80", "intent": "arbitrary"}},
    {"action": "verify_finding", "arguments": {"vuln_id": "known", "machine_verified": True}},
    {"action": "cancel_scan", "arguments": {"job_id": "known", "shell": "id"}},
])
def test_closed_action_contract(body):
    with pytest.raises(ValidationError):
        actions.PrepareAction.model_validate(body)


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True, job_execution_mode="agent")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    operator = auth_headers(client, "operator")
    admin = auth_headers(client, "admin")
    result = client.post("/api/operator/sessions?tenant_id=default", headers=operator, json={})
    assert result.status_code == 201, result.text
    return client, settings, operator, admin, result.json()["session_id"]


def _prepare(env, **arguments):
    client, settings, operator, admin, session = env
    return client.post(f"/api/operator/sessions/{session}/proposals?tenant_id=default", headers=operator,
        json={"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80", **arguments}})


def _confirm(env, proposal, **body):
    client, settings, operator, admin, session = env
    return client.post(f"/api/operator/proposals/{proposal['proposal_id']}/confirm?tenant_id=default",
        headers=operator, json={"arguments_sha256": proposal["arguments_sha256"], **body})


@requires_postgres
def test_prepare_is_read_only_and_confirm_is_durable_single_job(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env)
    assert proposal.status_code == 201, proposal.text
    proposal = proposal.json()
    assert proposal["status"] == "preview"
    assert proposal["impact"]["targets"]["ranges"] == ["127.0.0.1"]
    assert jobs.list_jobs(settings)[1] == 0
    first = _confirm(env, proposal)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "succeeded", first.text
    job_id = first.json()["execution"]["result"]["job_id"]
    second = _confirm(env, proposal)
    assert second.json()["execution"]["result"]["job_id"] == job_id
    assert jobs.list_jobs(settings)[1] == 1
    job = jobs.get_job(settings, job_id)
    assert job.tenant_id == "default"
    history = client.get(f"/api/operator/sessions/{session}?tenant_id=default", headers=operator).json()
    assert history["proposals"][0]["proposal_id"] == proposal["proposal_id"]
    assert "auth_session_sha256" not in str(history)


@requires_postgres
def test_hash_tampering_expiry_and_changed_policy_never_dispatch(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    assert _confirm(env, proposal, arguments_sha256="0" * 64).status_code == 409
    with get_session(settings.postgres_url) as db:
        row = db.get(models.OperatorProposal, proposal["proposal_id"])
        row.payload = {**row.payload, "expires_at": (store._now() - timedelta(seconds=1)).isoformat() + "Z"}
    assert _confirm(env, proposal).status_code == 409
    proposal = _prepare(env).json()
    response = client.put("/api/tenants/default/scan-scope", headers=admin,
        json={"entries": [{"kind": "cidr", "effect": "allow", "value": "10.0.0.0/8"}]})
    assert response.status_code == 200, response.text
    assert _confirm(env, proposal).status_code in {403, 409}
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_scope_group_and_role_refusals_have_no_jobs(env):
    client, settings, operator, admin, session = env
    assert _prepare(env, agent_group="does-not-exist").status_code in {403, 422}
    url = f"/api/operator/sessions/{session}/proposals"
    assert client.post(url, headers=operator, json={"action": "cancel_scan", "arguments": {"job_id": "missing"}}).status_code == 422
    viewer = auth_headers(client, "viewer")
    assert client.post(url + "?tenant_id=default", headers=viewer, json={"action": "cancel_scan", "arguments": {"job_id": "missing"}}).status_code == 403
    proposal = _prepare(env).json()
    assert client.get(f"/api/operator/proposals/{proposal['proposal_id']}?tenant_id=default", headers=admin).status_code == 404
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_unknown_dispatch_reconciles_without_second_job(env, monkeypatch):
    original = jobs.start_scan

    def accepted_then_disconnected(*args, **kwargs):
        original(*args, **kwargs)
        raise ConnectionError("private upstream exception")

    monkeypatch.setattr(jobs, "start_scan", accepted_then_disconnected)
    proposal = _prepare(env).json()
    result = _confirm(env, proposal)
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "unknown"
    assert "private upstream" not in result.text
    assert jobs.list_jobs(env[1])[1] == 1
    retry = _confirm(env, proposal)
    assert retry.json()["status"] == "succeeded", retry.text
    assert retry.json()["execution"]["reconciled"]
    assert jobs.list_jobs(env[1])[1] == 1


@requires_postgres
def test_unknown_without_job_never_redispatches_and_preserves_history(env, monkeypatch):
    calls = []

    def disconnected(*args, **kwargs):
        calls.append(1)
        raise ConnectionError("unavailable")

    monkeypatch.setattr(jobs, "start_scan", disconnected)
    proposal = _prepare(env).json()
    assert _confirm(env, proposal).json()["status"] == "unknown"
    assert _confirm(env, proposal).json()["status"] == "unknown"
    assert calls == [1]
    client, settings, operator, admin, session = env
    assert client.delete(f"/api/operator/sessions/{session}?tenant_id=default", headers=operator).status_code == 409
    with get_session(settings.postgres_url) as db:
        assert len(list(db.scalars(select(models.OperatorExecution)))) == 1
    # A genuinely unknown outcome has an administrator exit; the operator has none.
    close = f"/api/operator/proposals/{proposal['proposal_id']}/close?tenant_id=default"
    assert client.post(close, headers=operator, json={"resolution": "no_effect"}).status_code == 403
    closed = client.post(close, headers=admin, json={"resolution": "no_effect"})
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "failed"
    assert closed.json()["execution"]["closed_by_admin"] is True
    assert client.post(close, headers=admin, json={"resolution": "no_effect"}).status_code == 409
    assert calls == [1]
    assert client.delete(f"/api/operator/sessions/{session}?tenant_id=default", headers=operator).status_code == 204


@requires_postgres
def test_admin_close_rejects_settled_actions_and_bad_input(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    close = f"/api/operator/proposals/{proposal['proposal_id']}/close?tenant_id=default"
    assert client.post(close, headers=admin, json={"resolution": "no_effect"}).status_code == 409  # never confirmed
    assert _confirm(env, proposal).json()["status"] == "succeeded"
    assert client.post(close, headers=admin, json={"resolution": "no_effect"}).status_code == 409  # settled
    assert client.post(close, headers=admin, json={"resolution": "whatever"}).status_code == 422
    assert client.post(close, headers=admin, json={}).status_code == 422


@requires_postgres
def test_admin_close_effect_confirmed_marks_succeeded_and_audits(env, monkeypatch):
    monkeypatch.setattr(jobs, "start_scan", lambda *a, **k: (_ for _ in ()).throw(ConnectionError("x")))
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    assert _confirm(env, proposal).json()["status"] == "unknown"
    close = f"/api/operator/proposals/{proposal['proposal_id']}/close?tenant_id=default"
    closed = client.post(close, headers=admin, json={"resolution": "effect_confirmed"})
    assert closed.json()["status"] == "succeeded", closed.text
    with get_session(settings.postgres_url) as db:
        entry = db.scalar(select(models.AuditEvent).where(models.AuditEvent.action == "operator.action.close"))
        assert entry is not None


@requires_postgres
@pytest.mark.parametrize("kind,status", [("quota", 429), ("maintenance", 409), ("value", 200), ("store", 200)])
def test_errors_before_effect_fail_with_reason_and_never_stick_as_unknown(env, monkeypatch, kind, status):
    from api.services import maintenance

    def refuse(*args, **kwargs):
        if kind == "quota":
            raise quotas.QuotaExceeded("limit", tenant_id="default", resource="scans", limit=1, used=1,
                                       retry_after_seconds=30)
        if kind == "maintenance":
            raise maintenance.MaintenanceBlocked("closed", tenant_id="default", reason="freeze")
        if kind == "value":
            raise ValueError("Confirmed scan admission changed; prepare a new proposal")
        raise store.OperatorStoreError("access_revoked")

    monkeypatch.setattr(jobs, "start_scan", refuse)
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    result = _confirm(env, proposal)
    assert result.status_code == status, result.text
    if kind == "quota":
        assert result.headers["Retry-After"] == "30"
    # The failure is committed either way and a repeat shows it without dispatching again.
    after = client.get(f"/api/operator/proposals/{proposal['proposal_id']}?tenant_id=default", headers=operator).json()
    assert after["status"] == "failed", after
    assert after["execution"]["no_effect"] is True
    assert after["execution"]["error"] == {"quota": "quota_exceeded", "maintenance": "maintenance_blocked",
                                           "value": "stale_proposal", "store": "access_revoked"}[kind]
    assert after["execution"]["retryable"] is (kind in {"quota", "maintenance"})
    assert _confirm(env, proposal).json()["status"] == "failed"
    assert jobs.list_jobs(settings)[1] == 0
    assert client.delete(f"/api/operator/sessions/{session}?tenant_id=default", headers=operator).status_code == 204


def test_pre_effect_classification_never_trusts_a_wrapped_lost_response():
    from api.services import vulnerabilities

    def wrapped(cause):
        try:
            try:
                raise cause
            except Exception as inner:
                raise vulnerabilities.VerificationDispatchError("Could not dispatch") from inner
        except vulnerabilities.VerificationDispatchError as exc:
            return exc

    assert actions.is_pre_effect(vulnerabilities.VerificationDispatchError("No live sensor"))
    assert actions.is_pre_effect(wrapped(ValueError("admission changed")))
    assert actions.is_pre_effect(wrapped(PermissionError("scope")))
    assert not actions.is_pre_effect(wrapped(ConnectionError("lost response after commit")))
    assert not actions.is_pre_effect(wrapped(RuntimeError("thread start failed")))
    assert not actions.is_pre_effect(vulnerabilities.VerificationReconciliationRequired(
        type("Job", (), {"job_id": "j", "status": "queued"})()))
    assert not actions.is_pre_effect(ConnectionError("x"))
    assert not actions.is_pre_effect(RuntimeError("x"))


@requires_postgres
def test_recheck_failures_in_second_transaction_are_logged_and_classified(env, monkeypatch, caplog):
    proposal = _prepare(env).json()
    real = actions._preview
    state = {"calls": 0}

    def second_preview_fails(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 2:
            raise quotas.QuotaExceeded("limit", tenant_id="default", resource="scans", limit=1, used=1)
        return real(*args, **kwargs)

    monkeypatch.setattr(actions, "_preview", second_preview_fails)
    with caplog.at_level("WARNING"):
        result = _confirm(env, proposal)
    assert result.status_code == 429, result.text
    assert "refused before effect: quota_exceeded" in caplog.text
    assert jobs.list_jobs(env[1])[1] == 0


@requires_postgres
def test_proposal_expiry_is_compared_as_datetimes_not_strings(env, monkeypatch):
    from datetime import datetime

    proposal = _prepare(env).json()
    client, settings, operator, admin, session = env
    with get_session(settings.postgres_url) as db:
        row = db.get(models.OperatorProposal, proposal["proposal_id"])
        # No fractional digits: as a string this sorts AFTER "...00.500000Z".
        row.payload = {**row.payload, "expires_at": "2026-01-01T00:00:00Z"}
    monkeypatch.setattr(actions, "_utcnow", lambda: datetime(2026, 1, 1, 0, 0, 0, 500000))
    assert _confirm(env, proposal).status_code == 409
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_status_polling_does_not_take_the_writer_lock(env, monkeypatch):
    proposal = _prepare(env).json()
    client, settings, operator, admin, session = env
    seen = []
    real = store._lock_actor

    def spy(*args, **kwargs):
        seen.append(kwargs.get("writer", True))
        return real(*args, **kwargs)

    monkeypatch.setattr(store, "_lock_actor", spy)
    assert client.get(f"/api/operator/proposals/{proposal['proposal_id']}?tenant_id=default", headers=operator).status_code == 200
    assert seen == [False]
    assert _confirm(env, proposal).status_code == 200
    assert True in seen


@requires_postgres
def test_confirm_audit_binds_target_digest_and_job_identifier(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    assert _confirm(env, proposal).json()["status"] == "succeeded"
    with get_session(settings.postgres_url) as db:
        rows = list(db.scalars(select(models.AuditEvent).where(models.AuditEvent.action.in_(
            ["operator.action.confirm", "operator.action.result"]))))
    by_action = {row.action: row for row in rows}
    confirm = by_action["operator.action.confirm"].after
    assert len(confirm["targets_sha256"]) == 64
    assert "127.0.0.1" not in json.dumps(confirm)
    result = by_action["operator.action.result"].after
    assert result["targets_sha256"] == confirm["targets_sha256"]
    assert result["job_id"] == jobs.list_jobs(settings)[0][0].job_id


@requires_postgres
def test_cancellation_uses_existing_job_control_and_truthful_status(env):
    proposal = _prepare(env).json()
    job_id = _confirm(env, proposal).json()["execution"]["result"]["job_id"]
    client, settings, operator, admin, session = env
    prepared = client.post(f"/api/operator/sessions/{session}/proposals?tenant_id=default", headers=operator,
        json={"action": "cancel_scan", "arguments": {"job_id": job_id}})
    assert prepared.status_code == 201, prepared.text
    cancelled = _confirm(env, prepared.json())
    assert cancelled.json()["status"] == "succeeded", cancelled.text
    assert cancelled.json()["execution"]["result"]["job_status"] == "cancelled"


@requires_postgres
def test_new_login_cannot_confirm_old_auth_session_plan(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    new_login = auth_headers(client, "operator")
    response = client.post(f"/api/operator/proposals/{proposal['proposal_id']}/confirm?tenant_id=default",
        headers=new_login, json={"arguments_sha256": proposal["arguments_sha256"]})
    assert response.status_code == 403, response.text
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_policy_changes_block_preview_and_stale_confirmation(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    policy = client.put("/api/tenants/default/scan-policy", headers=admin, json={"safe_only": True})
    assert policy.status_code == 200, policy.text
    assert _confirm(env, proposal).status_code == 409
    assert _prepare(env, mode="fast").status_code == 403
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_quota_and_full_queue_after_preview_refuse_without_dispatch(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    # Existing queue depth is authoritative even when the preview was allowed.
    another = _prepare(env).json()
    assert _confirm(env, another).json()["status"] == "succeeded"
    scan_queue.set_limits(settings, "default", max_concurrent_scans=None, max_queued_scans=1)
    assert _confirm(env, proposal).status_code == 429
    assert _prepare(env).status_code == 429
    scan_queue.set_limits(settings, "default", max_concurrent_scans=None, max_queued_scans=None)
    settings.quota_enforcement_enabled = True
    quotas.set_quota(settings, "default", max_assets=None, max_scans_per_month=1)
    assert _confirm(env, proposal).status_code == 429
    assert jobs.list_jobs(settings)[1] == 1


@requires_postgres
def test_revoked_membership_cannot_use_stored_preview(env):
    client, settings, operator, admin, session = env
    proposal = _prepare(env).json()
    grant = client.put("/api/tenants/default/members/operator", headers=admin, json={"role": "viewer"})
    assert grant.status_code == 200, grant.text
    assert _confirm(env, proposal).status_code == 403
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_suspended_tenant_cannot_confirm_plan(env):
    client, settings, operator, admin, session = env
    assert client.post("/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "Acme"}).status_code == 201
    assert client.put("/api/tenants/acme/members/operator", headers=admin, json={"role": "operator"}).status_code == 200
    from tests.conftest import approve_scan_scope
    approve_scan_scope(settings, "acme")
    created = client.post("/api/operator/sessions?tenant_id=acme", headers=operator, json={})
    assert created.status_code == 201, created.text
    response = client.post(f"/api/operator/sessions/{created.json()['session_id']}/proposals?tenant_id=acme", headers=operator,
        json={"action": "start_scan", "arguments": {"ranges": "127.0.0.1", "ports": "80"}})
    assert response.status_code == 201, response.text
    proposal = response.json()
    result = client.post("/api/tenants/acme/suspend", headers=admin,
        json={"reason": "test", "revoke_credentials": False})
    assert result.status_code == 200, result.text
    assert client.post(f"/api/operator/proposals/{proposal['proposal_id']}/confirm?tenant_id=acme", headers=operator,
        json={"arguments_sha256": proposal["arguments_sha256"]}).status_code in {401, 403}
    assert jobs.list_jobs(settings)[1] == 0


@requires_postgres
def test_claim_survives_engine_restart_and_concurrent_double_click(env):
    from concurrent.futures import ThreadPoolExecutor
    from api.db.engine import get_engine

    proposal = _prepare(env).json()
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: _confirm(env, proposal), range(2)))
    assert all(response.status_code == 200 for response in responses), [response.text for response in responses]
    assert jobs.list_jobs(env[1])[1] == 1
    get_engine(env[1].postgres_url).dispose()
    response = _confirm(env, proposal)
    assert response.json()["status"] == "succeeded", response.text
    assert jobs.list_jobs(env[1])[1] == 1


@requires_postgres
def test_missing_verification_and_cross_tenant_cancel_reveal_nothing(env):
    client, settings, operator, admin, session = env
    base = f"/api/operator/sessions/{session}/proposals?tenant_id=default"
    response = client.post(base, headers=operator, json={"action": "verify_finding", "arguments": {"vuln_id": "missing"}})
    assert response.status_code == 404
    proposal = _prepare(env).json()
    job_id = _confirm(env, proposal).json()["execution"]["result"]["job_id"]
    with get_session(settings.postgres_url) as db:
        tenant = models.Tenant(tenant_id="other", name="Other", status="active", created_at=store._now())
        db.add(tenant)
        db.flush()
        job = db.get(models.Job, job_id)
        job.tenant_id = "other"
    response = client.post(base, headers=operator, json={"action": "cancel_scan", "arguments": {"job_id": job_id}})
    assert response.status_code == 404


@requires_postgres
def test_policy_interleaving_at_actual_admission_cannot_change_confirmed_plan(env, monkeypatch):
    from api.services import scan_policy

    proposal = _prepare(env).json()
    original = jobs.start_scan

    def interleaving(*args, **kwargs):
        # Runs after both operator checks, immediately before real submission.
        scan_policy.replace_policy(env[1], tenant_id="default", safe_only=True, updated_by="admin")
        return original(*args, **kwargs)

    monkeypatch.setattr(jobs, "start_scan", interleaving)
    result = _confirm(env, proposal)
    assert result.status_code == 200, result.text
    # A refusal at actual admission happens before any effect: failed, not unknown.
    assert result.json()["status"] == "failed", result.text
    assert result.json()["execution"]["error"] == "stale_proposal"
    assert result.json()["execution"]["no_effect"] is True
    assert jobs.list_jobs(env[1])[1] == 0
    assert not list((env[1].state_dir / "job_inputs").glob("*"))
    # No admin step is needed to clean up the session afterwards.
    client, settings, operator, admin, session = env
    assert client.delete(f"/api/operator/sessions/{session}?tenant_id=default", headers=operator).status_code == 204


@requires_postgres
@pytest.mark.parametrize("changed_during_dispatch", [False, True])
def test_verification_uses_real_lifecycle_and_never_machine_closes(env, monkeypatch, changed_during_dispatch):
    from api.services import agents, assets, vulnerabilities
    from tests.test_vuln_lifecycle import _write_run

    client, settings, operator, admin, session = env
    _write_run(settings.output_dir, "finding-run", [{"host": "127.0.0.1"}], [
        {"host": "127.0.0.1", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8,
         "severity": "critical", "source": "nuclei", "script_id": "CVE-2024-0001"}])
    assets.upsert_assets_from_run(settings, tenant_id="default", run_id="finding-run")
    vulnerabilities.register_findings_from_run(settings, tenant_id="default", run_id="finding-run")
    finding = vulnerabilities.list_vulnerabilities(settings, tenant_id="default")[0][0]
    vuln_id = finding["vuln_id"]
    vulnerabilities.transition(settings, tenant_id="default", vuln_id=vuln_id, to_state="FIXING", actor="operator")
    agents.register_agent(hostname="verify-scanner", tenant_id="default", version="99.0.0",
        capabilities=["scan_policy", "config_overlay.v1", "config_overlay.v2"])
    response = client.post(f"/api/operator/sessions/{session}/proposals?tenant_id=default", headers=operator,
        json={"action": "verify_finding", "arguments": {"vuln_id": vuln_id}})
    assert response.status_code == 201, response.text
    proposal = response.json()
    assert proposal["impact"]["targets"]["ranges"] == ["127.0.0.1"]
    if changed_during_dispatch:
        original = vulnerabilities.trigger_verification

        def changed(*args, **kwargs):
            with get_session(settings.postgres_url) as db:
                db.get(models.Vulnerability, vuln_id).port = 8443
            return original(*args, **kwargs)

        monkeypatch.setattr(vulnerabilities, "trigger_verification", changed)
    verified = _confirm(env, proposal)
    assert verified.status_code == 200, verified.text
    if changed_during_dispatch:
        assert verified.json()["status"] == "failed", verified.text
        assert jobs.list_jobs(settings)[1] == 0
        assert vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)["state"] == "FIXING"
        return
    assert verified.json()["status"] == "succeeded", verified.text
    result = verified.json()["execution"]["result"]
    assert result["machine_verified"] is False
    assert result["finding_state"] == "VERIFYING"
    job = jobs.get_job(settings, result["job_id"])
    assert job.scan_options["verification_of"] == vuln_id
    assert job.scan_options["config_overlay_capability"] == "config_overlay.v2"
    assert jobs.list_jobs(settings)[1] == 1
    assert _confirm(env, proposal).json()["execution"]["result"]["job_id"] == job.job_id
    assert vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)["state"] == "VERIFYING"
