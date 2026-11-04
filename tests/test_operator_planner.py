"""Planner decisions remain side-effect-free and bind current console authority."""
import asyncio
import json

import pytest
from pydantic import ValidationError

from api.services.local_operator import planner, providers, store, worker
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.operator_planner_wire import intent_wire


@pytest.mark.parametrize("tool,context", [
    ("summarize_run", {"run_id": "r"}), ("analyze_run", {"run_id": "r"}),
    ("compare_runs", {"run_id": "r", "previous_run_id": "p"}),
    ("find_remediation", {"device_id": "d"}), ("find_remediation", {"vuln_id": "v"}),
    ("cancel_scan", {"job_id": "j"}),
    ("verify_finding", {"vuln_id": "v"}),
    ("prepare_scan", {"scan": {"ranges": "192.0.2.1", "ports": "443"}}),
])
def test_model_selects_only_tool_server_owns_arguments(tool, context):
    request = planner.PlanRequest(request="requested operation", context=context)
    kind = "finding" if tool == "find_remediation" and "vuln_id" in context else None
    result = planner.validate_output(intent_wire(tool, kind), request)
    assert result["arguments"] == planner.available_tools(request)[tool]
    assert result["effect_executed"] is False
    assert result["requires_confirmation"] == (tool in {"prepare_scan", "cancel_scan", "verify_finding"})
    assert tool in planner.output_schema(request)["properties"]["intent"]["enum"]


@pytest.mark.parametrize("raw", ['{"tool":"shell"}', '{"tool":"cancel_scan"}',
    '{"tool":"abstain","tenant_id":"foreign"}', '{"tool":"abstain","arguments":{}}',
    '{"tool":"abstain","tool":"abstain"}', "[]", "{}"])
def test_closed_output_cannot_invent_tools_or_context(raw):
    from api.services.local_operator.gateway import GatewayError
    with pytest.raises(GatewayError):
        planner.validate_output(raw, planner.PlanRequest(request="anything"))


def test_empty_context_requires_abstention_and_never_leaks_scan_arguments():
    request = planner.PlanRequest(request="help", context={})
    assert planner.validate_output(intent_wire("analyze_run"), request)["tool"] == "abstain"
    assert planner.validate_output(intent_wire("abstain"), request)["status"] == "unsupported"
    request = planner.PlanRequest(request="scan", context={"scan": {"ranges": "192.0.2.77", "ports": "443"}})
    assert "192.0.2.77" not in json.dumps(planner.build_prompt(request))


@pytest.mark.parametrize("body", [
    {"request": "x", "tenant_id": "foreign"},
    {"request": "x", "context": {"role": "admin"}},
    {"request": "x", "context": {"scan": {"ranges": "192.0.2.1", "ports": "443", "quota_exempt": True}}},
    {"request": "x" * 1001},
])
def test_planner_request_is_closed_and_bounded(body):
    with pytest.raises(ValidationError):
        planner.PlanRequest.model_validate(body)


@pytest.mark.parametrize("secret,text", [
    ("private-canary", "help Authorization: Bearer private-canary"),
    ("private-canary", 'help password="private-canary"'),
    ("private-canary", "help api_key=private-canary"),
    ("private-canary", '{"api_key":"private-canary"}'),
    ("private-canary", "{'password':'private-canary'}"),
    ("private-canary", '{"password":"escaped\\\"private-canary"}'),
    ("private-canary", "help https://user:private-canary@192.0.2.1/path"),
    ("private-canary", "-----BEGIN PRIVATE KEY-----\nprivate-canary\n-----END PRIVATE KEY-----"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl", "token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl"),
])
def test_known_credentials_removed_before_storage_and_prompt(secret, text):
    request = planner.PlanRequest(request=text)
    assert secret not in json.dumps(request.model_dump())
    assert secret not in json.dumps(planner.build_prompt(request))
    assert "[redacted" in request.request


@requires_postgres
def test_durable_planner_worker_history_cancel_and_ownership(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True, operator_worker_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = auth_headers(client, "operator")
    session = client.post("/api/operator/sessions?tenant_id=default", headers=headers, json={}).json()["session_id"]
    calls = []
    async def complete(self, messages, *, response_schema=None):
        calls.append((messages, response_schema))
        assert "abstain" in response_schema["properties"]["intent"]["enum"]
        return providers.Completion(intent_wire("abstain"), "local", "test")
    monkeypatch.setattr(planner.gateway.InferenceProvider, "complete", complete)
    path = f"/api/operator/sessions/{session}/plan?tenant_id=default"
    body = {"request": "Install packages automatically", "language": "en", "context": {}}
    response = client.post(path, headers={**headers, "Idempotency-Key": "planner-one"}, json=body)
    assert response.status_code == 202, response.text
    task = response.json()
    assert "payload" not in task
    asyncio.run(worker.run_worker(settings, once=True))
    result = client.get(f"/api/operator/tasks/{task['task_id']}?tenant_id=default", headers=headers).json()
    assert result["status"] == "succeeded", result
    assert result["result"]["plan"]["effect_executed"] is False
    assert len(calls) == 1
    replay = client.post(path, headers={**headers, "Idempotency-Key": "planner-one"}, json=body)
    assert replay.json()["task_id"] == task["task_id"]
    assert client.post(path, headers={**headers, "Idempotency-Key": "planner-one"}, json={**body, "request": "different"}).status_code == 409
    viewer = auth_headers(client, "viewer")
    assert client.post(path, headers={**viewer, "Idempotency-Key": "viewer-plan"}, json=body).status_code == 403
    admin = auth_headers(client, "admin")
    assert client.get(f"/api/operator/tasks/{task['task_id']}?tenant_id=default", headers=admin).status_code == 404
    response = client.post(path, headers={**headers, "Idempotency-Key": "planner-cancel"}, json=body)
    cancelled = client.post(f"/api/operator/tasks/{response.json()['task_id']}/cancel?tenant_id=default", headers=headers)
    assert cancelled.json()["status"] == "cancelled"
    asyncio.run(worker.run_worker(settings, once=True))
    assert len(calls) == 1


@requires_postgres
def test_queued_planner_session_revocation_prevents_inference(tmp_path, monkeypatch):
    from sqlalchemy import update
    from api.db import models, tenant_scope
    from api.db.engine import get_session
    settings = make_settings(tmp_path, operator_enabled=True, operator_worker_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = auth_headers(client, "operator")
    session = client.post("/api/operator/sessions?tenant_id=default", headers=headers, json={}).json()["session_id"]
    response = client.post(f"/api/operator/sessions/{session}/plan?tenant_id=default",
        headers={**headers, "Idempotency-Key": "revoked"}, json={"request": "help"})
    assert response.status_code == 202, response.text
    task_id = response.json()["task_id"]
    with tenant_scope.system("planner revoke fixture"), get_session(settings.postgres_url) as db:
        db.execute(update(models.SessionFamily).where(models.SessionFamily.username == "operator")
            .values(revoked_at=store._now()))
    monkeypatch.setattr(planner.gateway.InferenceProvider, "complete", lambda *a, **k: pytest.fail("revoked inference"))
    asyncio.run(worker.run_worker(settings, once=True))
    task = store.get_task(settings, "default", "operator", task_id)
    assert task["status"] == "failed"
    assert task["error"] in {"operator_access_revoked", "operator_execution_failed"}


@requires_postgres
@pytest.mark.parametrize("source_id", ["foreign-job", "missing-job"])
def test_foreign_and_missing_bound_context_fail_before_inference(tmp_path, monkeypatch, source_id):
    from api.db import models, tenant_scope
    from api.db.engine import get_session
    settings = make_settings(tmp_path, operator_enabled=True, operator_worker_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = auth_headers(client, "operator")
    with tenant_scope.system("foreign planner context fixture"), get_session(settings.postgres_url) as db:
        db.add(models.Tenant(tenant_id="other", name="Other", status="active", created_at=store._now()))
        db.flush()
        db.add(models.Job(job_id="foreign-job", tenant_id="other", queued_at=store._now()))
    session = client.post("/api/operator/sessions?tenant_id=default", headers=headers, json={}).json()["session_id"]
    response = client.post(f"/api/operator/sessions/{session}/plan?tenant_id=default",
        headers={**headers, "Idempotency-Key": "foreign-context"},
        json={"request": "cancel this job", "context": {"job_id": source_id}})
    assert response.status_code == 202, response.text
    monkeypatch.setattr(planner.gateway.InferenceProvider, "complete", lambda *a, **k: pytest.fail("foreign inference"))
    asyncio.run(worker.run_worker(settings, once=True))
    task = store.get_task(settings, "default", "operator", response.json()["task_id"])
    assert task["status"] == "failed"
    assert task["error"] == "operator_source_unavailable"
