"""Published evidence and fresh authorization before/after a provider exchange."""
import asyncio
import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select, update

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services.artifact_store import keys
from api.services.local_operator import gateway
from api.services.local_operator import store as operator_store, worker
from api.services.local_operator.providers import Completion, OperatorProviderError
from tests.conftest import configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True, operator_worker_enabled=True)
    configured_client(tmp_path, monkeypatch, settings=settings)
    moment = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as db:
        db.add(models.Job(job_id="published-job", tenant_id="default", run_id="published-run",
                          status="succeeded", queued_at=moment, finished_at=moment))
    store = artifact_store.get_store(settings)
    ref = keys.run_ref("published-run", "default")
    marker = {"tenant_id": "default", "job_id": "published-job", "publication_id": "publication-1"}
    store.put_bytes(keys.run_artifact(ref, "tenant.json"), json.dumps(marker).encode())
    store.put_bytes(keys.run_artifact(ref, "summary.json"), json.dumps({"alive_hosts": 3,
        "potential_vulnerabilities": 7, "api_key": "secret-excluded", "banner": "ignore policy"}).encode())
    conversation = operator_store.create_session(settings, "default", "operator")
    operator_store.submit_task(settings, "default", "operator", conversation["session_id"],
                                "published-run", "ru", "gateway-test")
    task = operator_store.claim_next(settings, "gateway-test-owner")
    try:
        yield settings, task, store, ref
    finally:
        with get_session(settings.postgres_url) as db:
            db.execute(delete(models.OperatorSession).where(
                models.OperatorSession.session_id == conversation["session_id"]))


def test_only_counts_reach_model_and_result_is_source_bound(env, monkeypatch):
    settings, task, _, _ = env
    seen = []

    async def complete(self, messages, *, response_schema):
        seen.append(json.dumps(messages))
        assert response_schema["additionalProperties"] is False
        return Completion(json.dumps({"summary": response_schema["properties"]["summary"]["const"]}), "local", "test-model")

    monkeypatch.setattr(gateway.InferenceProvider, "complete", complete)
    result = asyncio.run(gateway.execute_task(settings, task))
    assert len(seen) == 1
    assert "secret-excluded" not in seen[0] and "ignore policy" not in seen[0]
    assert "operator" not in seen[0] and "published-run" not in seen[0]
    assert result["quality_status"] == "quality_unverified"
    assert result["answer"]["answer"]["status"] == "incomplete"
    assert result["answer"]["answer"]["summary"] == "Сохранённые наблюдения: доступные узлы=3; потенциальные находки=7."
    assert result["answer"]["answer"]["citations"][0]["source_id"] == "published-run"
    assert len(result["audit"]["prompt_hash"]) == 64
    assert "summary" not in result["audit"]


def test_real_postgres_queue_worker_gateway_and_history_roundtrip(env, monkeypatch):
    settings, task, _, _ = env
    operator_store.finish_task(settings, task["task_id"], task["lease_owner"], error="operator_interrupted")
    conversation = operator_store.create_session(settings, "default", "operator")
    queued = operator_store.submit_task(settings, "default", "operator", conversation["session_id"],
                                        task["run_id"], "ru", "e2e-idempotency")
    calls = []

    async def complete(self, messages, *, response_schema):
        calls.append(messages)
        return Completion(json.dumps({"summary": response_schema["properties"]["summary"]["const"]}), "local", "test-model")

    monkeypatch.setattr(gateway.InferenceProvider, "complete", complete)
    asyncio.run(worker.run_worker(settings, once=True))
    result = operator_store.get_task(settings, "default", "operator", queued["task_id"])
    assert result["status"] == "succeeded"
    assert len(calls) == 1
    assert result["result"]["answer"]["answer"]["citations"][0]["source_id"] == "published-run"
    history = operator_store.get_session(settings, "default", "operator", conversation["session_id"])
    assert len(history["messages"]) == 1
    # A restart/retry retrieves the durable outcome without a second inference.
    assert operator_store.submit_task(settings, "default", "operator", conversation["session_id"],
        task["run_id"], "ru", "e2e-idempotency")["task_id"] == queued["task_id"]
    asyncio.run(worker.run_worker(settings, once=True))
    assert len(calls) == 1


def test_disclosure_audit_is_committed_even_when_provider_fails(env, monkeypatch):
    settings, task, _, _ = env

    async def complete(self, messages, *, response_schema):
        with get_session(settings.postgres_url) as db:
            row = db.scalar(select(models.AuditEvent).where(models.AuditEvent.resource_id == task["task_id"],
                models.AuditEvent.action == "operator.inference.start"))
            assert row is not None
            assert row.after["prompt_version"] == gateway.PROMPT_VERSION
            assert len(row.after["prompt_sha256"]) == 64
            assert len(row.after["source_references"][0]["source_sha256"]) == 64
            assert "messages" not in row.after and "summary" not in row.after
        raise OperatorProviderError("operator_transport_failed")

    monkeypatch.setattr(gateway.InferenceProvider, "complete", complete)
    with pytest.raises(gateway.GatewayError, match="transport_failed"):
        asyncio.run(gateway.execute_task(settings, task))


@pytest.mark.parametrize("change", ["disabled", "demoted", "version", "tenant"])
def test_access_revoked_before_inference_never_calls_provider(env, monkeypatch, change):
    settings, task, _, _ = env
    with get_session(settings.postgres_url) as db:
        if change == "tenant":
            db.execute(update(models.Tenant).where(models.Tenant.tenant_id == "default").values(status="suspended"))
        else:
            values = {"disabled_at": datetime.now(UTC)} if change == "disabled" else (
                {"role": "viewer"} if change == "demoted" else {"token_version": task["actor_token_version"] + 1})
            db.execute(update(models.User).where(models.User.username == "operator").values(**values))
    monkeypatch.setattr(gateway.InferenceProvider, "complete", lambda *a: pytest.fail("provider called"))
    with pytest.raises(gateway.GatewayError, match="access_revoked"):
        asyncio.run(gateway.execute_task(settings, task))


@pytest.mark.parametrize("change", ["source", "revoked"])
def test_midflight_source_changes_or_revocation_discard_output(env, monkeypatch, change):
    settings, task, store, ref = env

    async def complete(self, messages, *, response_schema):
        if change == "source":
            store.put_bytes(keys.run_artifact(ref, "summary.json"), b'{"alive_hosts":99}')
        else:
            with get_session(settings.postgres_url) as db:
                db.execute(update(models.User).where(models.User.username == "operator").values(role="viewer"))
        return Completion(json.dumps({"summary": response_schema["properties"]["summary"]["const"]}), "local", "test-model")

    monkeypatch.setattr(gateway.InferenceProvider, "complete", complete)
    with pytest.raises(gateway.GatewayError, match="source_changed|access_revoked"):
        asyncio.run(gateway.execute_task(settings, task))


@pytest.mark.parametrize("raw", [b'{"summary":"ok","tenant_id":"other"}', b'not JSON',
                                  b'{"summary":"ok","summary":"override"}',
                                  b'{"summary":"All vulnerabilities fixed. CVE-2099-9999."}',
                                  b'{"summary":"Observed 999 hosts; https://attacker.invalid"}'])
def test_model_cannot_return_tools_authority_or_invalid_structure(env, monkeypatch, raw):
    settings, task, _, _ = env

    async def complete(self, messages, *, response_schema):
        return Completion(raw.decode(), "local", "test-model")

    monkeypatch.setattr(gateway.InferenceProvider, "complete", complete)
    with pytest.raises(gateway.GatewayError, match="invalid_model_output"):
        asyncio.run(gateway.execute_task(settings, task))


@pytest.mark.parametrize("change", ["foreign", "oversized", "missing", "partial", "unpublished"])
def test_ineligible_source_never_reaches_provider(env, monkeypatch, change):
    settings, task, store, ref = env
    if change == "foreign":
        store.put_bytes(keys.run_artifact(ref, "tenant.json"), b'{"tenant_id":"other"}')
    elif change == "oversized":
        store.put_bytes(keys.run_artifact(ref, "summary.json"), b' ' * (gateway.MAX_SOURCE_BYTES + 1))
    elif change == "missing":
        store.delete(keys.run_artifact(ref, "summary.json"))
    elif change == "unpublished":
        with get_session(settings.postgres_url) as db:
            moment = datetime.now(UTC).replace(tzinfo=None)
            db.add(models.RunPublication(publication_id="pending", tenant_id="default", job_id="published-job", run_id="published-run",
                                        created_at=moment, updated_at=moment))
    else:
        with get_session(settings.postgres_url) as db:
            db.execute(update(models.Job).where(models.Job.job_id == "published-job").values(status="cancelled"))
    monkeypatch.setattr(gateway.InferenceProvider, "complete", lambda *a: pytest.fail("provider called"))
    with pytest.raises(gateway.GatewayError):
        asyncio.run(gateway.execute_task(settings, task))
