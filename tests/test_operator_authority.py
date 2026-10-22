"""Held console requests must use current grants without dropping tenant RLS."""
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import delete, select, text, update

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services.local_operator import store
from api.services.runs import write_run_tenant
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres
READS = ("list_sessions", "get_session", "get_task")
WRITES = ("create_session", "submit_task", "cancel_task", "delete_session")


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True, operator_worker_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin, operator = auth_headers(client, "admin"), auth_headers(client, "operator")
    assert client.post("/api/tenants", headers=admin, json={
        "tenant_id": "acme", "name": "Acme"}).status_code == 201
    assert client.put("/api/tenants/acme/members/operator", headers=admin,
                      json={"role": "operator"}).status_code == 200
    sessions = []
    for _ in range(2):
        response = client.post("/api/operator/sessions?tenant_id=acme", headers=operator, json={})
        assert response.status_code == 201, response.text
        sessions.append(response.json()["session_id"])
    with tenant_scope.system("operator authority fixture"):
        task = store.submit_task(settings, "acme", "operator", sessions[1], "authority-run", "en", "initial")
        with get_session(settings.postgres_url) as db:
            db.add(models.OperatorMessage(message_id=uuid4().hex, tenant_id="acme", username="operator",
                session_id=sessions[0], task_id=task["task_id"], role="assistant",
                content="confidential-history-marker", created_at=datetime.now(UTC).replace(tzinfo=None)))
    (settings.output_dir / "runs" / "authority-run").mkdir(parents=True)
    assert write_run_tenant(settings, "authority-run", "acme")
    return client, settings, operator, sessions, task


def _request(env, action, *, tenant="acme", headers=None):
    client, _, operator, sessions, task = env
    headers = headers or operator
    suffix = f"?tenant_id={tenant}"
    base = "/api/operator"
    if action == "list_sessions":
        return client.get(base + "/sessions" + suffix, headers=headers)
    if action == "get_session":
        return client.get(base + f"/sessions/{sessions[0]}" + suffix, headers=headers)
    if action == "get_task":
        return client.get(base + f"/tasks/{task['task_id']}" + suffix, headers=headers)
    if action == "create_session":
        return client.post(base + "/sessions" + suffix, headers=headers, json={})
    if action == "submit_task":
        return client.post(base + f"/sessions/{sessions[1]}/tasks" + suffix,
            headers={**headers, "Idempotency-Key": "held-request"},
            json={"tool": "summarize_run", "run_id": "authority-run", "language": "en"})
    if action == "cancel_task":
        return client.post(base + f"/tasks/{task['task_id']}/cancel" + suffix, headers=headers)
    return client.delete(base + f"/sessions/{sessions[0]}" + suffix, headers=headers)


def _state(settings):
    with tenant_scope.system("operator authority side-effect inspection"), get_session(settings.postgres_url) as db:
        return (
            tuple(db.scalars(select(models.OperatorSession.session_id).order_by(models.OperatorSession.session_id))),
            tuple(db.execute(select(models.OperatorTask.task_id, models.OperatorTask.status,
                                    models.OperatorTask.cancel_requested).order_by(models.OperatorTask.task_id)).all()),
            tuple(db.scalars(select(models.AuditEvent.id).where(
                models.AuditEvent.action.like("operator.%")).order_by(models.AuditEvent.id))),
        )


@pytest.mark.parametrize("action", READS + WRITES)
def test_all_personal_actions_recheck_committed_grant_changes(env, monkeypatch, action):
    _, settings, _, _, _ = env
    original = getattr(store, action)
    before = _state(settings)

    def interleave(*args, **kwargs):
        assert kwargs["auth_session_id"]
        with tenant_scope.system("held operator authority regression"), get_session(settings.postgres_url) as db:
            statement = (delete(models.UserTenant) if action in READS
                         else update(models.UserTenant).values(role="viewer"))
            db.execute(statement.where(models.UserTenant.username == "operator", models.UserTenant.tenant_id == "acme"))
        return original(*args, **kwargs)

    monkeypatch.setattr(store, action, interleave)
    response = _request(env, action)
    assert response.status_code == 403, response.text
    assert "confidential-history-marker" not in response.text
    assert _state(settings) == before


@pytest.mark.parametrize("action", READS)
def test_other_membership_cannot_resurrect_default_fallback(env, monkeypatch, action):
    client, settings, operator, _, _ = env
    admin = auth_headers(client, "admin")
    assert client.put("/api/tenants/default/members/operator", headers=admin,
                      json={"role": "operator"}).status_code == 200
    original = getattr(store, action)

    def interleave(*args, **kwargs):
        with tenant_scope.system("held default authority regression"), get_session(settings.postgres_url) as db:
            db.execute(delete(models.UserTenant).where(models.UserTenant.username == "operator",
                                                       models.UserTenant.tenant_id == "default"))
        return original(*args, **kwargs)

    monkeypatch.setattr(store, action, interleave)
    assert _request(env, action, tenant="default", headers=operator).status_code == 403


@pytest.mark.parametrize("action", WRITES)
def test_custom_role_demotion_rechecked(env, monkeypatch, action):
    _, settings, _, _, _ = env
    with tenant_scope.system("custom operator role fixture"), get_session(settings.postgres_url) as db:
        db.add(models.RoleDefinition(tenant_id="acme", role_id="analysis-operator", rank=2,
                                     created_at=datetime.now(UTC).replace(tzinfo=None)))
        db.execute(update(models.UserTenant).where(models.UserTenant.username == "operator",
            models.UserTenant.tenant_id == "acme").values(role="analysis-operator"))
    original = getattr(store, action)
    before = _state(settings)

    def interleave(*args, **kwargs):
        with tenant_scope.system("held custom role demotion"), get_session(settings.postgres_url) as db:
            db.execute(update(models.RoleDefinition).where(models.RoleDefinition.tenant_id == "acme",
                models.RoleDefinition.role_id == "analysis-operator").values(rank=1))
        return original(*args, **kwargs)

    monkeypatch.setattr(store, action, interleave)
    assert _request(env, action).status_code == 403
    assert _state(settings) == before


@pytest.mark.parametrize("role,rank", [("scan-operator", 2), ("analysis-operator", 2),
                                     ("auditor", 1), ("deleted-role", 1)])
def test_current_builtin_and_custom_role_contracts_remain(env, role, rank):
    _, settings, _, _, _ = env
    with tenant_scope.system("operator role compatibility"), get_session(settings.postgres_url) as db:
        if role == "analysis-operator":
            db.add(models.RoleDefinition(tenant_id="acme", role_id=role, rank=rank,
                                         created_at=datetime.now(UTC).replace(tzinfo=None)))
        db.execute(update(models.UserTenant).where(models.UserTenant.username == "operator",
            models.UserTenant.tenant_id == "acme").values(role=role))
    assert _request(env, "get_session").status_code == 200
    assert _request(env, "create_session").status_code == (201 if rank >= 2 else 403)


def test_authority_lookup_keeps_rls_for_personal_data(env, monkeypatch):
    original_db = store._personal_db
    from contextlib import contextmanager

    @contextmanager
    def inspect_db(*args, **kwargs):
        with original_db(*args, **kwargs) as db:
            assert db.scalar(text("SELECT current_user")) == tenant_scope.TENANT_ROLE
            assert db.scalar(text("SELECT current_setting('shapoclyack.tenant_id')")) == "acme"
            assert set(db.scalars(select(models.Tenant.tenant_id))) == {"acme"}
            yield db

    monkeypatch.setattr(store, "_personal_db", inspect_db)
    assert _request(env, "get_session").status_code == 200


def test_global_admin_and_no_membership_default_fallback_remain(env):
    client, settings, operator, _, _ = env
    admin = auth_headers(client, "admin")
    assert _request(env, "create_session", headers=admin).status_code == 201
    with tenant_scope.system("operator default fallback compatibility"), get_session(settings.postgres_url) as db:
        db.execute(delete(models.UserTenant).where(models.UserTenant.username == "operator"))
    assert _request(env, "create_session", tenant="default", headers=operator).status_code == 201
