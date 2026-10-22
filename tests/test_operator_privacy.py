"""PostgreSQL privacy lifecycle for personal AI state, including departed users."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import delete, func, select

from api.db import models
from api.db.engine import get_session
from api.services import data_subject, legal_hold
from api.services.local_operator import store
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def privacy_env(tmp_path):
    settings = make_settings(tmp_path)
    tenant = "operator-privacy-" + uuid4().hex
    owners = ["privacy-" + uuid4().hex for _ in range(2)]
    now = datetime.now(UTC).replace(tzinfo=None)
    sessions = {}
    with get_session(settings.postgres_url) as db:
        db.add(models.Tenant(tenant_id=tenant, name=tenant, created_at=now))
        for username in owners:
            db.add(
                models.User(
                    username=username,
                    email=username + "@test.invalid",
                    created_at=now,
                    updated_at=now,
                )
            )
        db.flush()
        for username in owners:
            sid, tid, pid = uuid4().hex, uuid4().hex, uuid4().hex
            sessions[username] = (sid, tid)
            db.add(
                models.OperatorSession(
                    session_id=sid,
                    tenant_id=tenant,
                    username=username,
                    created_at=now,
                    updated_at=now,
                )
            )
            db.flush()
            db.add(
                models.OperatorTask(
                    task_id=tid,
                    tenant_id=tenant,
                    username=username,
                    session_id=sid,
                    run_id="run-private",
                    language="ru",
                    idempotency_key="idem",
                    status="running",
                    lease_owner="provider",
                    lease_until=now + timedelta(minutes=10),
                    created_at=now,
                    updated_at=now,
                )
            )
            db.add(
                models.OperatorMessage(
                    message_id=uuid4().hex,
                    tenant_id=tenant,
                    username=username,
                    session_id=sid,
                    task_id=tid,
                    role="assistant",
                    content="personal-" + username,
                    created_at=now,
                )
            )
            db.add(
                models.OperatorProposal(
                    proposal_id=pid,
                    tenant_id=tenant,
                    username=username,
                    session_id=sid,
                    payload={"personal": username},
                    status="reserved",
                    created_at=now,
                )
            )
            db.flush()
            db.add(
                models.OperatorExecution(
                    execution_id=uuid4().hex,
                    tenant_id=tenant,
                    username=username,
                    proposal_id=pid,
                    status="reserved",
                    created_at=now,
                )
            )
    try:
        yield settings, tenant, owners, sessions
    finally:
        with get_session(settings.postgres_url) as db:
            db.execute(
                delete(models.TenantLegalHold).where(
                    models.TenantLegalHold.tenant_id == tenant
                )
            )
            db.execute(delete(models.Tenant).where(models.Tenant.tenant_id == tenant))
            db.execute(delete(models.User).where(models.User.username.in_(owners)))


def test_export_includes_only_subject_operator_data(privacy_env):
    settings, tenant, owners, sessions = privacy_env
    subject, other = owners
    document = data_subject.export_user(settings, subject)
    operator = document["operator"]
    assert set(operator) == {"sessions", "messages", "tasks", "proposals", "executions"}
    assert all(len(rows) == 1 for rows in operator.values())
    assert operator["sessions"][0]["session_id"] == sessions[subject][0]
    assert operator["messages"][0]["content"] == "personal-" + subject
    assert all(
        row["tenant_id"] == tenant and row["username"] == subject
        for rows in operator.values()
        for row in rows
    )
    assert other not in str(operator)
    assert "lease_owner" not in operator["tasks"][0]
    assert "actor_token_version" not in operator["tasks"][0]


def test_erasure_cascades_running_work_and_preserves_other_owner(privacy_env):
    settings, _, owners, sessions = privacy_env
    subject, other = owners
    result = data_subject.erase_user(settings, subject, requested_by="privacy-admin")
    assert result["removed"]["operator_sessions"] == 1
    task_id = sessions[subject][1]
    assert store.is_cancel_requested(settings, task_id, "provider")
    assert not store.finish_task(settings, task_id, "provider", result={"late": True})
    with get_session(settings.postgres_url) as db:
        for model in (
            models.OperatorSession,
            models.OperatorMessage,
            models.OperatorTask,
            models.OperatorProposal,
            models.OperatorExecution,
        ):
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.username == subject)
                )
                == 0
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.username == other)
                )
                == 1
            )
        assert db.get(models.User, subject).erased_at is not None
        assert db.get(models.User, other).erased_at is None


def test_legal_hold_preserves_departed_owner_even_without_actor_audit(privacy_env):
    settings, tenant, owners, sessions = privacy_env
    subject = owners[0]
    with get_session(settings.postgres_url) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(models.UserTenant)
                .where(models.UserTenant.username == subject)
            )
            == 0
        )
        assert (
            db.scalar(
                select(func.count())
                .select_from(models.AuditEvent)
                .where(models.AuditEvent.actor == subject)
            )
            == 0
        )
        db.add(
            models.TenantLegalHold(
                tenant_id=tenant,
                reason="preserve personal AI state",
                set_by="privacy-admin",
                set_at=datetime.now(UTC),
            )
        )
    with pytest.raises(legal_hold.LegalHoldActive):
        data_subject.erase_user(settings, subject, requested_by="privacy-admin")
    with get_session(settings.postgres_url) as db:
        assert db.get(models.OperatorSession, sessions[subject][0]) is not None
        assert db.get(models.OperatorTask, sessions[subject][1]).status == "running"
        assert db.get(models.User, subject).erased_at is None


def test_operator_export_refuses_overflow_without_partial_audit(
    privacy_env, monkeypatch
):
    settings, _, owners, _ = privacy_env
    monkeypatch.setattr(data_subject, "OPERATOR_EXPORT_LIMIT", 0)
    with pytest.raises(data_subject.ExportTooSlow, match="bounded record limit"):
        data_subject.export_user(settings, owners[0])
    with get_session(settings.postgres_url) as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(models.AuditEvent)
                .where(
                    models.AuditEvent.action == "user.export",
                    models.AuditEvent.resource_id == owners[0],
                )
            )
            == 0
        )


def test_hard_delete_then_recreate_cannot_inherit_old_operator_state(privacy_env):
    from api.services import users

    settings, tenant, owners, sessions = privacy_env
    subject, other = owners
    users.configure(settings)
    assert users.delete_user(subject)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as db:
        db.add(models.User(username=subject, created_at=now, updated_at=now))
    sid, tid = sessions[subject]
    assert store.get_session(settings, tenant, subject, sid) is None
    assert store.is_cancel_requested(settings, tid, "provider")
    with get_session(settings.postgres_url) as db:
        for model in (
            models.OperatorSession,
            models.OperatorMessage,
            models.OperatorTask,
            models.OperatorProposal,
            models.OperatorExecution,
        ):
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.username == subject)
                )
                == 0
            )
            assert (
                db.scalar(
                    select(func.count())
                    .select_from(model)
                    .where(model.username == other)
                )
                == 1
            )


def test_hard_delete_refuses_held_operator_session_and_preserves_user(privacy_env):
    from api.services import users

    settings, tenant, owners, sessions = privacy_env
    subject = owners[0]
    users.configure(settings)
    with get_session(settings.postgres_url) as db:
        db.add(
            models.TenantLegalHold(
                tenant_id=tenant,
                reason="preserve old operator work",
                set_by="privacy-admin",
                set_at=datetime.now(UTC),
            )
        )
    with pytest.raises(legal_hold.LegalHoldActive):
        users.delete_user(subject)
    with get_session(settings.postgres_url) as db:
        assert db.get(models.User, subject) is not None
        assert db.get(models.OperatorSession, sessions[subject][0]) is not None


def test_delete_api_answers_conflict_for_held_operator_history(privacy_env):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.auth import Role, TokenUser
    from api.routes import users as routes
    from api.services import users

    settings, tenant, owners, sessions = privacy_env
    subject, admin = owners
    users.configure(settings)
    with get_session(settings.postgres_url) as db:
        account = db.get(models.User, admin)
        account.role, account.password_hash = "admin", "hash"
        db.add(
            models.TenantLegalHold(
                tenant_id=tenant,
                reason="held AI history",
                set_by=admin,
                set_at=datetime.now(UTC),
            )
        )
    app = FastAPI()
    app.add_api_route(
        "/api/users/{username}", routes.delete_user, methods=["DELETE"], status_code=204
    )
    # Exercise the real endpoint and real account/store transaction while
    # supplying its already-authenticated administrator and step-up context.
    endpoint = next(
        route for route in app.routes if getattr(route, "name", None) == "delete_user"
    )
    for dependency in endpoint.dependant.dependencies:
        if dependency.name == "admin":
            app.dependency_overrides[dependency.call] = lambda: TokenUser(
                username=admin, role=Role.admin
            )
        else:
            app.dependency_overrides[dependency.call] = lambda: None
    with TestClient(app) as client:
        response = client.delete(f"/api/users/{subject}")
    assert response.status_code == 409, response.text
    assert "legal hold" in response.json()["detail"]
    with get_session(settings.postgres_url) as db:
        assert db.get(models.User, subject) is not None
        assert db.get(models.OperatorSession, sessions[subject][0]) is not None


def test_late_authenticated_create_cannot_survive_delete_and_name_reuse(
    privacy_env, monkeypatch
):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from api.services import users

    settings, tenant, owners, _ = privacy_env
    subject = owners[0]
    users.configure(settings)
    sid = uuid4().hex
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as db:
        db.add(
            models.SessionFamily(
                family_id=sid,
                username=subject,
                token_version=0,
                created_at=now,
                last_used_at=now,
                expires_at=now + timedelta(hours=1),
            )
        )
    reached, proceed = Event(), Event()
    original = store._lock_actor

    def delayed_check(*args, **kwargs):
        reached.set()
        assert proceed.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "_lock_actor", delayed_check)

    def late_create():
        with pytest.raises(store.OperatorStoreError, match="access_revoked"):
            store.create_session(settings, tenant, subject, auth_session_id=sid)

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(late_create)
        assert reached.wait(10)
        try:
            assert users.delete_user(subject)
            with get_session(settings.postgres_url) as db:
                db.add(models.User(username=subject, created_at=now, updated_at=now))
        finally:
            proceed.set()
        future.result(timeout=10)
    assert store.list_sessions(settings, tenant, subject)["total"] == 0


@pytest.mark.parametrize(
    "invalid", ["missing", "revoked", "expired", "version", "owner", "idle"]
)
def test_mutations_refuse_stale_console_session_family(privacy_env, invalid):
    settings, tenant, owners, sessions = privacy_env
    subject, other = owners
    sid = uuid4().hex
    now = datetime.now(UTC).replace(tzinfo=None)
    if invalid != "missing":
        with get_session(settings.postgres_url) as db:
            db.add(
                models.SessionFamily(
                    family_id=sid,
                    username=other if invalid == "owner" else subject,
                    token_version=1 if invalid == "version" else 0,
                    created_at=now,
                    last_used_at=now - timedelta(days=1) if invalid == "idle" else now,
                    expires_at=now - timedelta(seconds=1)
                    if invalid == "expired"
                    else now + timedelta(hours=1),
                    revoked_at=now if invalid == "revoked" else None,
                )
            )
    conversation_id, task_id = sessions[subject]
    operations = [
        lambda: store.create_session(settings, tenant, subject, auth_session_id=sid),
        lambda: store.submit_task(
            settings,
            tenant,
            subject,
            conversation_id,
            "run",
            "ru",
            "new-key",
            auth_session_id=sid,
        ),
        lambda: store.cancel_task(
            settings, tenant, subject, task_id, auth_session_id=sid
        ),
        lambda: store.delete_session(
            settings, tenant, subject, conversation_id, auth_session_id=sid
        ),
    ]
    operations.extend(
        [
            lambda: store.list_sessions(settings, tenant, subject, auth_session_id=sid),
            lambda: store.get_session(
                settings, tenant, subject, conversation_id, auth_session_id=sid
            ),
            lambda: store.get_task(
                settings, tenant, subject, task_id, auth_session_id=sid
            ),
        ]
    )
    for operation in operations:
        with pytest.raises(store.OperatorStoreError, match="access_revoked"):
            operation()
    assert store.get_task(settings, tenant, subject, task_id)["status"] == "running"
