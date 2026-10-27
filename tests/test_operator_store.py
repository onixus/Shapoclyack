"""Durable queue lifecycle, tenant isolation and real PostgreSQL serialization."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from threading import Barrier
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, event, select
from sqlalchemy.orm import Session

from api.db.models import (
    AuditEvent,
    OperatorExecution,
    OperatorMessage,
    OperatorProposal,
    OperatorSession,
    OperatorTask,
    Tenant,
    TenantLegalHold,
    User,
)
from api.services.local_operator import store
from tests.conftest import POSTGRES_URL


@pytest.fixture(params=["sqlite", "postgres"])
def env(request, monkeypatch, tmp_path):
    postgres = request.param == "postgres"
    if postgres and not POSTGRES_URL:
        pytest.skip("OCTO_POSTGRES_URL required for authoritative store locking tests")
    settings = SimpleNamespace(
        postgres_url=POSTGRES_URL if postgres else "sqlite", operator_queue_limit=20
    )
    tenant = "operator-test-" + uuid4().hex
    username = "operator-user-" + uuid4().hex
    engine = None
    if not postgres:
        engine = create_engine(f"sqlite:///{tmp_path / 'operator.db'}")

        @event.listens_for(engine, "connect")
        def foreign_keys(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")

        for model in (
            Tenant,
            User,
            TenantLegalHold,
            OperatorSession,
            OperatorMessage,
            OperatorTask,
            OperatorProposal,
            OperatorExecution,
        ):
            model.__table__.create(engine)

        @contextmanager
        def transaction(_url):
            with Session(engine) as db:
                yield db
                db.commit()

        monkeypatch.setattr(store, "get_session_db", transaction)
        # Audit persistence itself requires migrated PostgreSQL trigger contracts.
        monkeypatch.setattr(store, "_audit", lambda *a: None)
    transaction = store.get_session_db
    now = datetime.now(UTC)
    with transaction(settings.postgres_url) as db:
        db.add(Tenant(tenant_id=tenant, name=tenant, created_at=now))
        db.add(
            User(
                username=username,
                password_hash="",
                created_at=now,
                updated_at=now,
                token_version=7,
            )
        )
    try:
        yield settings, tenant, username, transaction
    finally:
        with transaction(settings.postgres_url) as db:
            db.execute(
                delete(TenantLegalHold).where(TenantLegalHold.tenant_id == tenant)
            )
            db.execute(delete(Tenant).where(Tenant.tenant_id == tenant))
            db.execute(delete(User).where(User.username == username))
        if engine:
            engine.dispose()


def session_and_task(env, key="one"):
    settings, tenant, username, _ = env
    conversation = store.create_session(settings, tenant, username)
    task = store.submit_task(
        settings, tenant, username, conversation["session_id"], "run-1", "ru", key
    )
    return conversation, task


def test_personal_isolation_idempotency_and_restart(env):
    settings, tenant, username, transaction = env
    conversation, task = session_and_task(env)
    sid = conversation["session_id"]
    assert (
        store.submit_task(settings, tenant, username, sid, "run-1", "ru", "one") == task
    )
    with pytest.raises(store.OperatorStoreError, match="idempotency_conflict"):
        store.submit_task(settings, tenant, username, sid, "run-2", "ru", "one")
    for t, u in ((tenant, "missing-" + uuid4().hex), ("other", username)):
        assert store.get_session(settings, t, u, sid) is None
        assert store.get_task(settings, t, u, task["task_id"]) is None
        if t == tenant:
            with pytest.raises(store.OperatorStoreError, match="access_revoked"):
                store.cancel_task(settings, t, u, task["task_id"])
        assert store.list_sessions(settings, t, u)["items"] == []
    # A new settings object/process has exactly the persisted state.
    again = SimpleNamespace(postgres_url=settings.postgres_url)
    assert (
        store.get_session(again, tenant, username, sid)["tasks"][0]["task_id"]
        == task["task_id"]
    )
    with transaction(settings.postgres_url) as db:
        assert db.get(OperatorTask, task["task_id"]).actor_token_version == 7


def test_cancel_retains_running_slot_and_fences_finish(env):
    settings, tenant, username, _ = env
    _, task = session_and_task(env)
    claimed = store.claim_next(settings, "owner")
    assert claimed["task_id"] == task["task_id"]
    assert claimed["actor_token_version"] == 7
    assert not store.finish_task(
        settings, task["task_id"], "impostor", result={"answer": "bad"}
    )
    cancelled = store.cancel_task(settings, tenant, username, task["task_id"])
    assert cancelled["status"] == "running" and cancelled["cancel_requested"]
    assert store.claim_next(settings, "other") is None
    assert store.is_cancel_requested(settings, task["task_id"], "owner")
    assert store.finish_task(
        settings, task["task_id"], "owner", result={"answer": "late"}
    )
    saved = store.get_task(settings, tenant, username, task["task_id"])
    assert saved["status"] == "cancelled" and saved["result"] is None
    assert (
        store.get_session(settings, tenant, username, task["session_id"])["messages"]
        == []
    )


def test_expiry_interrupts_without_replay_or_late_owner_result(env):
    settings, tenant, username, transaction = env
    _, task = session_and_task(env)
    store.claim_next(settings, "old")
    with transaction(settings.postgres_url) as db:
        db.get(OperatorTask, task["task_id"]).lease_until = datetime.now(UTC).replace(
            tzinfo=None
        ) - timedelta(seconds=1)
    assert store.is_cancel_requested(settings, task["task_id"], "old")
    assert store.claim_next(settings, "new") is None
    assert store.recover_expired(settings) == 1
    assert not store.finish_task(
        settings, task["task_id"], "old", result={"late": True}
    )
    assert store.claim_next(settings, "new") is None
    assert (
        store.get_task(settings, tenant, username, task["task_id"])["status"]
        == "interrupted"
    )


def test_delete_refuses_active_and_legal_hold_and_cascades(env):
    settings, tenant, username, transaction = env
    conversation, task = session_and_task(env)
    sid = conversation["session_id"]
    with pytest.raises(store.OperatorStoreError, match="active_tasks"):
        store.delete_session(settings, tenant, username, sid)
    store.cancel_task(settings, tenant, username, task["task_id"])
    with transaction(settings.postgres_url) as db:
        db.add(
            TenantLegalHold(
                tenant_id=tenant,
                reason="test",
                set_by="system",
                set_at=datetime.now(UTC),
            )
        )
    with pytest.raises(store.OperatorStoreError, match="legal_hold"):
        store.delete_session(settings, tenant, username, sid)
    with transaction(settings.postgres_url) as db:
        db.execute(delete(TenantLegalHold).where(TenantLegalHold.tenant_id == tenant))
    assert store.delete_session(settings, tenant, username, sid)
    assert store.get_task(settings, tenant, username, task["task_id"]) is None


def test_success_is_durable_and_audit_records_actor_without_raw_result(env):
    settings, tenant, username, transaction = env
    _, task = session_and_task(env)
    store.claim_next(settings, "worker")
    assert store.finish_task(
        settings, task["task_id"], "worker", result={"answer": "private-output"}
    )
    assert (
        store.get_task(settings, tenant, username, task["task_id"])["status"]
        == "succeeded"
    )
    messages = store.get_session(settings, tenant, username, task["session_id"])[
        "messages"
    ]
    assert len(messages) == 1 and "private-output" in messages[0]["content"]
    if settings.postgres_url != "sqlite":
        with transaction(settings.postgres_url) as db:
            rows = db.scalars(
                select(AuditEvent).where(AuditEvent.tenant_id == tenant)
            ).all()
            assert len(rows) == 4
            assert all(row.actor == username for row in rows)
            assert all("private-output" not in str(row.after) for row in rows)


def test_pg_concurrent_idempotency_admission_and_global_claim(env):
    settings, tenant, username, _ = env
    if settings.postgres_url == "sqlite":
        pytest.skip("Concurrency acceptance requires PostgreSQL row/advisory locks")
    sid = store.create_session(settings, tenant, username)["session_id"]
    settings.operator_queue_limit = 1
    gate = Barrier(6)

    def submit(index):
        gate.wait(timeout=10)
        try:
            return store.submit_task(
                settings, tenant, username, sid, "run", "en", f"key-{index}"
            )
        except store.OperatorStoreError as exc:
            assert exc.code == "queue_full"
            return None

    with ThreadPoolExecutor(6) as pool:
        admitted = [row for row in pool.map(submit, range(6)) if row]
    assert len(admitted) == 1
    gate = Barrier(6)

    def claim(index):
        gate.wait(timeout=10)
        return store.claim_next(settings, f"worker-{index}")

    with ThreadPoolExecutor(6) as pool:
        claimed = [row for row in pool.map(claim, range(6)) if row]
    assert len(claimed) == 1
    assert store.finish_task(
        settings, claimed[0]["task_id"], claimed[0]["lease_owner"], result={}
    )
    gate = Barrier(6)

    def replay(_index):
        gate.wait(timeout=10)
        return store.submit_task(
            settings, tenant, username, sid, "run", "en", "same-key"
        )

    with ThreadPoolExecutor(6) as pool:
        replayed = list(pool.map(replay, range(6)))
    assert len({row["task_id"] for row in replayed}) == 1


def test_claims_are_round_robin_between_tenants_not_global_fifo(env):
    settings, tenant, username, transaction = env
    flooder = store.create_session(settings, tenant, username)["session_id"]
    queued = [store.submit_task(settings, tenant, username, flooder, f"run-{i}", "ru", f"flood-{i}")
              for i in range(4)]
    second_tenant = "operator-second-" + uuid4().hex
    with transaction(settings.postgres_url) as db:
        db.add(Tenant(tenant_id=second_tenant, name=second_tenant, created_at=datetime.now(UTC)))
    try:
        sid = store.create_session(settings, second_tenant, username)["session_id"]
        victim = store.submit_task(settings, second_tenant, username, sid, "run-v", "en", "victim")
        order = []
        for index in range(5):
            claimed = store.claim_next(settings, f"owner-{index}")
            assert claimed is not None
            order.append(claimed["task_id"])
            assert store.finish_task(settings, claimed["task_id"], claimed["lease_owner"], result={})
        # The other tenant gets the second slot, not the fifth; each tenant stays FIFO.
        assert order == [queued[0]["task_id"], victim["task_id"], queued[1]["task_id"],
                         queued[2]["task_id"], queued[3]["task_id"]]
    finally:
        with transaction(settings.postgres_url) as db:
            db.execute(delete(Tenant).where(Tenant.tenant_id == second_tenant))


def test_pg_one_running_slot_across_distinct_tenants(env):
    settings, tenant, username, transaction = env
    if settings.postgres_url == "sqlite":
        pytest.skip("Global-slot acceptance requires PostgreSQL advisory locks")
    _, first = session_and_task(env)
    second_tenant = "operator-second-" + uuid4().hex
    with transaction(settings.postgres_url) as db:
        db.add(
            Tenant(
                tenant_id=second_tenant,
                name=second_tenant,
                created_at=datetime.now(UTC),
            )
        )
    try:
        sid = store.create_session(settings, second_tenant, username)["session_id"]
        second = store.submit_task(
            settings, second_tenant, username, sid, "run-2", "en", "two"
        )
        gate = Barrier(2)

        def claim(owner):
            gate.wait(timeout=10)
            return store.claim_next(settings, owner)

        with ThreadPoolExecutor(2) as pool:
            claimed = [row for row in pool.map(claim, ("alpha", "beta")) if row]
        assert len(claimed) == 1
        winner = claimed[0]
        assert winner["task_id"] in {first["task_id"], second["task_id"]}
        assert store.claim_next(settings, "third") is None
        assert store.finish_task(
            settings, winner["task_id"], winner["lease_owner"], result={}
        )
        following = store.claim_next(settings, "third")
        assert following is not None and following["tenant_id"] != winner["tenant_id"]
        assert store.finish_task(settings, following["task_id"], "third", result={})
    finally:
        with transaction(settings.postgres_url) as db:
            db.execute(delete(Tenant).where(Tenant.tenant_id == second_tenant))
