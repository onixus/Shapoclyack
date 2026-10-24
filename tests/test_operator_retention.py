"""History follows tenant run windows and preserves held/active records."""
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from api.db import models
from api.db.engine import get_session
from api.services.local_operator import retention, store
from tests.conftest import configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, run_retention_days=30)
    configured_client(tmp_path, monkeypatch, settings=settings)
    session = store.create_session(settings, "default", "operator")
    old = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=60)
    with get_session(settings.postgres_url) as db:
        db.execute(update(models.OperatorSession).where(models.OperatorSession.session_id == session["session_id"]).values(updated_at=old))
    return settings, session["session_id"], old


def test_expired_inactive_history_is_removed(env):
    settings, session_id, _ = env
    assert retention.sweep(settings) == 1
    assert store.get_session(settings, "default", "operator", session_id) is None


def test_legal_hold_blocks_expiration(env):
    settings, session_id, old = env
    with get_session(settings.postgres_url) as db:
        db.add(models.TenantLegalHold(tenant_id="default", set_by="admin", set_at=old, reason="test"))
    try:
        assert retention.sweep(settings) == 0
        assert store.get_session(settings, "default", "operator", session_id)
    finally:
        with get_session(settings.postgres_url) as db:
            db.query(models.TenantLegalHold).delete()


def test_active_task_keeps_old_session(env):
    settings, session_id, old = env
    store.submit_task(settings, "default", "operator", session_id, "run-1", "en", "active-key")
    with get_session(settings.postgres_url) as db:
        db.execute(update(models.OperatorSession).where(models.OperatorSession.session_id == session_id).values(updated_at=old))
    assert retention.sweep(settings) == 0
    assert store.get_session(settings, "default", "operator", session_id)


@pytest.mark.parametrize("status", ["executing", "unknown"])
def test_unreconciled_effect_preserves_old_session(env, status):
    settings, session_id, old = env
    with get_session(settings.postgres_url) as db:
        db.add(models.OperatorProposal(proposal_id="retention-proposal", tenant_id="default",
            username="operator", session_id=session_id, payload={}, status=status, created_at=old))
    assert retention.sweep(settings) == 0
    with get_session(settings.postgres_url) as db:
        assert db.get(models.OperatorProposal, "retention-proposal").status == status


def test_per_tenant_keep_policy_is_used(env):
    settings, session_id, _ = env
    with get_session(settings.postgres_url) as db:
        db.add(models.TenantRetentionPolicy(tenant_id="default", run_days=120,
            updated_at=datetime.now(UTC).replace(tzinfo=None), updated_by="admin"))
    assert retention.sweep(settings) == 0
    assert store.get_session(settings, "default", "operator", session_id)


def test_evidence_cleanup_runs_bounded_without_changing_session_count(env, monkeypatch):
    settings, session_id, _ = env
    calls = []

    def prune(settings_arg, *, limit):
        assert settings_arg is settings
        calls.append(limit)
        return 17

    monkeypatch.setattr(retention.retrieval, "prune_invalid", prune)
    assert retention.sweep(settings, limit=100) == 1
    assert store.get_session(settings, "default", "operator", session_id) is None
    assert calls == [20]
    assert retention.sweep(settings, limit=100) == 0
    assert calls == [20, 20]


@pytest.mark.parametrize("blocker", ["suspended", "queued", "running"])
def test_skipped_old_sessions_do_not_starve_eligible_history(env, blocker):
    settings, eligible, old = env
    settings.operator_queue_limit = 100
    count = 1 if blocker == "running" else 21
    limit = 1 if blocker == "running" else 20
    older = old - timedelta(days=1)
    with get_session(settings.postgres_url) as db:
        db.add(models.Tenant(tenant_id="blocked", name="Blocked", created_at=older,
                            status="suspended" if blocker == "suspended" else "active"))
        db.flush()
        for index in range(count):
            session_id = f"blocked-{index}"
            db.add(models.OperatorSession(session_id=session_id, tenant_id="blocked", username="operator",
                                           created_at=older, updated_at=older))
            db.flush()
            if blocker != "suspended":
                db.add(models.OperatorTask(task_id=f"task-{index}", tenant_id="blocked", username="operator",
                    session_id=session_id, actor_token_version=0, kind="summarize_run", run_id="run-1",
                    language="en", idempotency_key=f"blocked-{index}", status=blocker,
                    cancel_requested=False, created_at=older, updated_at=older))
    assert retention.sweep(settings, limit=limit) == 1
    assert store.get_session(settings, "default", "operator", eligible) is None
    with get_session(settings.postgres_url) as db:
        assert len(list(db.scalars(select(models.OperatorSession.session_id).where(
            models.OperatorSession.tenant_id == "blocked")))) == count
    assert retention.sweep(settings) == 0


@pytest.mark.parametrize("change", ["queued", "hold", "policy"])
def test_expiry_rechecks_protection_after_candidate_selection(env, monkeypatch, change):
    settings, session_id, old = env
    original = retention.get_session
    calls = 0

    @contextmanager
    def interleave(url):
        nonlocal calls
        calls += 1
        if calls == 2:
            with original(url) as db:
                if change == "queued":
                    db.add(models.OperatorTask(task_id="late-task", tenant_id="default", username="operator",
                        session_id=session_id, actor_token_version=0, kind="summarize_run", run_id="run-1",
                        language="en", idempotency_key="late-task", status="queued", cancel_requested=False,
                        created_at=old, updated_at=old))
                elif change == "hold":
                    db.add(models.TenantLegalHold(tenant_id="default", set_by="admin", set_at=old, reason="late hold"))
                else:
                    db.add(models.TenantRetentionPolicy(tenant_id="default", run_days=120,
                        updated_at=old, updated_by="admin"))
        with original(url) as db:
            yield db

    monkeypatch.setattr(retention, "get_session", interleave)
    assert retention.sweep(settings) == 0
    assert store.get_session(settings, "default", "operator", session_id) is not None
