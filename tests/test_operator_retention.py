"""History follows tenant run windows and preserves held/active records."""
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

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
