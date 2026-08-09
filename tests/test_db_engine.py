"""Unit tests for api/db/engine.py helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import tenants as tenants_service
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


def _agent(agent_id: str) -> models.Agent:
    now = datetime.now(UTC).replace(tzinfo=None)
    return models.Agent(
        agent_id=agent_id,
        tenant_id="default",
        hostname="h",
        version="",
        labels={},
        status="idle",
        registered_at=now,
        last_seen_at=now,
    )


def test_insert_if_absent_keeps_a_duplicate_from_aborting_the_transaction(tmp_path):
    """The P1.2 startup imports run in every replica at once, so a
    check-then-insert can lose the race. Without the SAVEPOINT the resulting
    IntegrityError would poison the whole transaction and take API startup down
    with it -- on every restart, since the file is only retired afterwards."""
    settings = make_settings(tmp_path)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)

    with get_session(settings.postgres_url) as session:
        assert insert_if_absent(session, _agent("dup"), "dup") is True
        # Simulates the other replica having committed this key first.
        assert insert_if_absent(session, _agent("dup"), "dup") is False
        # The transaction is still usable: the rest of the import completes.
        assert insert_if_absent(session, _agent("next"), "next") is True

    assert {row.agent_id for row in _all_agents(settings)} == {"dup", "next"}


def _all_agents(settings) -> list[models.Agent]:
    with get_session(settings.postgres_url) as session:
        return session.query(models.Agent).all()
