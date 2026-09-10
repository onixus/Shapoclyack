"""Unit tests for api/db/engine.py helpers."""

from __future__ import annotations

from datetime import UTC, datetime

from api.db import models
from api.db import engine as db_engine
from api.db.engine import get_session, insert_if_absent
from api.services import tenants as tenants_service
from tests.conftest import make_settings, requires_postgres

# Per test rather than per module: the pool-sizing tests below never open a
# connection (create_engine is lazy), so skipping them without a Postgres would
# mean the whole feature goes unexercised on a developer's laptop -- silently,
# the way a skip does.
UNCONNECTED_POSTGRES_URL = "postgresql+psycopg://u:p@127.0.0.1:5432/shapoclyack"


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


@requires_postgres
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


def test_configure_sizes_the_connection_pool(tmp_path):
    """An HA overlay runs N replicas against one server, so the per-process pool
    has to be settable: SQLAlchemy's 5+10 default is silently multiplied by the
    replica count, and the failure mode is every replica hitting the server's
    `max_connections` at the same moment (#335). Before configure() reached the
    engine the values were whatever the library chose."""
    settings = make_settings(
        tmp_path,
        # An explicit URL, not conftest's: nothing here connects (create_engine
        # is lazy and the schema helper skips non-SQLite), so the test must not
        # depend on a Postgres being configured to run at all.
        postgres_url=UNCONNECTED_POSTGRES_URL,
        db_pool_size=3,
        db_max_overflow=1,
        db_pool_timeout=7,
    )
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        pool = db_engine.get_engine(settings.postgres_url).pool
        assert pool.size() == 3
        assert pool._max_overflow == 1
        assert pool._timeout == 7
    finally:
        db_engine.reset_for_tests()


def test_configure_after_the_engine_exists_rebuilds_it(tmp_path):
    """The engine is a lazy singleton, so a later configure() that only stored
    the numbers would leave the live pool on the old sizing -- and nothing would
    say so. Ordering in create_app() makes this a test-only path; it is asserted
    because a silent no-op here reads exactly like a working knob."""
    settings = make_settings(tmp_path, postgres_url=UNCONNECTED_POSTGRES_URL)
    db_engine.reset_for_tests()
    try:
        first = db_engine.get_engine(settings.postgres_url)
        settings.db_pool_size = 2
        db_engine.configure(settings)
        second = db_engine.get_engine(settings.postgres_url)
        assert second is not first
        assert second.pool.size() == 2
    finally:
        db_engine.reset_for_tests()


def test_sqlite_fallback_ignores_pool_sizing(tmp_path):
    """An in-memory SQLite URL gets a SingletonThreadPool, which accepts neither
    pool_size nor max_overflow -- passing them is a TypeError at engine
    construction, i.e. an API that will not start. `sqlite:///file` happens to
    get a QueuePool and would tolerate them, so asserting on the engine rather
    than on the kwargs would pass with the guard removed."""
    settings = make_settings(tmp_path, db_pool_size=3)
    db_engine.reset_for_tests()
    try:
        db_engine.configure(settings)
        assert db_engine._pool_kwargs("sqlite://") == {}
        assert db_engine._pool_kwargs(f"sqlite:///{tmp_path / 'dev.db'}") == {}
        assert db_engine.get_engine("sqlite://") is not None
    finally:
        db_engine.reset_for_tests()


def test_pool_kwargs_are_empty_until_configured():
    """Tools and most of the suite never call configure(); they must keep
    SQLAlchemy's own defaults rather than get a half-built options dict."""
    db_engine.reset_for_tests()
    assert db_engine._pool_kwargs("postgresql+psycopg://u:p@h/d") == {}
