"""Serialized migrations and the single schema path (#159).

Two properties are under test:

* concurrent ``python -m api.db.migrate`` runs do not migrate at the same time —
  which is what N replicas of a scaled Deployment do on every rollout;
* ``create_all`` no longer builds a PostgreSQL schema behind Alembic's back.

The Postgres cases need a real database (advisory locks do not exist on SQLite,
which is exactly why the SQLite path skips the lock rather than emulating it).
"""

from __future__ import annotations

import logging
import threading
import time

import pytest
from sqlalchemy import create_engine, inspect, text

from api.db import migrate
from api.db.engine import _create_schema_if_unmanaged
from tests.conftest import POSTGRES_URL, requires_postgres


def test_sqlite_still_gets_its_schema_from_the_models(tmp_path) -> None:
    """The dev/test fallback must not need a migration run to work."""
    engine = create_engine(f"sqlite:///{tmp_path / 'schema.db'}", future=True)

    _create_schema_if_unmanaged(engine)

    assert "tenants" in inspect(engine).get_table_names()


@requires_postgres
def test_postgres_schema_is_not_created_from_the_models() -> None:
    """Alembic owns the Postgres schema; a second path would diverge from it."""
    engine = create_engine(POSTGRES_URL, future=True)
    before = set(inspect(engine).get_table_names())

    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS unmanaged_probe"))
    _create_schema_if_unmanaged(engine)

    # Nothing was created and, more to the point, nothing was *re*-created:
    # the call is a no-op rather than a quiet repair of a missing migration.
    assert set(inspect(engine).get_table_names()) == before


@requires_postgres
def test_concurrent_upgrades_do_not_overlap() -> None:
    """The property #159 exists for: N replicas migrate one at a time.

    Both threads run a real ``upgrade head`` (a no-op against an already
    migrated CI database, which is fine — what is asserted is the mutual
    exclusion, not the DDL). The overlap check is done inside the lock via a
    shared counter, so a passing run means the second thread genuinely waited
    rather than merely finishing later.
    """
    concurrent = 0
    max_concurrent = 0
    guard = threading.Lock()
    errors: list[BaseException] = []
    real_upgrade = migrate._upgrade

    def instrumented(revision: str) -> None:
        nonlocal concurrent, max_concurrent
        with guard:
            concurrent += 1
            max_concurrent = max(max_concurrent, concurrent)
        try:
            # Long enough that a genuinely concurrent pair would be caught;
            # the lock is what should make that impossible.
            time.sleep(0.25)
            real_upgrade(revision)
        finally:
            with guard:
                concurrent -= 1

    def worker() -> None:
        try:
            migrate.run_upgrade(POSTGRES_URL, lock_timeout_seconds=30)
        except BaseException as exc:  # noqa: BLE001 - reported after the join
            errors.append(exc)

    migrate._upgrade = instrumented
    try:
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
    finally:
        migrate._upgrade = real_upgrade

    assert not errors, errors
    assert max_concurrent == 1


@requires_postgres
def test_waiting_for_a_held_lock_times_out_with_a_named_cause() -> None:
    """A stuck migration must fail the pod, not hang it at Init:0/1."""
    holder = create_engine(POSTGRES_URL, future=True)
    conn = holder.connect().execution_options(isolation_level="AUTOCOMMIT")
    try:
        conn.execute(
            text("SELECT pg_advisory_lock(:class_id, :object_id)"),
            {
                "class_id": migrate.LOCK_CLASS_ID,
                "object_id": migrate.MIGRATION_LOCK_ID,
            },
        )

        with pytest.raises(RuntimeError, match="migration lock"):
            migrate.run_upgrade(POSTGRES_URL, lock_timeout_seconds=1)
    finally:
        conn.close()
        holder.dispose()


@requires_postgres
def test_upgrade_does_not_silence_application_loggers() -> None:
    """Alembic's fileConfig must not switch off the caller's own logger.

    Running the upgrade in-process means ``logging.config.fileConfig`` executes
    inside this process, and its default disables every logger it does not name
    — including ``api.db.migrate``, whose next line is the message explaining
    why the migration failed.
    """
    victim = logging.getLogger("api.settings")

    migrate.run_upgrade(POSTGRES_URL, lock_timeout_seconds=30)

    assert not victim.disabled
    assert not logging.getLogger("api.db.migrate").disabled


def test_missing_database_url_is_refused_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OCTO_POSTGRES_URL", raising=False)

    with pytest.raises(RuntimeError, match="OCTO_POSTGRES_URL"):
        migrate._database_url()
