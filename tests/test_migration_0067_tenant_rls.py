"""``0067_tenant_rls`` on the hardened layout, and behind a long transaction.

Two properties of the migration itself (#311 review), both on a sibling
database that exists only for this test, migrated by a role that is *not* a
superuser — the layout docs/operations.md recommends, where the API's role owns
the schema and ``audit_events`` belongs to a role of its own:

* a table another role owns is left to that owner — the upgrade completes,
  logs the exact statements, and the startup check names the table until they
  have been run — instead of failing with ``must be owner of table``;
* a table some other transaction holds costs the run a few seconds and a
  retry, not every query on every table the run had already locked: each table
  is its own short transaction under ``lock_timeout``, and a second run
  finishes what the first could not.
"""

from __future__ import annotations

import time
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError

from api.db import migrate, models, tenant_scope
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

# Pinned rather than "head": the test is about this revision alone (relinked
# onto #325's 0066 at merge), with the ownership split applied just before it.
BEFORE = "0066_tenant_lifecycle"
REVISION = "0067_tenant_rls"


@pytest.fixture
def owner_database(monkeypatch: pytest.MonkeyPatch):
    """A fresh database owned by a non-superuser, CREATEROLE migration role."""
    suffix = uuid.uuid4().hex[:8]
    owner, audit_owner, name = f"rls_mig_{suffix}", f"rls_audit_{suffix}", f"rls0067_{suffix}"
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE ROLE "{owner}" LOGIN CREATEROLE'))
        conn.execute(text(f'CREATE ROLE "{audit_owner}" NOLOGIN'))
        conn.execute(text(f'CREATE DATABASE "{name}" OWNER "{owner}"'))
        # The documented step for a role that did not create shapoclyack_tenant
        # itself (it exists cluster-wide once any database has run 0067).
        conn.execute(
            text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles"
                " WHERE rolname = 'shapoclyack_tenant') THEN"
                " CREATE ROLE shapoclyack_tenant NOLOGIN; END IF; END $$"
            )
        )
        conn.execute(text(f'GRANT shapoclyack_tenant TO "{owner}" WITH INHERIT FALSE'))
    as_owner = make_url(POSTGRES_URL).set(database=name, username=owner, password=None)
    as_admin = make_url(POSTGRES_URL).set(database=name)
    monkeypatch.setenv("OCTO_POSTGRES_URL", as_owner.render_as_string(hide_password=False))
    try:
        yield (
            as_owner.render_as_string(hide_password=False),
            as_admin.render_as_string(hide_password=False),
            owner,
            audit_owner,
        )
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
            for role in (owner, audit_owner):
                conn.execute(text(f'DROP OWNED BY "{role}"'))
                conn.execute(text(f'DROP ROLE "{role}"'))
        admin.dispose()


def _protected(url: str) -> set[str]:
    engine = create_engine(url, future=True)
    try:
        with engine.connect() as conn:
            return set(
                conn.execute(
                    text(
                        "SELECT c.relname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid"
                        " WHERE p.polname = 'shapoclyack_tenant_isolation'"
                    )
                ).scalars()
            )
    finally:
        engine.dispose()


def test_0067_leaves_another_owners_table_to_it_and_survives_a_held_lock(
    owner_database, capfd
) -> None:
    as_owner, as_admin, owner, audit_owner = owner_database
    migrate._upgrade(BEFORE)  # noqa: SLF001
    admin = create_engine(as_admin, future=True)
    holder = admin.connect()
    try:
        with admin.begin() as conn:
            # docs/operations.md § Recommended GRANT layout, applied before 0067.
            conn.execute(text(f'ALTER TABLE audit_events OWNER TO "{audit_owner}"'))
            conn.execute(text(f'ALTER SEQUENCE audit_events_id_seq OWNER TO "{audit_owner}"'))
            conn.execute(text(f'GRANT SELECT, INSERT ON audit_events TO "{owner}"'))
            conn.execute(text(f'GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO "{owner}"'))

        # A long transaction holding a lock on one table.
        holder.begin()
        holder.execute(text("LOCK TABLE agents IN ACCESS SHARE MODE"))
        started = time.monotonic()
        with pytest.raises(DBAPIError, match="lock timeout"):
            migrate._upgrade(REVISION)  # noqa: SLF001
        assert time.monotonic() - started < 60
        done = _protected(as_admin)
        # Tables before it in the run were each committed on their own...
        assert {"agent_deployments", "agent_groups"} <= done
        # ...and the one being waited for was not left half-done.
        assert "agents" not in done
        holder.rollback()

        # The retry finishes the rest.
        migrate._upgrade(REVISION)  # noqa: SLF001
        done = _protected(as_admin)
        expected = set(tenant_scope.tenant_tables(models.Base.metadata))
        assert done == expected - {"audit_events"}

        # The statements for the table it could not touch were handed over —
        # on stderr, where Alembic's own logging configuration sends them.
        logged = capfd.readouterr().err
        marker = "audit_events is owned by another role"
        assert marker in logged, logged[-2000:]
        tail = logged.split(marker, 1)[1].split("Run as its owner:\n", 1)[1]
        statements = tail.split(";\n\n", 1)[0].split("\nINFO", 1)[0].strip()
        assert statements.endswith(";") and "GRANT USAGE, SELECT ON SEQUENCE" in statements

        # ...the startup check names it until they have run...
        engine = create_engine(as_owner, future=True)
        try:
            with engine.connect() as conn:
                problems = tenant_scope.database_problems(conn, models.Base.metadata)
            assert any("owns (audit_events)" in problem for problem in problems), problems

            # ...and running them as that owner is all it takes.
            with admin.begin() as conn:
                conn.execute(text(f'SET LOCAL ROLE "{audit_owner}"'))
                for statement in statements.split(";\n"):
                    conn.execute(text(statement.strip().rstrip(";")))
            with engine.connect() as conn:
                assert tenant_scope.database_problems(conn, models.Base.metadata) == []
        finally:
            engine.dispose()

        # And the rollback, as the same role, leaves that table to its owner too.
        migrate._downgrade(BEFORE)  # noqa: SLF001
        assert _protected(as_admin) == {"audit_events"}
        assert marker in capfd.readouterr().err
    finally:
        holder.close()
        admin.dispose()
