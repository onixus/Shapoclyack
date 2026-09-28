"""``0066`` up, down and up again, on a database of its own (#325, review round 1).

The downgrade is the half an ordinary round trip in an empty database cannot
check: it has to turn ``pending_deletion`` and ``deleting`` — words the previous
release's ``TenantInfo`` cannot serialise — into ``suspended``, which every
gate of that release still refuses, and take the permission rows it seeded
with it.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

BEFORE = "0065_tenant_retention_legal_hold"
REVISION = "0066_tenant_lifecycle"


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mig0066_{uuid.uuid4().hex[:10]}"
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    try:
        yield url
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()


def test_the_downgrade_maps_the_deletion_states_and_takes_its_rows_with_it(fresh_database):
    url = fresh_database
    migrate._upgrade(REVISION)  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            for tenant_id, status in (
                ("paused", "suspended"),
                ("leaving", "pending_deletion"),
                ("going", "deleting"),
                ("staying", "active"),
            ):
                conn.execute(
                    text(
                        "INSERT INTO tenants (tenant_id, name, status, created_at) "
                        "VALUES (:t, :t, :s, now())"
                    ),
                    {"t": tenant_id, "s": status},
                )
            granted = conn.execute(
                text(
                    "SELECT count(*) FROM role_permissions "
                    "WHERE permission_key = 'platform.tenant.lifecycle' AND role_id = 'platform-admin'"
                )
            ).scalar_one()
            assert granted == 1

        migrate._downgrade(BEFORE)  # noqa: SLF001
        with engine.connect() as conn:
            statuses = dict(conn.execute(text("SELECT tenant_id, status FROM tenants")).all())
            assert statuses["leaving"] == "suspended"
            assert statuses["going"] == "suspended"
            assert statuses["paused"] == "suspended"
            assert statuses["staying"] == "active"
            assert conn.execute(
                text("SELECT count(*) FROM permissions WHERE permission_key = 'platform.tenant.lifecycle'")
            ).scalar_one() == 0
        tables = set(inspect(engine).get_table_names())
        assert "tenant_deletions" not in tables and "tenant_deletion_steps" not in tables
        columns = {column["name"] for column in inspect(engine).get_columns("tenants")}
        assert "status_reason" not in columns

        migrate._upgrade(REVISION)  # noqa: SLF001
        with engine.connect() as conn:
            assert conn.execute(
                text("SELECT count(*) FROM permissions WHERE permission_key = 'platform.tenant.lifecycle'")
            ).scalar_one() == 1
    finally:
        engine.dispose()


def test_one_open_deletion_per_tenant_is_the_databases_rule(fresh_database):
    """The partial unique index, not only the service's check: two replicas
    requesting the same deletion at once cannot both open one."""
    url = fresh_database
    migrate._upgrade(REVISION)  # noqa: SLF001
    engine = create_engine(url, future=True)
    insert = text(
        "INSERT INTO tenant_deletions (deletion_id, tenant_id, state, reason, requested_by, "
        "requested_at, purge_after) VALUES (:d, 'acme', :s, 'r', 'root', now(), now())"
    )
    try:
        with engine.begin() as conn:
            conn.execute(insert, {"d": "del_1", "s": "cancelled"})
            conn.execute(insert, {"d": "del_2", "s": "completed"})
            conn.execute(insert, {"d": "del_3", "s": "pending"})
        with pytest.raises(Exception, match="uq_tenant_deletions_open"):
            with engine.begin() as conn:
                conn.execute(insert, {"d": "del_4", "s": "purging"})
    finally:
        engine.dispose()


@pytest.mark.parametrize("state", ["purging", "blocked"])
def test_the_downgrade_refuses_while_a_tenant_is_half_purged(fresh_database, state):
    """``deleting`` would come back as ``suspended``, and a resume would put a
    tenant whose data is half gone back into service. A purge that is running
    or stopped by a hold is finished (the hold lifted first) before 0066 goes."""
    url = fresh_database
    migrate._upgrade(REVISION)  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, status, created_at) "
                    "VALUES ('going', 'going', 'deleting', now())"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO tenant_deletions (deletion_id, tenant_id, state, reason, "
                    "requested_by, requested_at, purge_after) "
                    "VALUES ('del_1', 'going', :s, 'r', 'root', now(), now())"
                ),
                {"s": state},
            )
        with pytest.raises(Exception, match="going"):
            migrate._downgrade(BEFORE)  # noqa: SLF001
        with engine.connect() as conn:
            assert conn.execute(text("SELECT status FROM tenants")).scalar_one() == "deleting"
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            assert version == REVISION

        # Finished: the tenant row is gone and the journal says so.
        with engine.begin() as conn:
            conn.execute(text("UPDATE tenant_deletions SET state = 'completed'"))
            conn.execute(text("DELETE FROM tenants WHERE tenant_id = 'going'"))
        migrate._downgrade(BEFORE)  # noqa: SLF001
        columns = {column["name"] for column in inspect(engine).get_columns("tenants")}
        assert "closed_at" not in columns
    finally:
        engine.dispose()
