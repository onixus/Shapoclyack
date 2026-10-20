"""Saved views table and its tenant isolation survive upgrade and rollback (#357)."""
from __future__ import annotations

import uuid

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_console_saved_views_migration_upgrade_rollback_and_rls(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0092_" + uuid.uuid4().hex[:12]
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0090_asset_import_connector")
        assert "console_saved_views" not in inspect(database).get_table_names()
        migrate.run_upgrade(url, revision="0092_console_saved_views")
        inspector = inspect(database)
        assert "console_saved_views" in inspector.get_table_names()
        assert {c["name"] for c in inspector.get_columns("console_saved_views")} == {
            "view_id", "tenant_id", "username", "page", "name", "name_key", "state", "created_at", "updated_at",
        }
        assert [
            i["column_names"]
            for i in inspector.get_indexes("console_saved_views")
            if not i.get("duplicates_constraint")
        ] == [["tenant_id", "username", "page"]]
        assert [
            (u["name"], u["column_names"])
            for u in inspector.get_unique_constraints("console_saved_views")
        ] == [(
            "uq_console_saved_views_name_key",
            ["tenant_id", "username", "page", "name_key"],
        )]
        with database.begin() as connection:
            assert connection.execute(text(
                "SELECT relrowsecurity FROM pg_class WHERE relname='console_saved_views'"
            )).scalar_one()
            policies = {row[0]: row[1] for row in connection.execute(text(
                "SELECT policyname, permissive FROM pg_policies WHERE tablename='console_saved_views'"
            ))}
            assert policies == {
                "shapoclyack_unscoped": "PERMISSIVE",
                "shapoclyack_tenant_isolation": "RESTRICTIVE",
            }
            for tenant in ("alpha", "beta"):
                connection.execute(text(
                    "INSERT INTO tenants (tenant_id,name,created_at) VALUES (:t,:t,CURRENT_TIMESTAMP)"
                ), {"t": tenant})
                connection.execute(text(
                    """INSERT INTO console_saved_views
                    (view_id, tenant_id, username, page, name, name_key, state, created_at, updated_at)
                    VALUES (:t, :t, 'alice', 'assets', 'v', 'v', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"""
                ), {"t": tenant})
            # The tenant role only sees rows of the tenant bound to the session.
            connection.execute(text("SET LOCAL ROLE shapoclyack_tenant"))
            connection.execute(text("SELECT set_config('shapoclyack.tenant_id', 'alpha', true)"))
            assert [r[0] for r in connection.execute(text("SELECT tenant_id FROM console_saved_views"))] == ["alpha"]
        with database.begin() as connection:
            # Tenant deletion cascades to the personal views.
            connection.execute(text("DELETE FROM tenants WHERE tenant_id='beta'"))
            assert connection.execute(text("SELECT count(*) FROM console_saved_views")).scalar_one() == 1
        migrate._downgrade("0091_asset_connector_run_lease")  # noqa: SLF001
        assert "console_saved_views" not in inspect(database).get_table_names()
        migrate.run_upgrade(url, revision="0092_console_saved_views")
        assert "console_saved_views" in inspect(database).get_table_names()
    finally:
        database.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
