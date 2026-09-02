"""Migration ``0025``'s grandfather path, on a database that was really at ``0024``.

#226 made scan-scope enforcement fail-closed: a tenant with no rows scans
nothing. On an existing installation that would have stopped every scheduled
scan at the first upgrade, with no operator present — so ``0025`` inserts an
explicit allow-all scope for every tenant that exists when it runs, stamped
``approved_by = 'migration-0025'``. Whether that insert happens is the single
fact that decides if an upgrade is safe, and until now it had been checked by
hand: the CI database is migrated to head before the suite starts, so nothing
in it ever ran ``0025`` over a tenant.

This module builds its own database, brings it to ``0024``, creates tenants
there, and only then applies the rest. Postgres only — the same privilege that
lets CI create the schema lets it create a sibling database.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from api.settings import Settings
from tests.conftest import POSTGRES_URL, make_settings, requires_postgres

pytestmark = requires_postgres

_LEGACY = ("acme", "globex")
_GRANDFATHER_VALUES = {("cidr", "0.0.0.0/0"), ("cidr", "::/0"), ("domain", "*")}


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    """A sibling database that exists only for this test; ``OCTO_POSTGRES_URL``
    points at it so Alembic's ``env.py`` migrates it and nothing else."""
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"gf0025_{uuid.uuid4().hex[:10]}"
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


def _settings(tmp_path, url: str) -> Settings:
    return make_settings(tmp_path, postgres_url=url)


def test_upgrading_past_0025_keeps_existing_tenants_scanning(fresh_database, tmp_path):
    from api.services import scan_scopes

    url = fresh_database
    migrate._upgrade("0024_agent_deployment_security")

    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        for tenant_id in _LEGACY:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, status, created_at) "
                    "VALUES (:id, :name, 'active', now())"
                ),
                {"id": tenant_id, "name": tenant_id.title()},
            )
    engine.dispose()

    migrate._upgrade("head")

    engine = create_engine(url, future=True)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT tenant_id, effect, kind, value, approved_by "
                "FROM tenant_scan_scopes ORDER BY tenant_id, kind, value"
            )
        ).all()
    engine.dispose()

    by_tenant: dict[str, set[tuple[str, str]]] = {}
    for tenant_id, effect, kind, value, approved_by in rows:
        # The row is a visible permission with an honest author, not an
        # implicit "no scope means everything" rule hidden in the code.
        assert effect == "allow"
        assert approved_by == "migration-0025"
        by_tenant.setdefault(tenant_id, set()).add((kind, value))
    assert by_tenant == {tenant_id: _GRANDFATHER_VALUES for tenant_id in _LEGACY}

    # And the scope the API loads from those rows is what the upgrade promised:
    # allow-all in both address families and every domain.
    settings = _settings(tmp_path, url)
    for tenant_id in _LEGACY:
        scope = scan_scopes.load_scope(settings, tenant_id)
        assert scope.approved
        scope.check(
            ranges=["10.1.2.0/24", "203.0.113.10", "2001:db8::/32"],
            domains=["anything.example", "deep.sub.example.org"],
        )


def test_a_tenant_created_after_0025_starts_fail_closed(fresh_database, tmp_path):
    """The grandfather is for tenants the upgrade found, not a default."""
    from api.services import scan_scopes

    url = fresh_database
    migrate._upgrade("head")

    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('newcomer', 'Newcomer', 'active', now())"
            )
        )
        count = conn.execute(text("SELECT count(*) FROM tenant_scan_scopes")).scalar_one()
    engine.dispose()
    assert count == 0

    scope = scan_scopes.load_scope(_settings(tmp_path, url), "newcomer")
    assert not scope.approved
    with pytest.raises(scan_scopes.ScanScopeDenied):
        scope.require_approved()


def test_downgrading_below_0025_removes_the_grandfathered_rows_with_the_table(fresh_database):
    """The documented downgrade returns to the state that preceded the upgrade."""
    url = fresh_database
    migrate._upgrade("0024_agent_deployment_security")
    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('acme', 'Acme', 'active', now())"
            )
        )
    engine.dispose()
    migrate._upgrade("head")

    from alembic import command
    from alembic.config import Config

    command.downgrade(Config(str(migrate._ALEMBIC_INI)), "0024_agent_deployment_security")

    engine = create_engine(url, future=True)
    with engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        }
        columns = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name = 'auth_events'"
                )
            )
        }
    engine.dispose()
    assert "tenant_scan_scopes" not in tables
    assert "detail" not in columns
