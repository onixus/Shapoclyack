"""``0065`` on the installations its own docs describe (#332, review round 1).

Two properties the ordinary round trip in a superuser's database cannot see:

* **The split install.** ``docs/operations.md`` recommends moving
  ``audit_events_prune`` to a dedicated owner role, and the migration runs as
  the API's role. ``CREATE OR REPLACE FUNCTION`` needs ownership, so ``0065``
  failed there with a bare ``InsufficientPrivilege`` and the rollout stopped.
  It now refuses up front, naming the statements that let it through.
* **The downgrade.** Dropping ``tenant_legal_holds`` and ``users.erased_at``
  would let the previous release sweep a held tenant and re-enable an erased
  account. It refuses while either is in use.

Each test gets a sibling database of its own, as in
``tests/test_migration_0032_downgrade.py``.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

BEFORE = "0064_asset_services_retro_match"
REVISION = "0065_tenant_retention_legal_hold"


def _version(url: str) -> str:
    engine = create_engine(url, future=True)
    try:
        with engine.connect() as conn:
            return conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
    finally:
        engine.dispose()


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mig0065_{uuid.uuid4().hex[:10]}"
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


@pytest.fixture
def split_install(monkeypatch: pytest.MonkeyPatch):
    """A database migrated by an unprivileged API role, with the audit prune
    function handed to an owner role the way the GRANT layout does it.

    Roles are cluster-wide, so they carry a random suffix and are dropped with
    the database. The password is ignored under trust authentication and used
    under password authentication, which is what CI's Postgres service has.
    """
    suffix = uuid.uuid4().hex[:8]
    api_role, owner_role = f"i332_api_{suffix}", f"i332_owner_{suffix}"
    name = f"mig0065_split_{suffix}"
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f"CREATE ROLE {api_role} LOGIN PASSWORD 'i332-test'"))
        conn.execute(text(f"CREATE ROLE {owner_role} NOLOGIN"))
        conn.execute(text(f'CREATE DATABASE "{name}" OWNER {api_role}'))
    base = make_url(POSTGRES_URL).set(database=name)
    as_admin = base.render_as_string(hide_password=False)
    as_api = base.set(username=api_role, password="i332-test").render_as_string(
        hide_password=False
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", as_api)
    try:
        yield as_api, as_admin, owner_role
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
            conn.execute(text(f"DROP ROLE IF EXISTS {api_role}"))
            conn.execute(text(f"DROP ROLE IF EXISTS {owner_role}"))
        admin.dispose()


def test_the_upgrade_names_the_ownership_it_needs_on_a_split_install(split_install) -> None:
    as_api, as_admin, owner_role = split_install
    migrate._upgrade(BEFORE)  # noqa: SLF001
    admin = create_engine(as_admin, future=True)
    try:
        with admin.begin() as conn:
            conn.execute(
                text(
                    "ALTER FUNCTION audit_events_prune(timestamp without time zone) "
                    f"OWNER TO {owner_role}"
                )
            )
    finally:
        admin.dispose()

    with pytest.raises(Exception) as refused:
        migrate._upgrade("head")  # noqa: SLF001

    message = str(refused.value)
    assert "audit_events_prune" in message
    assert owner_role in message
    assert "ALTER FUNCTION audit_events_prune(timestamp without time zone) OWNER TO" in message
    assert "data-retention.md" in message
    # Refused before anything was created: the version did not move.
    assert _version(as_admin) == BEFORE


def test_the_downgrade_refuses_while_a_hold_or_a_tombstone_exists(fresh_database) -> None:
    url = fresh_database
    # To this revision, not "head": a later one (0066, #325) downgrades first,
    # in the same transaction, and the refusal would roll the schema back to it.
    migrate._upgrade(REVISION)  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, status, created_at) "
                    "VALUES ('held', 'Held', 'active', now())"
                )
            )
            conn.execute(
                text(
                    "INSERT INTO tenant_legal_holds (tenant_id, reason, set_by, set_at) "
                    "VALUES ('held', 'matter 2026-17', 'admin', now())"
                )
            )
        with pytest.raises(Exception, match="legal hold"):
            migrate._downgrade(BEFORE)  # noqa: SLF001
        assert _version(url) == REVISION

        with engine.begin() as conn:
            conn.execute(text("DELETE FROM tenant_legal_holds"))
            conn.execute(
                text(
                    "INSERT INTO users (username, password_hash, role, created_at, updated_at, "
                    "erased_at, disabled_at) "
                    "VALUES ('dana', '', 'viewer', now(), now(), now(), now())"
                )
            )
        with pytest.raises(Exception, match="erased"):
            migrate._downgrade(BEFORE)  # noqa: SLF001
        assert _version(url) == REVISION

        with engine.begin() as conn:
            conn.execute(text("DELETE FROM users WHERE username = 'dana'"))
        migrate._downgrade(BEFORE)  # noqa: SLF001
        assert _version(url) == BEFORE
    finally:
        engine.dispose()
