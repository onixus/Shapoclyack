"""``0073`` on a database of its own (#504, review round 1).

``POST /api/agent/deployment-command`` and the SSH push used to mint a
provisioning key for anyone at rank 3 in the tenant; they now ask for
``tenant.credential.manage``, as ``POST …/provisioning-keys`` always did. A
tenant role written at rank 3 without that permission minted keys yesterday
and has to tomorrow, so the migration writes the permission onto it — and onto
nothing else.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

BEFORE = "0072_run_publication_projected"
REVISION = "0073_rank3_credential_permission"
CREDENTIAL = "tenant.credential.manage"


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mig0073_{uuid.uuid4().hex[:10]}"
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


def _held(conn) -> set[tuple[str, str]]:
    return {
        (tenant_id, role_id)
        for tenant_id, role_id in conn.execute(
            text("SELECT tenant_id, role_id FROM role_permissions WHERE permission_key = :key"),
            {"key": CREDENTIAL},
        ).all()
    }


def test_a_rank_3_tenant_role_keeps_minting_keys_after_the_upgrade(fresh_database):
    url = fresh_database
    migrate._upgrade(BEFORE)  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, status, created_at) "
                    "VALUES ('acme', 'acme', 'active', now())"
                )
            )
            for role_id, rank in (
                ("deployer", 3),
                ("people-lead", 3),
                ("already-keys", 3),
                ("operator-ish", 2),
                ("reader-ish", 1),
            ):
                conn.execute(
                    text(
                        "INSERT INTO roles (role_id, tenant_id, description, builtin, rank, "
                        "created_at) VALUES (:r, 'acme', '', false, :rank, now())"
                    ),
                    {"r": role_id, "rank": rank},
                )
            for role_id, key in (
                ("people-lead", "tenant.member.manage"),
                ("already-keys", CREDENTIAL),
                ("operator-ish", "scan.cancel"),
            ):
                conn.execute(
                    text(
                        "INSERT INTO role_permissions (role_id, tenant_id, permission_key) "
                        "VALUES (:r, 'acme', :k)"
                    ),
                    {"r": role_id, "k": key},
                )
            builtin_before = {
                role_id for tenant_id, role_id in _held(conn) if tenant_id == ""
            }

        migrate._upgrade(REVISION)  # noqa: SLF001
        with engine.connect() as conn:
            held = _held(conn)
            assert {role_id for tenant_id, role_id in held if tenant_id == "acme"} == {
                "deployer",
                "people-lead",
                "already-keys",
            }
            # The built-in rows are the release's, not this migration's.
            assert {role_id for tenant_id, role_id in held if tenant_id == ""} == builtin_before
            people_lead = set(
                conn.execute(
                    text(
                        "SELECT permission_key FROM role_permissions "
                        "WHERE tenant_id = 'acme' AND role_id = 'people-lead'"
                    )
                ).scalars()
            )
            assert people_lead == {"tenant.member.manage", CREDENTIAL}

        # Down leaves the grants: which rank-3 role held the permission before
        # the upgrade is not recorded anywhere, and taking it from all of them
        # would take it from roles the tenant gave it to on purpose.
        migrate._downgrade(BEFORE)  # noqa: SLF001
        with engine.connect() as conn:
            assert ("acme", "deployer") in _held(conn)
        migrate._upgrade(REVISION)  # noqa: SLF001
    finally:
        engine.dispose()
