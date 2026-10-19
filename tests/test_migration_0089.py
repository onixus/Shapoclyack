"""Rollback must not widen source access or revive rotated predecessors (#323)."""
from __future__ import annotations

import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_token_policy_migration_upgrade_rollback_is_fail_closed(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0089_" + uuid.uuid4().hex[:12]
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0088_actionable_non_cve")
        with database.begin() as connection:
            connection.execute(text("INSERT INTO tenants (tenant_id,name,created_at) VALUES ('default','Default',CURRENT_TIMESTAMP)"))
            for token in ("legacy", "restricted", "overlap", "revoked"):
                connection.execute(text("""INSERT INTO service_tokens
                    (token_id, tenant_id, name, token_prefix, token_hash, scopes, role, created_at, expires_at)
                    VALUES (:token, 'default', :token, :token, 'existing-bcrypt-hash', 'runs:read',
                    'viewer', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '30 days')"""), {"token": token})
        migrate.run_upgrade(url, revision="0089_service_token_rotation")
        with database.begin() as connection:
            assert connection.execute(text("SELECT allowed_cidrs, expiry_notice_days FROM service_tokens WHERE token_id='legacy'")).one() == ([], 7)
            connection.execute(text("UPDATE service_tokens SET allowed_cidrs='[\"192.0.2.0/24\"]' WHERE token_id='restricted'"))
            connection.execute(text("UPDATE service_tokens SET rotation_expires_at=CURRENT_TIMESTAMP + INTERVAL '1 hour' WHERE token_id='overlap'"))
            connection.execute(text("UPDATE service_tokens SET revoked_at=CURRENT_TIMESTAMP - INTERVAL '1 day', allowed_cidrs='[\"::1/128\"]' WHERE token_id='revoked'"))
            deadline = connection.execute(text("SELECT rotation_expires_at FROM service_tokens WHERE token_id='overlap'")).scalar_one()
            revoked = connection.execute(text("SELECT revoked_at FROM service_tokens WHERE token_id='revoked'")).scalar_one()
        migrate._downgrade("0088_actionable_non_cve")  # noqa: SLF001
        with database.connect() as connection:
            rows = {row.token_id: row for row in connection.execute(text("SELECT token_id, token_hash, scopes, role, expires_at, revoked_at FROM service_tokens"))}
            assert rows["legacy"].revoked_at is None
            assert rows["restricted"].revoked_at is not None
            assert rows["revoked"].revoked_at == revoked
            assert rows["overlap"].expires_at.replace(tzinfo=deadline.tzinfo) == deadline
            assert rows["overlap"].revoked_at is None
            assert all(row.token_hash == "existing-bcrypt-hash" and row.scopes == "runs:read" for row in rows.values())
        migrate.run_upgrade(url, revision="0089_service_token_rotation")
        with database.connect() as connection:
            assert connection.execute(text("SELECT revoked_at IS NOT NULL FROM service_tokens WHERE token_id='restricted'")).scalar_one()
            assert connection.execute(text("SELECT expires_at FROM service_tokens WHERE token_id='overlap'")).scalar_one().replace(tzinfo=deadline.tzinfo) == deadline
    finally:
        database.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
