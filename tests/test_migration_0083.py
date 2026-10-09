"""Certificate-material migration keeps legacy revocations and permits rollback."""

from __future__ import annotations

import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_certificate_material_upgrade_and_rollback(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0083_" + uuid.uuid4().hex[:12]
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = (
        make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0082_idempotency_actor_contract")
        with database.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO tenants (tenant_id,name,created_at) VALUES ('default','Default',CURRENT_TIMESTAMP)"
                )
            )
            connection.execute(
                text("""INSERT INTO agent_client_certs
                (cert_id,tenant_id,agent_id,fingerprint_sha256,serial_hex,subject,source,
                 created_at,created_by,revoked_at,revoked_by,revoked_reason)
                VALUES ('legacy','default','sensor-a',:digest,'ab','host','csr',
                        CURRENT_TIMESTAMP,'sensor-a',CURRENT_TIMESTAMP,'admin','compromised')"""),
                {"digest": "a" * 64},
            )
        snapshot = text(
            "SELECT fingerprint_sha256,serial_hex,revoked_at,revoked_reason FROM agent_client_certs"
        )
        with database.connect() as connection:
            before = connection.execute(snapshot).all()
        migrate.run_upgrade(url)
        with database.begin() as connection:
            assert connection.execute(snapshot).all() == before
            assert (
                connection.execute(
                    text("SELECT certificate_pem FROM agent_client_certs")
                ).scalar_one()
                == ""
            )
            connection.execute(
                text(
                    "UPDATE agent_client_certs SET certificate_pem='operator material'"
                )
            )
        migrate._downgrade("0082_idempotency_actor_contract")  # noqa: SLF001
        with database.connect() as connection:
            assert connection.execute(snapshot).all() == before
        migrate.run_upgrade(url)
        with database.connect() as connection:
            assert (
                connection.execute(
                    text("SELECT certificate_pem FROM agent_client_certs")
                ).scalar_one()
                == ""
            )
    finally:
        database.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
