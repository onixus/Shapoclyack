"""Upgrade and rollback preserve legacy inventory, identity and release bytes."""

from __future__ import annotations

import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_legacy_inventory_upgrade_and_downgrade(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0079_" + uuid.uuid4().hex[:12]
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    url = (
        make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0077_agent_client_certs")
        with database.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO tenants (tenant_id,name,created_at) VALUES ('legacy','Legacy',CURRENT_TIMESTAMP)"
                )
            )
            conn.execute(
                text("""INSERT INTO endpoint_devices (device_id,tenant_id,agent_id,hostname,agent_version,labels,first_seen,last_seen,latest_snapshot_id)
                VALUES ('device','legacy','agent','host','0.4.0','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'snapshot')""")
            )
            conn.execute(
                text("""INSERT INTO endpoint_inventory_snapshots (snapshot_id,tenant_id,device_id,schema_version,collected_at,received_at,payload_digest,software_count,collector_warnings,response)
                VALUES ('snapshot','legacy','device',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'digest',1,'{}','{}')""")
            )
            conn.execute(
                text("""INSERT INTO endpoint_software_items (snapshot_id,tenant_id,device_id,comparison_key,name,version,source)
                VALUES ('snapshot','legacy','device','legacy-key','openssl','1.1.1','dpkg')""")
            )
            conn.execute(
                text("""INSERT INTO endpoint_agent_releases (version,platform,sha256,size_bytes,content,uploaded_at)
                VALUES ('0.4.0','linux','digest',3,:content,CURRENT_TIMESTAMP)"""),
                {"content": b"abc"},
            )
        migrate.run_upgrade(url)
        with database.connect() as conn:
            assert conn.execute(
                text(
                    "SELECT latest_snapshot_id,software_snapshot_id,source_states FROM endpoint_devices"
                )
            ).one() == ("snapshot", "snapshot", [])
            assert conn.execute(
                text(
                    "SELECT comparison_key,version,installation_identity FROM endpoint_software_items"
                )
            ).one() == ("legacy-key", "1.1.1", None)
            release = conn.execute(
                text("SELECT content,signed_manifest FROM endpoint_agent_releases")
            ).one()
            assert bytes(release[0]) == b"abc"
            assert release[1] is None
        migrate._downgrade("0077_agent_client_certs")
        with database.connect() as conn:
            assert conn.execute(
                text("SELECT comparison_key,version FROM endpoint_software_items")
            ).one() == ("legacy-key", "1.1.1")
            assert (
                conn.execute(
                    text("SELECT latest_snapshot_id FROM endpoint_devices")
                ).scalar_one()
                == "snapshot"
            )
    finally:
        database.dispose()
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
