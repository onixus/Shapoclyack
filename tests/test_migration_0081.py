"""Release storage preserves bytes and refuses a lossy downgrade."""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_release_variant_upgrade_and_lossless_downgrade(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0081_" + uuid.uuid4().hex[:12]
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = (
        make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    )
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0080_endpoint_inventory_v2")
        insert = text("""INSERT INTO endpoint_agent_releases
            (version,platform,sha256,size_bytes,content,uploaded_at,signed_manifest)
            VALUES (:version,'linux','digest',3,:content,CURRENT_TIMESTAMP,CAST(:manifest AS json))""")
        with database.begin() as connection:
            for version, content, manifest in (
                ("legacy", b"old", None),
                ("native", b"deb", {"manifest": {"package_kind": "deb"}}),
            ):
                connection.execute(
                    insert,
                    dict(
                        version=version,
                        content=content,
                        manifest=json.dumps(manifest) if manifest else None,
                    ),
                )
        migrate.run_upgrade(url)
        read = text(
            "SELECT version,package_kind,content FROM endpoint_agent_releases ORDER BY version,package_kind"
        )
        with database.begin() as connection:
            # A refused downgrade must roll back the entire revision chain,
            # including migrations added after the release-variant change.
            head_before_downgrade = connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()
            rows = connection.execute(read).all()
            assert [
                (version, kind, bytes(content)) for version, kind, content in rows
            ] == [
                ("legacy", "binary", b"old"),
                ("native", "deb", b"deb"),
            ]
            connection.execute(
                text("""INSERT INTO endpoint_agent_releases
                (version,platform,package_kind,sha256,size_bytes,content,uploaded_at)
                VALUES ('native','linux','rpm','rpm-digest',3,:content,CURRENT_TIMESTAMP)"""),
                {"content": b"rpm"},
            )
        with pytest.raises(RuntimeError, match="duplicate installer variants"):
            migrate._downgrade("0080_endpoint_inventory_v2")
        with database.begin() as connection:
            assert (
                connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar_one()
                == head_before_downgrade
            )
            assert len(connection.execute(read).all()) == 3
            connection.execute(
                text("DELETE FROM endpoint_agent_releases WHERE package_kind='rpm'")
            )
        migrate._downgrade("0080_endpoint_inventory_v2")
        with database.connect() as connection:
            assert [
                bytes(row[0])
                for row in connection.execute(
                    text("SELECT content FROM endpoint_agent_releases ORDER BY version")
                )
            ] == [b"old", b"deb"]
        migrate.run_upgrade(url)
        with database.connect() as connection:
            assert [
                (version, kind, bytes(content))
                for version, kind, content in connection.execute(read)
            ] == [
                ("legacy", "binary", b"old"),
                ("native", "deb", b"deb"),
            ]
    finally:
        database.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
