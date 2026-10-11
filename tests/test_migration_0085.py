"""0085 removes the two console overrides that only the Nmap stage understood (#548)."""

from __future__ import annotations

import importlib
import json
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

migration = importlib.import_module("api.db.migrations.versions.0085_drop_nmap_config_overrides")


def test_strip_removes_only_nmap_timing_and_shadow():
    stored = {
        "nuclei": {"enabled": True},
        "service_probe": {"backend": "pulse", "shadow": True},
        "profiles": {
            "safe": {"nmap_timing": "T2", "port_rate": 100},
            "fast": {"top_ports": 1000},
        },
    }
    assert migration.strip_removed_keys(stored) == {
        "nuclei": {"enabled": True},
        "service_probe": {"backend": "pulse"},
        "profiles": {"safe": {"port_rate": 100}, "fast": {"top_ports": 1000}},
    }
    # The input is not edited in place.
    assert stored["profiles"]["safe"]["nmap_timing"] == "T2"


def test_strip_leaves_a_stored_backend_alone_even_when_it_is_nmap():
    """Not ours to swap: ``nmap`` there is a choice the operator has to make
    again, and the scan failure names it."""
    stored = {"service_probe": {"backend": "nmap"}}
    assert migration.strip_removed_keys(stored) is None


def test_strip_reports_unchanged_documents_as_none():
    assert migration.strip_removed_keys({}) is None
    assert migration.strip_removed_keys({"profiles": {"safe": {"port_rate": 1}}}) is None
    assert migration.strip_removed_keys(None) is None


@requires_postgres
def test_upgrade_rewrites_the_stored_row_and_downgrade_is_a_no_op(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0085_" + uuid.uuid4().hex[:12]
    with admin.connect() as connection:
        connection.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    database = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0084_asset_service_distro")
        stored = {
            "service_probe": {"backend": "hybrid", "shadow": True},
            "profiles": {"balanced": {"nmap_timing": "T3", "port_rate": 900}},
        }
        with database.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO config_overrides (scope, data, updated_at) "
                    "VALUES ('global', CAST(:data AS JSON), CURRENT_TIMESTAMP)"
                ),
                {"data": json.dumps(stored)},
            )
        migrate.run_upgrade(url)
        with database.connect() as connection:
            data = connection.execute(text("SELECT data FROM config_overrides")).scalar_one()
        assert data == {
            "service_probe": {"backend": "hybrid"},
            "profiles": {"balanced": {"port_rate": 900}},
        }
        migrate._downgrade("0084_asset_service_distro")  # noqa: SLF001
        with database.connect() as connection:
            assert connection.execute(text("SELECT data FROM config_overrides")).scalar_one() == data
    finally:
        database.dispose()
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()
