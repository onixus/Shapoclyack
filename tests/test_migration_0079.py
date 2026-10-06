"""``0079`` on a database that already has findings (#451).

The backfill is the half a test that builds its state from scratch cannot
check: rows written before the column existed have to come out of the upgrade
with the detector their ``script_id`` names — and with nothing invented where
it names none.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

BEFORE = "0077_agent_client_certs"
REVISION = "0079_vuln_detectors"


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mig0079_{uuid.uuid4().hex[:10]}"
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


#: (vuln_id, source, script_id, port) as an older release wrote them.
ROWS = [
    ("vln_nuclei", "scan", "nuclei:CVE-2021-44228", "8080"),
    ("vln_pulse", "scan", "pulse:local", "22"),
    ("vln_pulse_exposure", "scan", "pulse:exposure:443:open-admin", "443"),
    ("vln_nse", "scan", "vulners", "443"),
    ("vln_bare", "scan", None, "80"),
    ("vln_blank", "scan", "  ", "81"),
    ("vln_software", "endpoint_software", None, None),
    ("vln_retro", "retro_match", None, "22"),
]


def _seed(conn) -> None:
    conn.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, status, created_at) "
            "VALUES ('acme', 'acme', 'active', now())"
        )
    )
    conn.execute(
        text(
            "INSERT INTO assets (asset_id, tenant_id, first_seen, last_seen) "
            "VALUES ('ast_1', 'acme', now(), now())"
        )
    )
    for vuln_id, source, script_id, port in ROWS:
        conn.execute(
            text(
                "INSERT INTO vulnerabilities (vuln_id, tenant_id, asset_id, finding_key, source, "
                "cve, script_id, port, state, state_changed_at, first_seen_at, last_seen_at, "
                "sla_started_at, last_seen_run_id, created_at, updated_at) VALUES "
                "(:v, 'acme', 'ast_1', :v, :source, 'CVE-2024-0001', :script, :port, 'OPEN', "
                "now(), now(), '2026-10-01 12:00:00', now(), 'run-old', now(), now())"
            ),
            {"v": vuln_id, "source": source, "script": script_id, "port": port},
        )


def _detectors(conn) -> dict[str, list]:
    rows = conn.execute(text("SELECT vuln_id, detectors FROM vulnerabilities")).all()
    return {
        vuln_id: (json.loads(value) if isinstance(value, str) else value) for vuln_id, value in rows
    }


def test_the_upgrade_derives_detectors_from_existing_rows(fresh_database):
    url = fresh_database
    migrate._upgrade(BEFORE)  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        with engine.begin() as conn:
            _seed(conn)

        migrate._upgrade(REVISION)  # noqa: SLF001
        with engine.connect() as conn:
            found = _detectors(conn)

        def only(vuln_id: str) -> dict:
            assert len(found[vuln_id]) == 1, found[vuln_id]
            return found[vuln_id][0]

        assert only("vln_nuclei") == {
            "detector": "nuclei",
            "ref": "CVE-2021-44228",
            # Never stored before 0079: the closure falls back to the asset's
            # own addresses for this entry.
            "host": None,
            "port": "8080",
            "last_run_id": "run-old",
            "last_seen_at": "2026-10-01T12:00:00Z",
        }
        assert (only("vln_pulse")["detector"], only("vln_pulse")["ref"]) == ("pulse", "local")
        assert only("vln_pulse_exposure")["ref"] == "exposure:443:open-admin"
        assert (only("vln_nse")["detector"], only("vln_nse")["ref"]) == ("nmap-nse", "vulners")
        # Nothing to derive from, and nothing invented: "unknown", which the
        # closure holds to the legacy rule.
        for vuln_id in ("vln_bare", "vln_blank", "vln_software", "vln_retro"):
            assert found[vuln_id] == [], vuln_id

        migrate._downgrade(BEFORE)  # noqa: SLF001
        columns = {c["name"] for c in inspect(engine).get_columns("vulnerabilities")}
        assert "detectors" not in columns
        migrate._upgrade(REVISION)  # noqa: SLF001
        with engine.connect() as conn:
            assert _detectors(conn)["vln_nuclei"][0]["ref"] == "CVE-2021-44228"
    finally:
        engine.dispose()
