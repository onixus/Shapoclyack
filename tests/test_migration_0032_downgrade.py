"""``0032``'s downgrade, on a database that really has software findings.

``0032`` adds ``vulnerabilities.source`` and ``vulnerabilities.device_id``, and
those two columns are the *only* thing that tells a software finding from a
scan one. Dropping them is not a symmetric operation: an upgrade afterwards
re-adds ``source`` with its ``scan`` server default and ``device_id`` as NULL,
so every software finding comes back wearing a scan finding's clothes. It stops
being a 409 on ``/verify``, drops out of ``existing`` in ``_fold_device`` — the
fold reads a device's findings by ``device_id`` — and the next inventory
snapshot therefore creates a full duplicate set beside it while the originals
sit open forever under keys nothing looks up.

There is no way to preserve the distinction in a database that has no column
for it, so the downgrade deletes the rows it cannot label rather than leaving
them to poison the table. That is destructive, it is the only two-way door
available, and it is the reason the docstring and ``docs/operations.md`` both
name this revision as one to plan a rollback around.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    """A sibling database that exists only for this test, as in
    ``tests/test_migration_0025_grandfather.py``."""
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"down0032_{uuid.uuid4().hex[:10]}"
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


def _seed(engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('default', 'Default', 'active', now())"
            )
        )
        conn.execute(
            text(
                "INSERT INTO assets (asset_id, tenant_id, status, first_seen, last_seen) "
                "VALUES ('ast_1', 'default', 'active', now(), now())"
            )
        )
        conn.execute(
            text(
                "INSERT INTO endpoint_devices "
                "(device_id, tenant_id, agent_id, asset_id, hostname, agent_version, "
                " labels, reconciliation_status, first_seen, last_seen) "
                "VALUES ('dev_1', 'default', 'agent-1', 'ast_1', 'host-1', '1.0', "
                "        '{}', 'linked', now(), now())"
            )
        )
        for vuln_id, source, device_id in (
            ("vln_scan", "scan", None),
            ("vln_software", "endpoint_software", "dev_1"),
        ):
            conn.execute(
                text(
                    "INSERT INTO vulnerabilities "
                    "(vuln_id, tenant_id, asset_id, finding_key, source, device_id, cve, "
                    " state, state_changed_at, first_seen_at, last_seen_at, sla_started_at, "
                    " observation_count, created_at, updated_at) "
                    "VALUES (:vuln_id, 'default', 'ast_1', :key, :source, :device_id, "
                    "        'CVE-2023-38545', 'OPEN', now(), now(), now(), now(), 1, now(), now())"
                ),
                {
                    "vuln_id": vuln_id,
                    "key": f"key-{vuln_id}",
                    "source": source,
                    "device_id": device_id,
                },
            )


def test_downgrading_past_0032_does_not_leave_software_findings_as_scan_findings(
    fresh_database, tmp_path
) -> None:
    url = fresh_database
    migrate._upgrade("head")  # noqa: SLF001
    engine = create_engine(url, future=True)
    try:
        _seed(engine)

        migrate._downgrade("0031_tenant_promoted_domains")  # noqa: SLF001
        migrate._upgrade("head")  # noqa: SLF001

        with engine.begin() as conn:
            rows = conn.execute(
                text("SELECT vuln_id, source, device_id FROM vulnerabilities ORDER BY vuln_id")
            ).all()
        # The scan finding is untouched. The software one is gone rather than
        # sitting there as a `source = 'scan'`, `device_id IS NULL` row that
        # the next fold would duplicate and never close.
        assert [(row.vuln_id, row.source, row.device_id) for row in rows] == [
            ("vln_scan", "scan", None)
        ]
    finally:
        engine.dispose()
