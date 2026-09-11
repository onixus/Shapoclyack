"""Migration ``0056``'s marker fold, on a database that was really at ``0053``.

``agent_offline`` used to be claimed under the agent's ``last_seen_at``, which
is why #349 happened: a degraded agent presented a new-but-still-stale
timestamp on every tick and was announced on every one of them. The new claim
is the constant ``"offline"``, one row per agent, held for the episode.

That leaves the upgrade itself to answer for: the old rows key nothing the new
code looks for, so without the fold the first tick after an upgrade would take
a fresh claim for every agent that was *already* quiet and announce the lot
again. ``webhook_deliveries`` would de-duplicate that by ``event_id``, but the
copy published to NATS would not be — the content window is minutes wide and
these agents have been silent for hours.

So the revision rewrites the standing claims, and this module checks it on a
database that really holds them. Postgres only, and a sibling database of its
own, as in ``test_migration_0025_grandfather``: the CI database is migrated to
head before the suite starts, so nothing in it ever runs ``0056`` over rows.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres

_QUIET_AT = datetime(2026, 9, 1, 8, 0, tzinfo=UTC).replace(tzinfo=None)


@pytest.fixture
def fresh_database(monkeypatch: pytest.MonkeyPatch):
    """A sibling database that exists only for this test; ``OCTO_POSTGRES_URL``
    points at it so Alembic's ``env.py`` migrates it and nothing else."""
    admin = create_engine(POSTGRES_URL, future=True, isolation_level="AUTOCOMMIT")
    name = f"mk0056_{uuid.uuid4().hex[:10]}"
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


def _claim(conn, *, subject_id: str, marker: str, created_at: datetime) -> None:
    conn.execute(
        text(
            "INSERT INTO workflow_event_markers "
            "(marker_id, tenant_id, kind, subject_id, marker, created_at) "
            "VALUES (:id, 'acme', :kind, :subject, :marker, :at)"
        ),
        {
            "id": f"wem_{uuid.uuid4().hex[:16]}",
            "kind": "sla_breached" if subject_id.startswith("vln") else "agent_offline",
            "subject": subject_id,
            "marker": marker,
            "at": created_at,
        },
    )


def test_upgrading_past_0056_folds_the_standing_offline_claims(fresh_database):
    url = fresh_database
    migrate._upgrade("0053_tenant_scan_policy")  # noqa: SLF001

    engine = create_engine(url, future=True)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('acme', 'Acme', 'active', now())"
            )
        )
        # ``agent-1`` is the storm: one claim per tick, each under a different
        # last beat. ``agent-2`` went quiet once and stayed quiet.
        for minutes in (0, 15, 30):
            _claim(
                conn,
                subject_id="agent-1",
                marker=(_QUIET_AT + timedelta(minutes=minutes)).isoformat(),
                created_at=_QUIET_AT + timedelta(minutes=minutes + 1),
            )
        _claim(
            conn,
            subject_id="agent-2",
            marker=_QUIET_AT.isoformat(),
            created_at=_QUIET_AT,
        )
        # Another kind, keyed on a deadline, which this fold must not touch.
        _claim(conn, subject_id="vln-1", marker="2026-08-30T00:00:00", created_at=_QUIET_AT)
    engine.dispose()

    migrate._upgrade("head")  # noqa: SLF001

    engine = create_engine(url, future=True)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT kind, subject_id, marker, created_at FROM workflow_event_markers "
                "ORDER BY kind, subject_id, marker"
            )
        ).all()
    engine.dispose()

    assert [(kind, subject, marker) for kind, subject, marker, _ in rows] == [
        ("agent_offline", "agent-1", "offline"),
        ("agent_offline", "agent-2", "offline"),
        ("sla_breached", "vln-1", "2026-08-30T00:00:00"),
    ]
    # The claim is dated from the last time the agent was announced, not the
    # first: the worker releases a claim only for a run of heartbeats that
    # began after it was taken, so the newest of the old rows is both the
    # honest date and the conservative one.
    assert rows[0].created_at == _QUIET_AT + timedelta(minutes=31)
