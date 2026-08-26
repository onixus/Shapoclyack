"""Tests for historical risk score snapshots (#144, Track C)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine

from api.db.engine import _create_schema_if_unmanaged
from api.services import risk_snapshots
from api.settings import Settings
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)


def _setup_sqlite_db(tmp_path: Path) -> Settings:
    db_path = tmp_path / "risk_test.db"
    settings = Settings(
        postgres_url=f"sqlite:///{db_path}",
        output_dir=tmp_path / "output",
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    engine = create_engine(settings.postgres_url, future=True)
    _create_schema_if_unmanaged(engine)
    return settings


def test_take_and_list_snapshots(tmp_path: Path):
    settings = _setup_sqlite_db(tmp_path)
    tenant_id = "tenant-1"

    now = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
    snap = risk_snapshots.take_snapshot(
        settings,
        tenant_id=tenant_id,
        source="manual",
        now=now,
    )

    assert snap["tenant_id"] == tenant_id
    assert snap["source"] == "manual"
    assert snap["snapshot_id"].startswith("rsnap_")
    assert snap["open_total"] == 0
    assert "by_severity_open" in snap
    assert "by_risk_level_open" in snap

    # List snapshots
    history = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id)
    assert len(history) == 1
    assert history[0]["snapshot_id"] == snap["snapshot_id"]


def test_list_snapshots_time_filters(tmp_path: Path):
    settings = _setup_sqlite_db(tmp_path)
    tenant_id = "tenant-filter"

    t1 = datetime(2026, 8, 20, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 8, 21, 10, 0, 0, tzinfo=UTC)
    t3 = datetime(2026, 8, 22, 10, 0, 0, tzinfo=UTC)

    risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="run", now=t1)
    risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="run", now=t2)
    risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="run", now=t3)

    all_snaps = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id)
    assert len(all_snaps) == 3
    # Chronological ordering
    assert all_snaps[0]["recorded_at"] < all_snaps[1]["recorded_at"] < all_snaps[2]["recorded_at"]

    # Since filter
    filtered_since = risk_snapshots.list_snapshots(
        settings, tenant_id=tenant_id, since=datetime(2026, 8, 21, 0, 0, 0, tzinfo=UTC)
    )
    assert len(filtered_since) == 2

    # Until filter
    filtered_until = risk_snapshots.list_snapshots(
        settings, tenant_id=tenant_id, until=datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)
    )
    assert len(filtered_until) == 2

    # Limit keeps the *newest* rows, not the oldest ones the ASC+LIMIT query
    # used to return (#228).
    limited = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id, limit=1)
    assert [row["recorded_at"] for row in limited] == [all_snaps[2]["recorded_at"]]

    limited_two = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id, limit=2)
    assert [row["snapshot_id"] for row in limited_two] == [
        all_snaps[1]["snapshot_id"],
        all_snaps[2]["snapshot_id"],
    ]


def test_list_snapshots_limit_returns_latest_window_in_order(tmp_path: Path):
    """The dashboard asks for 30 points and must get the last 30 days (#228).

    Before the fix the query was ``ORDER BY recorded_at ASC LIMIT n``, so once
    the table held more rows than the limit the series stopped advancing: the
    chart showed the first days of the install forever. The old assertion only
    checked ``len(...)``, which is true of either end of the table.
    """
    settings = _setup_sqlite_db(tmp_path)
    tenant_id = "tenant-window"

    start = datetime(2026, 7, 1, 9, 0, 0, tzinfo=UTC)
    taken = [
        risk_snapshots.take_snapshot(
            settings, tenant_id=tenant_id, source="run", now=start + timedelta(days=day)
        )
        for day in range(40)
    ]

    window = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id, limit=30)
    recorded = [row["recorded_at"] for row in window]

    assert len(window) == 30
    assert recorded == sorted(recorded), "chart data must stay chronological"
    assert [row["snapshot_id"] for row in window] == [
        row["snapshot_id"] for row in taken[10:]
    ]


def test_prune_snapshots(tmp_path: Path):
    settings = _setup_sqlite_db(tmp_path)
    tenant_id = "tenant-prune"

    now = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
    old_time = now - timedelta(days=100)
    recent_time = now - timedelta(days=10)

    risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="scheduled", now=old_time)
    risk_snapshots.take_snapshot(settings, tenant_id=tenant_id, source="scheduled", now=recent_time)

    assert len(risk_snapshots.list_snapshots(settings, tenant_id=tenant_id)) == 2

    deleted = risk_snapshots.prune_snapshots(
        settings, tenant_id=tenant_id, retention_days=90, now=now
    )
    assert deleted == 1

    remaining = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id)
    assert len(remaining) == 1
    assert remaining[0]["source"] == "scheduled"


@requires_postgres
def test_api_risk_history_endpoints(tmp_path: Path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")

    # Initial query should be empty list
    resp = client.get("/api/vulnerabilities/risk-history", headers=viewer)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # Trigger manual snapshot via operator
    post_resp = client.post("/api/vulnerabilities/risk-history/snapshot", headers=operator)
    assert post_resp.status_code == 201
    snap = post_resp.json()
    assert snap["snapshot_id"].startswith("rsnap_")
    assert snap["source"] == "manual"

    # Viewer cannot trigger snapshot (403)
    viewer_post = client.post("/api/vulnerabilities/risk-history/snapshot", headers=viewer)
    assert viewer_post.status_code == 403

    # Check history contains the newly created snapshot
    history_resp = client.get("/api/vulnerabilities/risk-history", headers=viewer)
    assert history_resp.status_code == 200
    history = history_resp.json()
    assert len(history) >= 1
    assert any(h["snapshot_id"] == snap["snapshot_id"] for h in history)


@requires_postgres
def test_risk_history_is_single_tenant_for_platform_admin(tmp_path: Path, monkeypatch):
    """An unscoped platform admin gets one tenant's line, not two interleaved.

    ``_scope()`` returns ``None`` for them, which is right for ``/summary``
    (it sums) and wrong for a time series: snapshots of a tenant with 500 open
    findings and one with 3 landed in the same chronological list and drew a
    sawtooth (#228). The series now follows ``principal.tenant_id``, and the
    admin selects another tenant with the ``tenant_id`` query parameter.
    """
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    created = client.post(
        "/api/tenants", headers=admin, json={"name": "Other", "tenant_id": "ten_other"}
    )
    assert created.status_code == 201

    default_snap = client.post("/api/vulnerabilities/risk-history/snapshot", headers=admin)
    assert default_snap.status_code == 201
    other_snap = client.post(
        "/api/vulnerabilities/risk-history/snapshot?tenant_id=ten_other", headers=admin
    )
    assert other_snap.status_code == 201

    unscoped = client.get("/api/vulnerabilities/risk-history", headers=admin).json()
    assert {row["tenant_id"] for row in unscoped} == {"default"}
    assert any(row["snapshot_id"] == default_snap.json()["snapshot_id"] for row in unscoped)

    scoped = client.get(
        "/api/vulnerabilities/risk-history?tenant_id=ten_other", headers=admin
    ).json()
    assert {row["tenant_id"] for row in scoped} == {"ten_other"}
    assert [row["snapshot_id"] for row in scoped] == [other_snap.json()["snapshot_id"]]

    # /summary keeps the cross-tenant view: summing several tenants is a
    # meaningful number, unlike concatenating their histories.
    assert client.get("/api/vulnerabilities/summary", headers=admin).status_code == 200


def test_retention_sweep_prunes_every_tenant(tmp_path: Path):
    """#229: the table had a ``prune_snapshots()`` nobody ever called.

    One row per tenant per run, no sweep and no setting — migration 0023 landed
    after #187 closed, so the table sat outside the growth bounds. The sweep is
    the worker's tick, and it must cover tenants it was never told about.
    """
    settings = _setup_sqlite_db(tmp_path)
    settings.risk_snapshot_retention_days = 90

    now = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
    kept: dict[str, str] = {}
    for tenant_id in ("tenant-a", "tenant-b"):
        risk_snapshots.take_snapshot(
            settings, tenant_id=tenant_id, source="run", now=now - timedelta(days=120)
        )
        fresh = risk_snapshots.take_snapshot(
            settings, tenant_id=tenant_id, source="run", now=now - timedelta(days=5)
        )
        kept[tenant_id] = fresh["snapshot_id"]

    assert risk_snapshots.sweep(settings, now=now) == {"deleted": 2}
    for tenant_id in ("tenant-a", "tenant-b"):
        remaining = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id)
        assert [row["snapshot_id"] for row in remaining] == [kept[tenant_id]]

    # A second sweep has nothing left to do, and 0 days disables it entirely.
    assert risk_snapshots.sweep(settings, now=now) == {"deleted": 0}
    settings.risk_snapshot_retention_days = 0
    risk_snapshots.take_snapshot(
        settings, tenant_id="tenant-a", source="run", now=now - timedelta(days=400)
    )
    assert risk_snapshots.sweep(settings, now=now) == {"deleted": 0}
    assert len(risk_snapshots.list_snapshots(settings, tenant_id="tenant-a")) == 2


def test_app_lifespan_starts_the_retention_worker(tmp_path: Path, monkeypatch):
    """The sweep has to be wired, not merely written.

    ``prune_snapshots`` existed from the start and was called by nothing but its
    own test, which is how `risk_score_snapshots` grew unbounded while #187 was
    marked done (#229). A worker no lifespan starts is the same defect one layer
    up, so this asserts the wiring rather than the sweep.
    """
    from fastapi.testclient import TestClient

    from api.app import create_app
    from api.services import risk_snapshots

    settings = make_settings(tmp_path)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)

    assert settings.risk_snapshot_retention_enabled is True
    risk_snapshots.stop_worker()
    with TestClient(create_app()):
        assert risk_snapshots.worker_stats() is not None
    # ...and released on shutdown, so a second app does not inherit a thread.
    assert risk_snapshots.worker_stats() is None
