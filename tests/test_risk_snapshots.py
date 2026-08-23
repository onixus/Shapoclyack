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

    # Limit
    limited = risk_snapshots.list_snapshots(settings, tenant_id=tenant_id, limit=1)
    assert len(limited) == 1


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
