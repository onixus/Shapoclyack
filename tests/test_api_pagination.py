"""Server-side pagination across the list endpoints (ROADMAP P3.2).

Every list route answers with the same envelope — ``items``/``total``/
``offset``/``limit``/``has_more`` — with ``total`` counted after filtering,
so these tests assert the contract once per resource rather than per field.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.settings import Settings
from tests.conftest import configured_client, login, make_settings, requires_postgres

pytestmark = requires_postgres


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **overrides)


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **overrides)


def _headers(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client, "operator")}"}


def _seed_runs(settings_output: Path, count: int) -> None:
    for index in range(count):
        run_dir = settings_output / "runs" / f"20260801T00{index:02d}00Z"
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "run_meta.json").write_text(
            json.dumps({"profile": "balanced", "started_at": "2026-08-01T00:00:00Z"}), encoding="utf-8"
        )
        (run_dir / "summary.json").write_text(json.dumps({"alive_hosts": index}), encoding="utf-8")


def _seed_agents(count: int) -> None:
    from api.services import agents as agents_service

    for index in range(count):
        agents_service.register_agent(
            agent_id=f"agent-{index:02d}",
            hostname=f"worker-{index:02d}",
            version="1.0.0",
            labels={},
            tenant_id="default",
        )


def _seed_schedules(count: int) -> None:
    from api.services import scan_schedules

    for index in range(count):
        scan_schedules.create_schedule(
            tenant_id="default",
            name=f"nightly-{index:02d}",
            cron=None,
            interval_seconds=3600,
            scan_options={"mode": "balanced"},
            targets={"ranges": "10.0.0.0/30"},
            created_by="tester",
        )


def _assert_envelope(body: dict, *, total: int, offset: int, limit: int, items: int) -> None:
    assert body["total"] == total
    assert body["offset"] == offset
    assert body["limit"] == limit
    assert len(body["items"]) == items
    assert body["has_more"] is (offset + items < total)


def test_runs_pagination_walks_every_page_without_repeats(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_runs(tmp_path / "output", 5)
    headers = _headers(client)

    seen: list[str] = []
    for offset in (0, 2, 4):
        body = client.get("/api/runs", headers=headers, params={"offset": offset, "limit": 2}).json()
        _assert_envelope(body, total=5, offset=offset, limit=2, items=2 if offset < 4 else 1)
        seen.extend(item["run_id"] for item in body["items"])

    assert len(seen) == len(set(seen)) == 5
    # Default order is newest run_id first.
    assert seen == sorted(seen, reverse=True)


def test_runs_query_filters_before_counting(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_runs(tmp_path / "output", 5)
    body = client.get("/api/runs", headers=_headers(client), params={"q": "000200Z"}).json()
    _assert_envelope(body, total=1, offset=0, limit=100, items=1)


def test_runs_ascending_order_reverses_the_page(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_runs(tmp_path / "output", 3)
    headers = _headers(client)
    desc = client.get("/api/runs", headers=headers).json()["items"]
    asc = client.get("/api/runs", headers=headers, params={"order": "asc"}).json()["items"]
    assert [r["run_id"] for r in asc] == [r["run_id"] for r in reversed(desc)]


def test_agents_pagination_sorting_and_search(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_agents(4)
    headers = _headers(client)

    first = client.get("/api/agents", headers=headers, params={"limit": 3, "order": "asc"}).json()
    _assert_envelope(first, total=4, offset=0, limit=3, items=3)
    assert [a["hostname"] for a in first["items"]] == ["worker-00", "worker-01", "worker-02"]

    last = client.get(
        "/api/agents", headers=headers, params={"offset": 3, "limit": 3, "order": "asc"}
    ).json()
    _assert_envelope(last, total=4, offset=3, limit=3, items=1)
    assert last["has_more"] is False

    searched = client.get("/api/agents", headers=headers, params={"q": "worker-01"}).json()
    _assert_envelope(searched, total=1, offset=0, limit=100, items=1)


def test_schedules_pagination_is_sql_backed_and_tenant_scoped(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _seed_schedules(3)
    headers = _headers(client)

    page = client.get(
        "/api/schedules", headers=headers, params={"limit": 2, "sort": "name", "order": "asc"}
    ).json()
    _assert_envelope(page, total=3, offset=0, limit=2, items=2)
    assert [s["name"] for s in page["items"]] == ["nightly-00", "nightly-01"]

    searched = client.get("/api/schedules", headers=headers, params={"q": "nightly-02"}).json()
    _assert_envelope(searched, total=1, offset=0, limit=100, items=1)

    # Tenant scoping itself is covered in tests/test_tenant_iam.py (P0); here
    # it only matters that an unauthorised tenant never yields a page.
    other_tenant = client.get(
        "/api/schedules", headers=headers, params={"tenant_id": "ten_missing"}
    )
    assert other_tenant.status_code == 403


def test_assets_pagination_counts_after_the_identifier_filter(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    from api.db import models
    from api.db.engine import get_session
    from datetime import UTC, datetime

    settings = _settings(tmp_path)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        for index in range(4):
            asset_id = f"asset-{index:02d}"
            session.add(
                models.Asset(
                    asset_id=asset_id,
                    tenant_id="default",
                    status="active",
                    first_seen=now,
                    last_seen=now,
                )
            )
            session.add(
                models.AssetIdentifier(
                    asset_id=asset_id,
                    tenant_id="default",
                    identifier_type="ip",
                    identifier_value=f"10.0.0.{index}",
                )
            )

    headers = _headers(client)
    try:
        page = client.get(
            "/api/assets", headers=headers, params={"limit": 2, "sort": "asset_id", "order": "asc"}
        ).json()
        _assert_envelope(page, total=4, offset=0, limit=2, items=2)
        assert [a["asset_id"] for a in page["items"]] == ["asset-00", "asset-01"]

        # `q` narrows the count itself — not just the rows already fetched.
        filtered = client.get("/api/assets", headers=headers, params={"q": "10.0.0.3"}).json()
        _assert_envelope(filtered, total=1, offset=0, limit=100, items=1)
    finally:
        with get_session(settings.postgres_url) as session:
            session.query(models.AssetIdentifier).delete()
            session.query(models.Asset).delete()


def test_invalid_pagination_params_are_rejected(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    headers = _headers(client)
    assert client.get("/api/runs", headers=headers, params={"offset": -1}).status_code == 422
    assert client.get("/api/runs", headers=headers, params={"limit": 0}).status_code == 422
    assert client.get("/api/runs", headers=headers, params={"limit": 999999}).status_code == 422
    assert client.get("/api/runs", headers=headers, params={"order": "sideways"}).status_code == 422


def test_unknown_sort_field_falls_back_to_the_default(tmp_path, monkeypatch):
    """A stale client asking for a column that no longer exists still gets a
    usable page instead of a 4xx."""
    client = _client(tmp_path, monkeypatch)
    _seed_agents(2)
    headers = _headers(client)
    body = client.get("/api/agents", headers=headers, params={"sort": "no_such_column"}).json()
    _assert_envelope(body, total=2, offset=0, limit=100, items=2)
