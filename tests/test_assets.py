"""Phase 7 asset inventory: identity keys + cross-run upsert/staleness."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scanner.pipeline.asset_identity import (
    fqdn_identity_key,
    identity_candidates_for_host,
    ip_identity_key,
)
from tests.conftest import POSTGRES_URL, requires_postgres


def test_ip_identity_key_stable_and_namespaced():
    a = ip_identity_key("ten_a", "10.0.0.5")
    b = ip_identity_key("ten_a", "10.0.0.5")
    c = ip_identity_key("ten_b", "10.0.0.5")
    assert a == b
    assert a != c  # tenant-namespaced


def test_fqdn_identity_key_case_insensitive():
    a = fqdn_identity_key("ten_a", "App.Example.com")
    b = fqdn_identity_key("ten_a", "app.example.com ")
    assert a == b


def test_identity_candidates_for_host_ip_and_fqdn():
    candidates = identity_candidates_for_host(
        "ten_a", host_ip="10.0.0.5", hostnames=["app.example.com", ""]
    )
    types = {c.identifier_type for c in candidates}
    assert types == {"ip", "fqdn"}


def test_identity_candidates_for_host_empty():
    assert identity_candidates_for_host("ten_a", host_ip=None, hostnames=[]) == []


def _write_run(output_dir: Path, run_id: str, hosts: list[dict]) -> None:
    run_dir = output_dir / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(hosts), encoding="utf-8")


@requires_postgres
def test_upsert_assets_from_run_idempotent_and_stale(tmp_path):
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service
    from api.settings import Settings

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=POSTGRES_URL,
        asset_stale_days=14,
    )
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    tenants_service.load_tenants(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)  # reseed "default" after reset

    tenant_id = tenants_service.DEFAULT_TENANT_ID
    hosts = [
        {"host": "10.0.0.5", "hostname": "app.example.com"},
        {"host": "10.0.0.6", "names": ["db.example.com"]},
    ]
    _write_run(settings.output_dir, "run-1", hosts)

    stats1 = assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    assert stats1.hosts_seen == 2
    assert stats1.assets_created == 2
    assert stats1.assets_updated == 0

    listed = assets_service.list_assets(settings, tenant_id)
    assert len(listed) == 2

    # Re-ingesting the same run must not duplicate assets/identifiers.
    stats2 = assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    assert stats2.assets_created == 0
    assert stats2.assets_updated == 2
    listed_again = assets_service.list_assets(settings, tenant_id)
    assert len(listed_again) == 2

    detail = assets_service.get_asset(settings, tenant_id, listed[0]["asset_id"])
    assert detail is not None
    assert detail["identifiers"]

    # Force staleness by backdating last_seen directly, then confirm the
    # threshold flips status without a fresh ingest re-observing the asset.
    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        for asset_id in [row["asset_id"] for row in listed]:
            asset = session.get(models.Asset, asset_id)
            asset.last_seen = datetime.now(UTC) - timedelta(days=30)

    marked = assets_service.mark_stale_assets(settings, tenant_id=tenant_id)
    assert marked == 2
    stale = assets_service.list_assets(settings, tenant_id, status="stale")
    assert len(stale) == 2


def _settings_with_tenant(tmp_path: Path):
    from api.services import tenants as tenants_service
    from api.settings import Settings

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=POSTGRES_URL,
        asset_stale_days=14,
    )
    settings.output_dir.mkdir(parents=True)
    settings.state_dir.mkdir(parents=True)
    tenants_service.load_tenants(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    return settings, tenants_service.DEFAULT_TENANT_ID


@requires_postgres
def test_get_asset_criticality_by_ip_unset_then_set(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.5"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")

    assert assets_service.get_asset_criticality_by_ip(settings, tenant_id, "10.0.1.5") is None

    asset_id = ip_identity_key(tenant_id, "10.0.1.5")
    assets_service.update_asset(settings, tenant_id, asset_id, {"asset_criticality": 3})
    assert assets_service.get_asset_criticality_by_ip(settings, tenant_id, "10.0.1.5") == 3


@requires_postgres
def test_get_asset_criticality_by_ip_missing_asset_or_wrong_tenant(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    assert assets_service.get_asset_criticality_by_ip(settings, tenant_id, "10.9.9.9") is None
    assert assets_service.get_asset_criticality_by_ip(settings, "ten_other", "10.9.9.9") is None


@requires_postgres
def test_update_asset_partial_update_does_not_clobber_other_fields(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.6"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    asset_id = ip_identity_key(tenant_id, "10.0.1.6")

    updated = assets_service.update_asset(
        settings, tenant_id, asset_id, {"owner_email": "owner@example.com", "asset_criticality": 2}
    )
    assert updated["owner_email"] == "owner@example.com"
    assert updated["asset_criticality"] == 2

    updated_again = assets_service.update_asset(
        settings, tenant_id, asset_id, {"business_unit": "finance"}
    )
    assert updated_again["business_unit"] == "finance"
    assert updated_again["owner_email"] == "owner@example.com"
    assert updated_again["asset_criticality"] == 2


@requires_postgres
def test_update_asset_rejects_out_of_range_criticality(tmp_path):
    import pytest

    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.7"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    asset_id = ip_identity_key(tenant_id, "10.0.1.7")

    with pytest.raises(ValueError):
        assets_service.update_asset(settings, tenant_id, asset_id, {"asset_criticality": 9})


@requires_postgres
def test_update_asset_returns_none_for_unknown_or_cross_tenant_asset(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.8"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    asset_id = ip_identity_key(tenant_id, "10.0.1.8")

    assert assets_service.update_asset(settings, tenant_id, "no-such-asset", {"asset_criticality": 1}) is None
    assert assets_service.update_asset(settings, "ten_other", asset_id, {"asset_criticality": 1}) is None
