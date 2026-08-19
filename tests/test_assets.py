"""Phase 7 asset inventory: identity keys + cross-run upsert/staleness."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from scanner.pipeline.asset_identity import (
    CERTIFICATE,
    FORWARD_DNS,
    correlate_identities,
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


def test_bare_fqdn_host_is_not_stored_as_an_ip():
    candidates = identity_candidates_for_host("ten_a", host_ip="app.example.com")
    assert [(c.identifier_type, c.identifier_value) for c in candidates] == [
        ("fqdn", "app.example.com")
    ]


def test_correlate_requires_forward_dns_and_certificate():
    cert = {"dns": ["app.example.com"], "ip": [], "common_name": ["app.example.com"]}
    both = correlate_identities(
        forward={"1.2.3.4": {"app.example.com"}},
        certs_by_ip={"1.2.3.4": [cert]},
    )
    assert len(both) == 1
    assert both[0].mergeable
    assert both[0].sources == (CERTIFICATE, FORWARD_DNS)

    dns_only = correlate_identities(forward={"1.2.3.4": {"app.example.com"}}, certs_by_ip={})
    assert dns_only[0].confidence == "low"
    assert not dns_only[0].mergeable

    cert_only = correlate_identities(forward={}, certs_by_ip={"1.2.3.4": [cert]})
    assert cert_only == []


def test_wildcard_cert_confirms_a_forward_name():
    cert = {"dns": ["*.example.com"], "ip": [], "common_name": []}
    links = correlate_identities(
        forward={"1.2.3.4": {"app.example.com"}},
        certs_by_ip={"1.2.3.4": [cert]},
    )
    assert links[0].mergeable


def test_shared_hosting_is_not_mergeable():
    cert = {
        "dns": ["a.example.com", "b.example.com"],
        "ip": [],
        "common_name": [],
    }
    links = correlate_identities(
        forward={"1.2.3.4": {"a.example.com", "b.example.com"}},
        certs_by_ip={"1.2.3.4": [cert]},
    )
    assert {link.fqdn for link in links} == {"a.example.com", "b.example.com"}
    assert all(link.shared and not link.mergeable for link in links)


def test_cdn_san_does_not_invent_an_unresolved_name():
    cert = {"dns": ["unrelated.cdn.example"], "ip": [], "common_name": []}
    links = correlate_identities(
        forward={"1.2.3.4": {"app.example.com"}},
        certs_by_ip={"1.2.3.4": [cert]},
    )
    assert [link.fqdn for link in links] == ["app.example.com"]
    assert not links[0].mergeable
    assert CERTIFICATE not in links[0].sources


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

    listed, total = assets_service.list_assets(settings, tenant_id)
    assert len(listed) == total == 2

    # Re-ingesting the same run must not duplicate assets/identifiers.
    stats2 = assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    assert stats2.assets_created == 0
    assert stats2.assets_updated == 2
    listed_again, total_again = assets_service.list_assets(settings, tenant_id)
    assert len(listed_again) == total_again == 2

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
    stale, stale_total = assets_service.list_assets(settings, tenant_id, status="stale")
    assert len(stale) == stale_total == 2


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


@requires_postgres
def test_update_asset_decommission_transition_logs_event(tmp_path, caplog):
    import logging

    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.9"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    asset_id = ip_identity_key(tenant_id, "10.0.1.9")

    with caplog.at_level(logging.INFO, logger="shapoclyack.assets"):
        updated = assets_service.update_asset(settings, tenant_id, asset_id, {"status": "decommissioned"})
    assert updated["status"] == "decommissioned"
    assert any("decommissioned_host" in record.message for record in caplog.records)

    # A repeat PATCH once already decommissioned is a no-op, not a new event.
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="shapoclyack.assets"):
        updated_again = assets_service.update_asset(settings, tenant_id, asset_id, {"status": "decommissioned"})
    assert updated_again["status"] == "decommissioned"
    assert not any("decommissioned_host" in record.message for record in caplog.records)


@requires_postgres
def test_update_asset_rejects_non_decommissioned_status(tmp_path):
    import pytest

    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_run(settings.output_dir, "run-1", [{"host": "10.0.1.10"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    asset_id = ip_identity_key(tenant_id, "10.0.1.10")

    with pytest.raises(ValueError):
        assets_service.update_asset(settings, tenant_id, asset_id, {"status": "active"})


@requires_postgres
def test_list_assets_fetches_page_identifiers_in_one_query(tmp_path):
    """ROADMAP P3.8: identifiers used to be fetched per asset, so a page of N
    cost N+2 statements — invisible on a local socket, dominant over a network
    (the dashboard's limit=5000 page issued 5002 statements). Counting
    statements is the only way to keep the regression from creeping back."""
    from sqlalchemy import event

    from api.db.engine import get_engine
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    hosts = [
        {"host": f"10.0.2.{i}", "names": [f"h{i}.example.com"]} for i in range(1, 21)
    ]
    _write_run(settings.output_dir, "run-batch", hosts)
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-batch")

    statements: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    engine = get_engine(settings.postgres_url)
    event.listen(engine, "before_cursor_execute", record)
    try:
        page, total = assets_service.list_assets(settings, tenant_id, limit=20)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert total == 20
    assert len(page) == 20
    # Every asset still resolves both of its identifiers.
    assert all(row["identifier_count"] == 2 for row in page)
    assert all(row["primary_identifier"].startswith("10.0.2.") for row in page)

    identifier_selects = [
        s for s in statements if "asset_identifiers" in s and s.strip().upper().startswith("SELECT")
    ]
    assert len(identifier_selects) == 1, f"expected one batched fetch, got {len(identifier_selects)}"


@requires_postgres
def test_list_assets_empty_page_skips_the_identifier_query(tmp_path):
    from sqlalchemy import event

    from api.db.engine import get_engine
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    statements: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    engine = get_engine(settings.postgres_url)
    event.listen(engine, "before_cursor_execute", record)
    try:
        page, total = assets_service.list_assets(settings, tenant_id, limit=20)
    finally:
        event.remove(engine, "before_cursor_execute", record)

    assert page == [] and total == 0
    # An empty IN () list is either a syntax error or a full scan depending on
    # the dialect, so the batch fetch must be skipped entirely.
    assert not [
        s for s in statements if "asset_identifiers" in s and s.strip().upper().startswith("SELECT")
    ]
    assert not [
        s for s in statements if "vulnerabilities" in s and s.strip().upper().startswith("SELECT")
    ]


def _write_identity_run(
    output_dir: Path,
    run_id: str,
    hosts: list[dict],
    *,
    hostnames: dict | None = None,
    tls: dict | None = None,
) -> None:
    _write_run(output_dir, run_id, hosts)
    run_dir = output_dir / "runs" / run_id
    if hostnames is not None:
        (run_dir / "hostnames.json").write_text(json.dumps(hostnames), encoding="utf-8")
    if tls is not None:
        (run_dir / "tls_posture.json").write_text(json.dumps(tls), encoding="utf-8")


@requires_postgres
def test_p42_merges_ip_and_fqdn_when_cert_and_forward_agree(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_identity_run(settings.output_dir, "run-ip", [{"host": "8.8.8.8"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-ip")
    ip_id = ip_identity_key(tenant_id, "8.8.8.8")
    assets_service.update_asset(settings, tenant_id, ip_id, {"asset_criticality": 4})

    _write_identity_run(settings.output_dir, "run-fqdn", [{"host": "app.example.com"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-fqdn")
    _, total = assets_service.list_assets(settings, tenant_id)
    assert total == 2

    _write_identity_run(
        settings.output_dir,
        "run-join",
        [{"host": "8.8.8.8"}, {"host": "app.example.com"}],
        hostnames={"8.8.8.8": {"forward": ["app.example.com"], "reverse": ["ptr.example.net"]}},
        tls={
            "findings": [
                {
                    "host": "8.8.8.8",
                    "port": "443",
                    "cert": {"subject": "CN=app.example.com", "san": "DNS:app.example.com"},
                }
            ]
        },
    )
    stats = assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-join")
    assert stats.identities_merged >= 1
    listed, total = assets_service.list_assets(settings, tenant_id)
    assert total == 1
    detail = assets_service.get_asset(settings, tenant_id, listed[0]["asset_id"])
    kinds = {row["identifier_type"]: row["identifier_value"] for row in detail["identifiers"]}
    assert kinds["ip"] == "8.8.8.8"
    assert kinds["fqdn"] == "app.example.com"
    assert detail["asset_criticality"] == 4
    assert any(link["merged"] and "certificate" in link["sources"] for link in detail["identity_links"])
    assert all(link["fqdn"] != "ptr.example.net" for link in detail["identity_links"])
    assert assets_service.get_asset_criticality_by_ip(settings, tenant_id, "8.8.8.8") == 4


@requires_postgres
def test_p42_shared_hosting_does_not_merge(tmp_path):
    from api.services import assets as assets_service

    settings, tenant_id = _settings_with_tenant(tmp_path)
    _write_identity_run(settings.output_dir, "run-a", [{"host": "a.example.com"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-a")
    _write_identity_run(settings.output_dir, "run-b", [{"host": "b.example.com"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-b")
    _write_identity_run(settings.output_dir, "run-ip", [{"host": "9.9.9.9"}])
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-ip")

    _write_identity_run(
        settings.output_dir,
        "run-share",
        [{"host": "9.9.9.9"}, {"host": "a.example.com"}, {"host": "b.example.com"}],
        hostnames={"9.9.9.9": {"forward": ["a.example.com", "b.example.com"]}},
        tls={
            "findings": [
                {
                    "host": "9.9.9.9",
                    "port": "443",
                    "cert": {"san": "DNS:a.example.com, DNS:b.example.com"},
                }
            ]
        },
    )
    stats = assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-share")
    assert stats.identities_merged == 0
    _, total = assets_service.list_assets(settings, tenant_id)
    assert total == 3

