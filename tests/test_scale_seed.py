"""Tests for the scale fixture generator (ROADMAP P3.7).

Only the pure row-building half is covered here — it runs with neither
Postgres nor ClickHouse up, which is the point of keeping generation free of
DB and clock. The insert paths are exercised by actually running the CLI
against a dev stack (see the module docstring in tests/fixtures/scale_seed.py).
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

import pytest

from api.services.clickhouse_client import PORT_COLUMNS, VULN_COLUMNS
from scanner.pipeline.asset_identity import ip_identity_key
from tests.fixtures import scale_seed
from tests.fixtures.scale_seed import (
    CISA_DECISIONS,
    PORT_POOL,
    PROTOCOLS,
    SeedSpec,
    asset_ip,
    build_parser,
    iter_asset_rows,
    iter_identifier_rows,
    iter_port_rows,
    iter_vulnerability_rows,
)

FIXED_NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def spec(**overrides) -> SeedSpec:
    base = {"tenant_id": "scale-test", "assets": 200, "now": FIXED_NOW}
    base.update(overrides)
    return SeedSpec(**base)


# --- addressing ------------------------------------------------------------


def test_asset_ip_is_injective_and_in_range():
    ips = {asset_ip(i) for i in range(5000)}
    assert len(ips) == 5000
    net = ipaddress.ip_network("10.0.0.0/8")
    for ip in ips:
        assert ipaddress.ip_address(ip) in net


def test_asset_ip_rejects_out_of_range_index():
    with pytest.raises(ValueError):
        asset_ip(1 << 24)


def test_fifty_thousand_assets_fit_the_address_space():
    assert asset_ip(49_999) == "10.0.195.79"


# --- determinism -----------------------------------------------------------


def test_rows_are_identical_across_runs():
    a = list(iter_asset_rows(spec()))
    b = list(iter_asset_rows(spec()))
    assert a == b


def test_rows_are_independent_of_batching_and_stream_order():
    """Asset N's vulns must not depend on whether ports were generated first."""
    ports_first = list(iter_port_rows(spec(), run_id="r"))
    vulns_after = list(iter_vulnerability_rows(spec()))
    vulns_alone = list(iter_vulnerability_rows(spec()))
    assert vulns_after == vulns_alone
    assert ports_first == list(iter_port_rows(spec(), run_id="r"))


def test_seed_changes_the_data():
    assert list(iter_asset_rows(spec(seed=1))) != list(iter_asset_rows(spec(seed=2)))


def test_a_larger_run_extends_a_smaller_one():
    """Index-derived rows mean 10k is a prefix-superset of 1k, so a grown
    fixture keeps the previously measured rows byte-identical."""
    small = list(iter_asset_rows(spec(assets=50)))
    large = list(iter_asset_rows(spec(assets=200)))
    assert large[:50] == small


# --- assets / identifiers --------------------------------------------------


def test_asset_rows_shape_and_keys():
    rows = list(iter_asset_rows(spec(assets=100)))
    assert len(rows) == 100
    assert len({r["asset_id"] for r in rows}) == 100
    for index, row in enumerate(rows):
        assert row["asset_id"] == ip_identity_key("scale-test", asset_ip(index))
        assert row["tenant_id"] == "scale-test"
        assert row["status"] in {"active", "stale", "decommissioned"}
        assert row["first_seen"] < row["last_seen"]
        # Naive datetimes: the columns are TIMESTAMP WITHOUT TIME ZONE.
        assert row["first_seen"].tzinfo is None and row["last_seen"].tzinfo is None
        assert row["asset_criticality"] is None or 0 <= row["asset_criticality"] <= 4


def test_last_seen_falls_inside_the_requested_window():
    rows = list(iter_asset_rows(spec(assets=300, days_back=30)))
    floor = (FIXED_NOW.replace(tzinfo=None)).timestamp() - 30 * 86400
    for row in rows:
        assert floor <= row["last_seen"].timestamp() <= FIXED_NOW.replace(tzinfo=None).timestamp()


def test_status_mix_is_not_uniformly_active():
    statuses = {r["status"] for r in iter_asset_rows(spec(assets=500))}
    assert statuses == {"active", "stale", "decommissioned"}


def test_identifiers_are_unique_and_attach_to_their_asset():
    asset_ids = {r["asset_id"] for r in iter_asset_rows(spec())}
    rows = list(iter_identifier_rows(spec()))
    # uq_asset_identifier is (tenant_id, identifier_type, identifier_value).
    keys = {(r["tenant_id"], r["identifier_type"], r["identifier_value"]) for r in rows}
    assert len(keys) == len(rows)
    assert {r["asset_id"] for r in rows} == asset_ids
    assert sum(1 for r in rows if r["identifier_type"] == "ip") == 200


def test_fqdn_ratio_is_honoured():
    for ratio, low, high in ((0.0, 0, 0), (1.0, 500, 500)):
        rows = list(iter_identifier_rows(spec(assets=500, fqdn_ratio=ratio)))
        fqdns = sum(1 for r in rows if r["identifier_type"] == "fqdn")
        assert low <= fqdns <= high


# --- ClickHouse rows -------------------------------------------------------


def test_vulnerability_rows_match_the_column_contract():
    rows = list(iter_vulnerability_rows(spec(assets=100)))
    assert rows and all(len(row) == len(VULN_COLUMNS) for row in rows)
    for row in rows:
        (_tenant, ip, cve, base, epss, crit, exploit, decision, ctx, model, ts) = row
        assert ipaddress.ip_address(ip).version == 4
        assert cve.startswith("CVE-")
        assert 0.0 <= base <= 10.0
        assert 0.0 <= epss <= 1.0
        assert 0 <= crit <= 4
        assert exploit in (0, 1)
        # Enum8 in init-local.sql — anything else is rejected at insert time.
        assert decision in CISA_DECISIONS
        assert 0.0 <= ctx <= 10.0
        assert model == "mvp-2"
        assert ts.tzinfo is None


def test_vulnerability_keys_are_unique_per_asset():
    """ReplacingMergeTree ORDER BY (tenant, asset_ip, cve_id) collapses dupes,
    so a duplicate emitted here would silently shrink the fixture."""
    rows = list(iter_vulnerability_rows(spec(assets=300, vulns_per_asset=5)))
    keys = {(str(r[0]), r[1], r[2]) for r in rows}
    assert len(keys) == len(rows)


def test_cve_pool_is_shared_across_assets():
    rows = list(iter_vulnerability_rows(spec(assets=300, vulns_per_asset=3, cve_pool=50)))
    assert len({r[2] for r in rows}) <= 50
    assert len(rows) > 50  # i.e. CVEs genuinely repeat across hosts


def test_port_rows_match_the_column_contract():
    rows = list(iter_port_rows(spec(assets=100), run_id="run-42"))
    assert rows and all(len(row) == len(PORT_COLUMNS) for row in rows)
    for row in rows:
        _tenant, ip, port, protocol, run_id, ts = row
        assert ipaddress.ip_address(ip).version == 4
        assert port in PORT_POOL
        assert protocol in PROTOCOLS
        assert run_id == "run-42"
        assert ts.tzinfo is None


def test_port_keys_are_unique_per_asset():
    rows = list(iter_port_rows(spec(assets=200, ports_per_asset=6), run_id="r"))
    keys = {(str(r[0]), r[1], r[2]) for r in rows}
    assert len(keys) == len(rows)


def test_ports_per_asset_is_capped_by_the_pool():
    rows = list(iter_port_rows(spec(assets=10, ports_per_asset=999), run_id="r"))
    assert len(rows) == 10 * len(PORT_POOL)


# --- CLI -------------------------------------------------------------------


def test_cli_defaults_to_the_scale_test_tenant():
    args = build_parser().parse_args([])
    assert args.tenant == "scale-test"
    assert args.tenant != "default", "purge is tenant-scoped; never default to real data"


def test_cli_rejects_a_run_with_both_stores_skipped(capsys):
    assert scale_seed.main(["--skip-postgres", "--skip-clickhouse"]) == 2
    assert "nothing to do" in capsys.readouterr().err


def test_cli_requires_a_url_for_each_enabled_store(monkeypatch, capsys):
    monkeypatch.delenv("OCTO_POSTGRES_URL", raising=False)
    monkeypatch.delenv("OCTO_CLICKHOUSE_URL", raising=False)
    assert scale_seed.main(["--skip-clickhouse"]) == 2
    assert "Postgres URL" in capsys.readouterr().err
    assert scale_seed.main(["--skip-postgres"]) == 2
    assert "ClickHouse URL" in capsys.readouterr().err
