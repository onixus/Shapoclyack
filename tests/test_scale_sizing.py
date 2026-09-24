"""Tests for the sizing model (#337).

The formulas are checked against hand-worked numbers with made-up
coefficients, so a changed formula fails here rather than silently moving the
table in docs/sizing.md. The model's constants are checked against the code
and manifests they mirror: a default changed there must change here too.
"""

from __future__ import annotations

import dataclasses
import inspect
import re
from pathlib import Path

import pytest

from tests.fixtures import scale_sizing
from tests.fixtures.scale_sizing import (
    GiB,
    MEASURED,
    PG_MAX_WAL_BYTES,
    TIERS,
    Coefficients,
    Workload,
    estimate,
    ingest_message_bytes,
    max_hosts_per_run_for_clickhouse,
    render_markdown,
    size_api,
    size_clickhouse,
    size_nats,
    size_postgres,
)

ROOT = Path(__file__).resolve().parents[1]


def coeffs(**overrides) -> Coefficients:
    return dataclasses.replace(Coefficients(source="test"), **overrides)


def workload(**overrides) -> Workload:
    base = {"assets": 10_000, "sensors": 2, "scans_per_day": 20, "headroom": 1.0}
    base.update(overrides)
    return Workload(**base)


# --- workload ---------------------------------------------------------------


def test_hosts_per_run_spreads_daily_host_scans_over_the_runs():
    assert workload().hosts_per_run == 500
    assert workload(host_scans_per_day=40_000).hosts_per_run == 2000
    assert workload(scans_per_day=0).hosts_per_run == 0


# --- unmeasured stays unmeasured ----------------------------------------------


def test_an_unmeasured_coefficient_is_never_filled_in():
    components = estimate(workload(), Coefficients())
    postgres = next(c for c in components if c.name == "PostgreSQL")
    assert postgres.storage_bytes is None and postgres.memory_request_bytes is None
    assert "n/m" in render_markdown([workload()], Coefficients())


def test_one_missing_term_voids_the_sum_rather_than_undercounting_it():
    c = coeffs(pg_bytes_per_asset=500, pg_bytes_per_service=300)  # findings unmeasured
    assert size_postgres(workload(), c).storage_bytes is None


# --- Postgres -------------------------------------------------------------------


def test_postgres_volume_is_estate_plus_unpruned_history_plus_wal():
    c = coeffs(
        pg_bytes_per_asset=1000,
        pg_bytes_per_service=500,
        pg_bytes_per_finding=2000,
        pg_bytes_per_finding_observation=300,
        pg_bytes_per_job=4000,
    )
    w = workload(horizon_days=100)
    estate = 10_000 * 1000 + 10_000 * 4 * 500 + 10_000 * 3 * 2000
    history = 10_000 * 3 * 100 * 300 + 20 * 100 * 4000
    assert size_postgres(w, c).storage_bytes == pytest.approx(estate + history + PG_MAX_WAL_BYTES)
    # The hot set is the estate, not the history; memory has a 1 GiB floor.
    assert size_postgres(w, c).memory_request_bytes == pytest.approx(max(estate / 0.25, GiB))


def test_an_unmeasured_jobs_row_is_named_rather_than_voiding_the_volume():
    """K rows a day against S x F observations: said out loud, not guessed."""
    c = coeffs(
        pg_bytes_per_asset=1000,
        pg_bytes_per_service=500,
        pg_bytes_per_finding=2000,
        pg_bytes_per_finding_observation=300,
    )
    postgres = size_postgres(workload(), c)
    assert postgres.storage_bytes is not None
    assert any("20 jobs rows/day" in note and "n/m" in note for note in postgres.notes)


def test_history_is_linear_in_the_horizon_because_nothing_prunes_it():
    c = coeffs(
        pg_bytes_per_asset=0,
        pg_bytes_per_service=0,
        pg_bytes_per_finding=0,
        pg_bytes_per_finding_observation=100,
        pg_bytes_per_job=0,
    )
    one = size_postgres(workload(horizon_days=365), c).storage_bytes - PG_MAX_WAL_BYTES
    two = size_postgres(workload(horizon_days=730), c).storage_bytes - PG_MAX_WAL_BYTES
    assert two == pytest.approx(2 * one)


def test_endpoint_rows_are_bounded_by_their_retention_windows():
    c = coeffs(
        pg_bytes_per_asset=0,
        pg_bytes_per_service=0,
        pg_bytes_per_finding=0,
        pg_bytes_per_finding_observation=0,
        pg_bytes_per_job=0,
        pg_bytes_per_endpoint_item=200,
        pg_bytes_per_endpoint_change=150,
        pg_bytes_per_endpoint_snapshot=1000,
    )
    w = workload(endpoints=100, packages_per_endpoint=1000, endpoint_changed_fraction=0.1, horizon_days=365)
    items = 100 * 1000 * 90 * 200  # 90-day snapshot window, one a day
    changes = 100 * 1000 * 0.1 * 365 * 150
    snapshots = 100 * 365 * 1000
    assert size_postgres(w, c).storage_bytes == pytest.approx(items + changes + snapshots + PG_MAX_WAL_BYTES)


def test_postgres_cpu_limit_follows_the_measured_share_of_a_projection():
    c = coeffs(projection_cpu_seconds_per_host=0.02, projection_pg_cpu_seconds_per_host=0.01)
    # Each replica drives ~1 core of Python; its backends use half of that.
    assert size_postgres(workload(api_replicas=6), c).cpu_limit_millicores == pytest.approx(3000)
    assert size_postgres(workload(api_replicas=1), c).cpu_limit_millicores == pytest.approx(1000)


# --- API --------------------------------------------------------------------------


def test_api_memory_limit_grows_with_concurrent_ingests_of_the_run_size():
    c = coeffs(
        api_idle_rss_bytes=300e6,
        api_scorer_rss_bytes=100e6,
        api_dashboard_rss_bytes=50e6,
        projection_rss_bytes_per_host=1000,
        ch_transform_rss_bytes_per_host=500,
        archive_bytes_per_host=300,
    )
    w = workload()  # 500 hosts per run
    per_ingest = 500 * 1000 + 500 * 500 + 500 * 300 * (1 + 4 / 3)
    api = size_api(w, c)
    assert api.memory_request_bytes == pytest.approx(400e6)
    assert api.memory_limit_bytes == pytest.approx(400e6 + 50e6 + 4 * per_ingest)
    assert size_api(dataclasses.replace(w, concurrent_ingests=8), c).memory_limit_bytes > api.memory_limit_bytes


def test_a_run_past_the_upload_expansion_cap_is_called_out():
    c = coeffs(run_dir_bytes_per_host=12_000)
    # 10 000 hosts x 12 kB = 114 MiB: fine. 50 000 hosts = 572 MiB: refused.
    assert not any("refused" in n for n in size_api(workload(scans_per_day=1), c).notes)
    big = size_api(workload(assets=50_000, scans_per_day=1), c)
    assert any("572 MiB or more" in n and "refused" in n for n in big.notes)


def test_api_cpu_request_is_the_daily_work_spread_over_replicas():
    c = coeffs(
        api_idle_cpu_millicores=10,
        projection_cpu_seconds_per_run=2,
        projection_cpu_seconds_per_host=0.02,
        ch_transform_cpu_seconds_per_host=0.001,
        api_cpu_seconds_per_request=0.004,
        endpoint_cpu_seconds_per_item=0,
    )
    w = workload(api_requests_per_second=1)
    daily = 10 / 1000 * 86400 * 2 + 20 * 2 + 10_000 * 0.02 + 10_000 * 0.001 + 86400 * 0.004
    assert size_api(w, c).cpu_request_millicores == pytest.approx(daily / 86400 / 2 * 1000)
    # One uvicorn process: the GIL caps Python at about a core.
    assert size_api(w, c).cpu_limit_millicores == 1000


# --- ClickHouse -------------------------------------------------------------------


def test_clickhouse_volume_allows_an_unmerged_second_copy_and_its_own_logs():
    c = coeffs(ch_bytes_per_vuln_row=20, ch_bytes_per_port_row=5, ch_system_log_bytes_per_hour=1e6)
    w = workload(horizon_days=10)
    data = 10_000 * 3 * 20 + 10_000 * 4 * 5
    component = size_clickhouse(w, c)
    assert component.storage_bytes == pytest.approx(2 * data + 1e6 * 24 * 10)
    assert any("system.*_log" in note for note in component.notes)


def test_clickhouse_disabled_sizes_nothing():
    assert size_clickhouse(workload(clickhouse_enabled=False), coeffs()).storage_bytes is None


# --- NATS and the ingest message ----------------------------------------------------


def test_ingest_message_is_the_base64_archive_until_the_inline_cap():
    c = coeffs(archive_bytes_per_host=1000)
    assert ingest_message_bytes(workload(), c) == pytest.approx(500 * 1000 * 4 / 3)
    # 5000 hosts * 1000 B = 5 MB > the 4 MB cap: the archive is left out.
    assert ingest_message_bytes(workload(scans_per_day=2), c) == 0.0


def test_largest_run_reaching_clickhouse_is_the_lower_of_two_ceilings():
    c = coeffs(archive_bytes_per_host=100)
    # max_payload 1 MiB / (4/3) / 100 B = 7864 hosts; the 4 MB cap would allow 40000.
    assert max_hosts_per_run_for_clickhouse(c) == pytest.approx(1024 * 1024 * 3 / 4 / 100)
    assert max_hosts_per_run_for_clickhouse(c, max_payload=64 * 1024 * 1024) == pytest.approx(40_000)
    assert max_hosts_per_run_for_clickhouse(coeffs()) is None


def test_nats_volume_is_the_reserved_stream_caps_and_oversize_runs_are_flagged():
    c = coeffs(archive_bytes_per_host=2000)
    nats = size_nats(workload(), c)  # 500 hosts: 1 MB archive, 1.33 MB message
    assert nats.storage_bytes == pytest.approx(11 * GiB)
    assert any("max_payload" in note for note in nats.notes)
    small = size_nats(workload(scans_per_day=200), c)  # 50 hosts: 133 KB
    assert not any("max_payload" in note for note in small.notes)


# --- the model's constants mirror the code and manifests --------------------------


def test_constants_match_the_defaults_they_mirror():
    from api.services import nats_bus, results_ingest
    from api.settings import Settings

    assert scale_sizing.INGEST_MAX_BYTES_DEFAULT == nats_bus._DEFAULT_INGEST_MAX_BYTES  # noqa: SLF001
    assert scale_sizing.EVENTS_MAX_BYTES_DEFAULT == nats_bus._DEFAULT_EVENTS_MAX_BYTES  # noqa: SLF001
    assert Workload(assets=1, sensors=1, scans_per_day=1).ingest_max_age_days == (
        nats_bus._DEFAULT_INGEST_MAX_AGE_SECONDS / 86400  # noqa: SLF001
    )
    signature = inspect.signature(results_ingest.build_gateway_payload)
    assert signature.parameters["max_inline_bytes"].default == scale_sizing.INGEST_INLINE_CAP_BYTES
    assert results_ingest.MAX_UNCOMPRESSED_BYTES == scale_sizing.UPLOAD_EXPANSION_CAP_BYTES
    defaults = Settings()
    w = Workload(assets=1, sensors=1, scans_per_day=1)
    assert w.concurrent_ingests == defaults.agent_results_max_concurrent_ingests
    assert w.run_retention_days == defaults.run_retention_days


def test_publish_ingest_still_writes_two_copies():
    """INGEST_COPIES doubles the stream estimate; drop it when the legacy copy goes."""
    from api.services import nats_bus

    source = inspect.getsource(nats_bus.NatsBus.publish_ingest)
    assert source.count("self.publish_json(") == scale_sizing.INGEST_COPIES


def test_shipped_nats_and_clickhouse_limits_are_the_ones_modelled():
    nats_conf = (ROOT / "k8s/shapoclyack/base/nats/configmap.yaml").read_text(encoding="utf-8")
    match = re.search(r"max_file:\s*(\d+)G", nats_conf)
    assert match and int(match.group(1)) * 1_000_000_000 == scale_sizing.NATS_MAX_FILE_SHIPPED
    assert "max_payload" not in nats_conf  # else NATS_DEFAULT_MAX_PAYLOAD is not what ships
    init_sql = (ROOT / "k8s/shapoclyack/base/clickhouse/init-local.sql").read_text(encoding="utf-8")
    ttl = {int(days) for days in re.findall(r"TTL timestamp \+ INTERVAL (\d+) DAY", init_sql)}
    assert Workload(assets=1, sensors=1, scans_per_day=1).clickhouse_ttl_days in ttl


# --- coefficients -------------------------------------------------------------------


def test_from_dict_accepts_a_derive_result_and_refuses_unknown_names():
    c = Coefficients.from_dict({"coefficients": {"source": "stand", "pg_bytes_per_asset": 700.0}})
    assert c.pg_bytes_per_asset == 700.0
    with pytest.raises(ValueError, match="pg_bytes_per_assets"):
        Coefficients.from_dict({"pg_bytes_per_assets": 1})


def test_merged_prefers_measured_values_and_never_unmeasures():
    base = coeffs(pg_bytes_per_asset=500, pg_bytes_per_service=300)
    stand = Coefficients(source="stand", pg_bytes_per_asset=700)
    merged = base.merged(stand)
    assert merged.pg_bytes_per_asset == 700
    assert merged.pg_bytes_per_service == 300
    assert merged.source == "stand (over test)"


def test_committed_coefficients_say_where_they_were_measured():
    assert MEASURED.source != "unset"
    assert "CPU" in MEASURED.source
    # The sensor's scan stages cannot be measured without live targets; the
    # committed set must not pretend otherwise.
    assert MEASURED.sensor_cpu_seconds_per_host is None
    assert MEASURED.run_dir_bytes_is_floor is True


# --- rendering and CLI ---------------------------------------------------------------


def test_tier_table_has_a_column_per_tier_and_the_components(capsys):
    assert scale_sizing.main(["--tiers", "--markdown"]) == 0
    out = capsys.readouterr().out
    header = out.splitlines()[0]
    assert header.count("assets /") == len(TIERS)
    for label in ("API (per replica)", "PostgreSQL", "ClickHouse", "NATS JetStream", "Run artifacts", "Sensor"):
        assert label in out


def test_the_table_in_the_doc_is_what_the_committed_coefficients_produce():
    """docs/sizing.md says the table is ``--tiers --markdown`` output; hold it to that."""
    doc = (ROOT / "docs/sizing.md").read_text(encoding="utf-8")
    table = [line for line in render_markdown(list(TIERS), MEASURED).splitlines() if line.startswith("|")]
    assert len(table) > 10
    for line in table:
        assert line in doc, f"docs/sizing.md is stale; regenerate the table:\n{line}"


def test_cli_reads_coefficients_from_a_file(tmp_path, capsys):
    path = tmp_path / "c.json"
    path.write_text('{"coefficients": {"source": "stand-x", "pg_bytes_per_asset": 1.0}}', encoding="utf-8")
    assert scale_sizing.main(["--assets", "2000", "--coefficients", str(path)]) == 0
    assert "stand-x" in capsys.readouterr().out


def test_cli_without_a_workload_is_an_error():
    assert scale_sizing.main([]) == 2
