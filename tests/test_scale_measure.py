"""Tests for the sizing measurement harness (#337).

The measuring half needs Postgres, ClickHouse and a running API and is
exercised by running it (docs/sizing.md § Re-measuring on a stand). What is
covered here runs with none of them: the synthetic hosts, the run directory the
scanner's own writers produce from them — and that the API's readers accept
that directory, since a run the projection cannot parse would measure nothing
— and the arithmetic that turns raw results into coefficients.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.fixtures import scale_measure
from tests.fixtures.scale_measure import (
    DASHBOARD_PATH,
    derive_coefficients,
    finding_port,
    fit_runs,
    iter_hosts,
    linear_fit,
    measure_runs_dir,
    severity_for,
    size_delta,
    snapshot_request,
    upload_archive,
    write_run_dir,
)
from tests.fixtures.scale_seed import SeedSpec, iter_port_rows, iter_vulnerability_rows


def spec(**overrides) -> SeedSpec:
    base = {"tenant_id": "sizing-test", "assets": 40}
    base.update(overrides)
    return SeedSpec(**base)


# --- synthetic hosts -------------------------------------------------------


def test_hosts_carry_exactly_the_rows_scale_seed_puts_in_clickhouse():
    """Postgres and ClickHouse tiers must describe the same estate."""
    s = spec()
    hosts = list(iter_hosts(s))
    assert [h.index for h in hosts] == list(range(40))
    ports = {(r[1], r[2], r[3]) for r in iter_port_rows(s, run_id="x")}
    cves = {(r[1], r[2], r[3]) for r in iter_vulnerability_rows(s)}
    assert {(h.ip, p, proto) for h in hosts for p, proto in h.ports} == ports
    assert {(h.ip, cve, cvss) for h in hosts for cve, cvss in h.cves} == cves


def test_fqdn_follows_the_seeded_identifiers():
    hosts = list(iter_hosts(spec(assets=200, fqdn_ratio=0.35)))
    with_names = [h for h in hosts if h.fqdn]
    assert 0 < len(with_names) < 200
    assert all(h.fqdn.startswith(f"host-{h.index:06d}.") for h in with_names)
    assert not any(h.fqdn for h in iter_hosts(spec(fqdn_ratio=0.0)))


def test_finding_port_prefers_web_ports_and_ignores_udp():
    host = scale_measure.HostObservation(0, "10.0.0.1", None, ((22, "tcp"), (8080, "tcp"), (443, "udp")), ())
    assert finding_port(host) == 8080
    only_udp = scale_measure.HostObservation(0, "10.0.0.1", None, ((53, "udp"),), ())
    assert finding_port(only_udp) == 0


@pytest.mark.parametrize(
    ("cvss", "expected"),
    [(9.8, "critical"), (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"), (0.0, "unknown")],
)
def test_severity_bands_match_cvss_v3(cvss, expected):
    assert severity_for(cvss) == expected


# --- the synthetic run is one the API can read ------------------------------


def test_run_dir_is_readable_by_the_api_projection_and_the_ingest_transform(tmp_path):
    from api.services import asset_services, ch_transform, results_ingest
    from api.services import assets as assets_service

    s = spec(assets=25)
    run_dir = tmp_path / "run"
    stats = write_run_dir(run_dir, s)
    hosts = list(iter_hosts(s))
    assert stats["hosts"] == 25
    assert stats["findings"] == sum(len(h.cves) for h in hosts)

    # The files on_run_published reads, parsed by the functions that read them.
    assert len(assets_service._host_records(run_dir)) == 25  # noqa: SLF001
    vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert {(v["host"], v["cve"]) for v in vulns} == {(h.ip, cve) for h in hosts for cve, _ in h.cves}
    services = asset_services.fingerprints_from_run_dir(run_dir)
    assert len(services) == sum(len(h.ports) for h in hosts)

    # And the ClickHouse transform turns the uploaded archive into rows.
    archive = upload_archive(run_dir)
    payload = results_ingest.build_gateway_payload(
        job_id="j", run_id="r", agent_id="a", exit_code=0, archive_bytes=archive, tenant_id=s.tenant_id
    )
    vuln_rows, port_rows, _ = ch_transform.transform_ingest_payload(payload)
    assert len(vuln_rows) == stats["findings"]
    assert len(port_rows) == sum(len(h.ports) for h in hosts)


def test_directory_bytes_and_archive_cover_every_file(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "one.json").write_text("x" * 100, encoding="utf-8")
    (tmp_path / "two.txt").write_text("y" * 50, encoding="utf-8")
    assert scale_measure.directory_bytes(tmp_path) == {"a/one.json": 100, "two.txt": 50}
    from api.services.ch_transform import extract_archive_members

    assert set(extract_archive_members(upload_archive(tmp_path))) == {"a/one.json", "two.txt"}


# --- endpoint snapshots -----------------------------------------------------


def test_snapshot_request_is_schema_valid_and_bumps_only_the_changed_share():
    first = snapshot_request(3, packages=200, generation=0, changed=0.1)
    second = snapshot_request(3, packages=200, generation=1, changed=0.1)
    assert len(first.software) == 200
    assert len({item.name for item in first.software}) == 200
    assert first.agent_id == second.agent_id and first.snapshot_id != second.snapshot_id
    changed = [a for a, b in zip(first.software, second.software, strict=True) if a.version != b.version]
    assert len(changed) == 20


# --- process accounting -----------------------------------------------------


def test_proc_sample_reads_this_process_and_misses_a_dead_one():
    sample = scale_measure.proc_sample(os.getpid())
    assert sample is not None
    assert sample.rss_bytes > 0 and sample.hwm_bytes >= sample.rss_bytes and sample.cpu_seconds >= 0
    assert scale_measure.proc_sample(2**22 + 12345) is None


def test_application_name_is_added_without_dropping_the_rest_of_the_url():
    url = scale_measure.with_application_name(
        "postgresql+psycopg://user:pw@db.internal:5432/shapo?sslmode=require", "sizing-harness-1"
    )
    assert url.startswith("postgresql+psycopg://user:pw@db.internal:5432/shapo?")
    assert "sslmode=require" in url and "application_name=sizing-harness-1" in url


def test_child_steps_get_store_urls_through_the_environment_not_argv(monkeypatch):
    """A URL carries a password; a command line is readable by any local user."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"], seen["env"] = argv, kwargs["env"]
        return scale_measure.subprocess.CompletedProcess(argv, 0, stdout='{"ok": 1}\n', stderr="")

    monkeypatch.setattr(scale_measure.subprocess, "run", fake_run)
    url = "postgresql+psycopg://sizing:s3cret@db:5432/x"
    assert scale_measure._run_child("_build-run", postgres_url=url, tenant="t", assets=5) == {"ok": 1}  # noqa: SLF001
    assert not any("s3cret" in part for part in seen["argv"])
    assert seen["env"]["OCTO_POSTGRES_URL"] == url
    assert seen["argv"][-4:] == ["--tenant", "t", "--assets", "5"]


def test_system_log_rate_is_the_growth_between_two_samples(monkeypatch):
    from api.services import clickhouse_client as ch

    class Client:
        def command(self, sql):
            assert sql == "SYSTEM FLUSH LOGS"

        def query(self, sql):
            return type("R", (), {"result_rows": [[7200]]})()

    monkeypatch.setattr(ch, "get_client", lambda url: Client())
    monkeypatch.setattr(
        scale_measure,
        "ch_table_stats",
        lambda url, database: {"metric_log": {"bytes_on_disk": 9_000_000}, "not_a_log_table": {"bytes_on_disk": 5}},
    )
    alone = scale_measure.ch_system_log_growth("http://ch")
    assert alone["bytes_per_hour"] == 4_500_000 and set(alone["tables"]) == {"metric_log"}
    # 3 MB in the hour between the samples: the rate leaves out the first hour.
    since = scale_measure.ch_system_log_growth("http://ch", since={"uptime_seconds": 3600, "bytes_on_disk": 6_000_000})
    assert since["bytes_per_hour"] == 3_000_000 and since["window_seconds"] == 3600
    # An earlier sample from before a restart (longer uptime) is ignored.
    restarted = scale_measure.ch_system_log_growth("http://ch", since={"uptime_seconds": 9000, "bytes_on_disk": 1})
    assert restarted["bytes_per_hour"] == 4_500_000


def test_backend_cpu_is_only_trusted_when_no_backend_exited_in_between():
    """A pool closing an overflow connection takes its CPU with it; seen
    under concurrency as a negative Postgres cost per request."""
    b = scale_measure.BackendCpu
    assert scale_measure.backend_cpu_delta(b(frozenset({1, 2}), 5.0), b(frozenset({1, 2, 3}), 7.5)) == 2.5
    assert scale_measure.backend_cpu_delta(b(frozenset({1, 2}), 5.0), b(frozenset({1}), 4.0)) is None
    assert scale_measure.backend_cpu_delta(None, b(frozenset({1}), 4.0)) is None


def test_size_delta_keeps_only_tables_that_changed():
    before = {"a": {"total": 10, "rows": 1}, "b": {"total": 5, "rows": 1}}
    after = {"a": {"total": 30, "rows": 3}, "b": {"total": 5, "rows": 1}, "c": {"total": 8, "rows": 2}}
    assert size_delta(before, after) == {"a": {"total": 20, "rows": 2}, "c": {"total": 8, "rows": 2}}


# --- fitting ------------------------------------------------------------------


def test_linear_fit_recovers_intercept_and_slope():
    intercept, slope = linear_fit([(1000, 2500.0), (10000, 20500.0), (50000, 100500.0)])
    assert slope == pytest.approx(2.0)
    assert intercept == pytest.approx(500.0)
    assert linear_fit([(5, 1.0), (5, 2.0)]) is None


def _projection(run_id, *, cpu, statements, events_rows=0, events_total=0, vulns_total=0, vulns_rows=0, peak=0):
    return {
        "run_id": run_id,
        "api_cpu_seconds": cpu,
        "postgres_backend_cpu_seconds": cpu / 4,
        "statements": statements,
        "rss_before_bytes": 100,
        "peak_rss_bytes": 100 + peak,
        "scorer_load": {"cpu_seconds": 1.0, "rss_bytes": 90},
        "growth": {
            "assets": {"rows": vulns_rows // 3, "total": 400 * (vulns_rows // 3)},
            "vulnerabilities": {"rows": vulns_rows, "total": vulns_total},
            "vulnerability_events": {"rows": events_rows, "total": events_total},
        },
    }


def _tier(assets):
    findings = assets * 3
    return {
        "assets": assets,
        "run": {
            "hosts": assets,
            "report_stage_cpu_seconds": 0.5 + assets * 0.001,
            "run_dir_bytes": 1000 + assets * 12000,
            "archive_bytes": 500 + assets * 400,
            "rss_before_bytes": 10,
            "peak_rss_bytes": 10 + assets * 2000,
        },
        "projections": [
            _projection(f"t{assets}-r0", cpu=2 + assets * 0.03, statements=assets * 40,
                        vulns_rows=findings, vulns_total=findings * 1000, events_rows=findings,
                        events_total=findings * 300, peak=assets * 5000),
            _projection(f"t{assets}-r1", cpu=1 + assets * 0.02, statements=assets * 30,
                        vulns_total=findings * 900, events_rows=findings, events_total=findings * 280),
            _projection(f"t{assets}-r2", cpu=1 + assets * 0.02, statements=assets * 30,
                        events_rows=findings, events_total=findings * 250),
        ],
    }


def test_derive_separates_per_host_cost_from_per_run_overhead():
    results = {
        "environment_postgres": {"measured_at": "2026-09-24T00:00:00+00:00", "cpu_count": 4, "git_commit": "abc"},
        "postgres": [_tier(1000), _tier(10000)],
    }
    c = derive_coefficients(results)
    # Rescans (r1, r2) set the steady-state per-host cost; the 1 s is per run.
    assert c["projection_cpu_seconds_per_host"] == pytest.approx(0.02)
    assert c["projection_cpu_seconds_per_run"] == pytest.approx(1.0)
    assert c["projection_statements_per_host"] == pytest.approx(30)
    assert c["projection_pg_cpu_seconds_per_host"] == pytest.approx(0.005)
    assert c["projection_rss_bytes_per_host"] == pytest.approx(5000)
    # A finding's steady-state bytes are its first write plus the update bloat;
    # an observation's are the settled (post-VACUUM) rescan's.
    assert c["pg_bytes_per_finding"] == pytest.approx(1900)
    assert c["pg_bytes_per_finding_observation"] == pytest.approx(250)
    assert c["pg_bytes_per_asset"] == pytest.approx(400)
    assert c["report_cpu_seconds_per_host"] == pytest.approx(0.001)
    assert c["run_dir_bytes_per_host"] == pytest.approx(12000)
    assert c["archive_bytes_per_host"] == pytest.approx(400)
    assert c["run_dir_bytes_is_floor"] is True
    assert c["api_scorer_rss_bytes"] == 90
    assert "2026-09-24" in c["source"] and "abc" in c["source"]
    # Nothing measured, nothing emitted: absent means "n/m" downstream.
    assert "ch_bytes_per_vuln_row" not in c and "api_idle_rss_bytes" not in c


def test_derive_reads_api_endpoint_and_clickhouse_sections():
    results = {
        "api": {
            "idle": {"rss_bytes": 300, "cpu_millicores": 12.5},
            "peak_rss_bytes": 700,
            "requests": [
                {
                    "path": "/api/assets?limit=100",
                    "requests": 40,
                    "cpu_ms_per_request": 5.0,
                    "postgres_cpu_ms_per_request": 2.0,
                },
                {
                    "path": "/api/runs?limit=100",
                    "requests": 40,
                    "cpu_ms_per_request": 3.0,
                    "postgres_cpu_ms_per_request": None,  # remote server: not visible
                },
                {"path": DASHBOARD_PATH, "requests": 40, "cpu_ms_per_request": 500.0},
            ],
        },
        "endpoints": [
            {
                "first": {
                    "api_cpu_seconds": 3.0,
                    "growth": {
                        "endpoint_software_items": {"rows": 3000, "total": 600000},
                        "endpoint_inventory_snapshots": {"rows": 2, "total": 16384},
                    },
                },
                "upgrade": {
                    "api_cpu_seconds": 2.0,
                    "growth": {"endpoint_software_changes": {"rows": 150, "total": 30000}},
                },
            },
            # Many small snapshots: where the per-snapshot row is read from.
            {
                "first": {
                    "api_cpu_seconds": 1.0,
                    "growth": {
                        "endpoint_software_items": {"rows": 400, "total": 90000},
                        "endpoint_inventory_snapshots": {"rows": 400, "total": 409600},
                    },
                },
                "upgrade": {"api_cpu_seconds": 1.0, "growth": {}},
            },
        ],
        "clickhouse": [
            {
                "assets": n,
                "growth": {
                    "shapoclyack_vulnerabilities": {"rows": 3 * n, "bytes_on_disk": 60 * n},
                    "shapoclyack_open_ports": {"rows": 4 * n, "bytes_on_disk": 20 * n},
                },
                "ingest": {"transform_cpu_seconds": 0.001 * n, "rss_before_bytes": 0, "peak_rss_bytes": 100 * n},
                "queries": [{"read_rows": 3 * n, "memory_bytes": 30 * n}],
                "server_memory": {"resident_bytes": 600},
            }
            for n in (1000, 10000)
        ],
        "clickhouse_server_memory": {"resident_bytes": 500},
        "clickhouse_system_logs": {"bytes_per_hour": 1234},
    }
    c = derive_coefficients(results)
    assert c["api_idle_rss_bytes"] == 300
    assert c["api_dashboard_rss_bytes"] == 400
    # The dashboard page is sized separately; it must not skew the list mix.
    assert c["api_cpu_seconds_per_request"] == pytest.approx(0.004)
    # Only cells whose backends were visible count toward the Postgres share.
    assert c["api_pg_cpu_seconds_per_request"] == pytest.approx(0.002)
    assert c["pg_bytes_per_endpoint_item"] == pytest.approx(200)
    assert c["pg_bytes_per_endpoint_change"] == pytest.approx(200)
    assert c["pg_bytes_per_endpoint_snapshot"] == pytest.approx(1024)
    assert c["endpoint_cpu_seconds_per_item"] == pytest.approx(0.001)
    assert c["ch_bytes_per_vuln_row"] == pytest.approx(20)
    assert c["ch_bytes_per_port_row"] == pytest.approx(5)
    assert c["ch_transform_cpu_seconds_per_host"] == pytest.approx(0.001)
    assert c["ch_query_memory_bytes_per_row"] == pytest.approx(10)
    # The idle server sample wins over one taken right after an ingest.
    assert c["ch_idle_rss_bytes"] == 500
    assert c["ch_system_log_bytes_per_hour"] == 1234


def test_live_rows_replace_synthetic_ones_only_where_there_are_enough():
    results = {
        "postgres": [_tier(1000), _tier(10000)],
        "postgres_live": {
            "jobs": {"rows_estimate": 5000.0, "total_bytes": 10_000_000, "bytes_per_row": 2000.0},
            # 50 rows is page granularity, not a row size.
            "vulnerability_events": {"rows_estimate": 50.0, "total_bytes": 81920, "bytes_per_row": 1638.4},
            "audit_events": {"rows_estimate": 9000.0, "total_bytes": 9_000_000, "bytes_per_row": 1000.0},
        },
    }
    c = derive_coefficients(results)
    assert c["pg_bytes_per_job"] == 2000.0
    assert c["pg_bytes_per_finding_observation"] == pytest.approx(250)
    # Informative tables do not map onto a coefficient.
    assert "audit_events" not in json.dumps(sorted(c))


def test_merging_result_files_concatenates_tiers_instead_of_keeping_the_last():
    merged = scale_measure.merge_results(
        [
            {"postgres": [_tier(1000)], "environment_postgres": {"cpu_count": 4}},
            {"postgres": [_tier(10000)], "coefficients": {"stale": True}},
        ]
    )
    assert [tier["assets"] for tier in merged["postgres"]] == [1000, 10000]
    # Two tiers make a slope; the stale block from an input file is replaced.
    assert merged["coefficients"]["projection_cpu_seconds_per_host"] == pytest.approx(0.02)
    assert "stale" not in merged["coefficients"]


def test_derive_output_is_accepted_by_the_model():
    from tests.fixtures.scale_sizing import Coefficients

    c = derive_coefficients({"postgres": [_tier(1000), _tier(10000)]})
    assert Coefficients.from_dict(c).projection_cpu_seconds_per_host == pytest.approx(0.02)


# --- real run directories (a stand) ----------------------------------------------


def _fake_run(root: Path, relative: str, hosts: int, per_host: int) -> None:
    run = root / relative
    run.mkdir(parents=True)
    (run / "alive_hosts.json").write_text(json.dumps([{"host": f"10.0.0.{i}"} for i in range(hosts)]))
    (run / "blob.bin").write_bytes(b"\0" * (hosts * per_host))
    (run / "stage_timings.json").write_text(
        json.dumps(
            {
                "pipeline_wall_sec": 12.5,
                "stages": [{"name": "ports", "duration_sec": 3.0, "status": "ok"}],
                # The block scanner/pipeline/stage_timing.py writes (#337).
                "resources": {
                    "cpu_sec": 2.0 + hosts * 0.1,
                    "children_cpu_sec": hosts * 0.4,
                    "max_rss_mb": 100.0,
                    "children_max_rss_mb": 50.0 + hosts,
                },
            }
        )
    )


def test_runs_dir_reads_both_layouts_and_fits_bytes_per_host(tmp_path):
    _fake_run(tmp_path, "20260101T000000Z", hosts=10, per_host=1000)
    _fake_run(tmp_path, "_tenants/acme/20260102T000000Z", hosts=30, per_host=1000)
    result = measure_runs_dir(tmp_path, archive=True)
    assert {r["run"] for r in result["runs"]} == {"20260101T000000Z", "_tenants/acme/20260102T000000Z"}
    assert all(r["stages"] == {"ports": 3.0} and r["pipeline_wall_sec"] == 12.5 for r in result["runs"])
    sizes = {r["hosts"]: r["bytes"] for r in result["runs"]}
    # Two points, so the fit is exact: the blob plus alive_hosts.json's row.
    assert result["fit"]["bytes_per_host"] == round((sizes[30] - sizes[10]) / 20)
    assert 1000 < result["fit"]["bytes_per_host"] < 1100
    assert result["fit"]["archive_bytes_per_host"] is not None
    # Scan process plus the tools it waited for, per host; the peak is the
    # larger run's process plus its biggest tool.
    assert result["fit"]["sensor_cpu_seconds_per_host"] == pytest.approx(0.5)
    assert result["fit"]["sensor_cpu_seconds_per_run"] == pytest.approx(2.0)
    assert result["fit"]["sensor_peak_rss_bytes"] == (100 + 80) * 2**20
    # A stand's real runs replace the report-stage floor in the model.
    c = derive_coefficients({"runs_dir": result})
    assert c["run_dir_bytes_is_floor"] is False
    assert c["run_dir_bytes_per_host"] == result["fit"]["bytes_per_host"]
    assert c["sensor_cpu_seconds_per_host"] == pytest.approx(0.5)
    assert c["sensor_peak_rss_bytes"] == (100 + 80) * 2**20


def test_fit_runs_needs_two_distinct_run_sizes():
    assert fit_runs([{"hosts": 5, "bytes": 100}])["bytes_per_host"] is None


# --- CLI ------------------------------------------------------------------------


def test_tier_list_is_parsed_sorted_and_validated():
    parser = scale_measure.build_parser()
    args = parser.parse_args(["postgres", "--tiers", "50000,1000,10000", "--work-dir", "w", "--postgres-url", "x"])
    assert args.tiers == [1000, 10000, 50000]
    with pytest.raises(SystemExit):
        parser.parse_args(["postgres", "--tiers", "0", "--work-dir", "w"])
    with pytest.raises(SystemExit):
        parser.parse_args(["postgres", "--tiers", "ten", "--work-dir", "w"])


def test_only_the_harness_and_fixture_tenants_count_as_its_own():
    assert scale_measure._harness_tenant("sizing-50000")  # noqa: SLF001
    assert scale_measure._harness_tenant("scale-test")  # noqa: SLF001
    for other in ("default", "acme", "sizing50000", "scale-test-2"):
        assert not scale_measure._harness_tenant(other)  # noqa: SLF001


def test_measuring_refuses_stores_that_hold_other_tenants_data(monkeypatch, capsys, tmp_path):
    """The writing commands VACUUM, purge and seed demo accounts: fail closed."""
    monkeypatch.setattr(scale_measure, "foreign_tenants", lambda *_a, **_k: ["acme", "clickhouse:1234"])
    monkeypatch.setattr(scale_measure, "current_database", lambda url: "db")
    code = scale_measure.main(
        [
            "postgres",
            "--work-dir",
            str(tmp_path / "w"),
            "--postgres-url",
            "postgresql+psycopg://x@nowhere/db",
            "--i-own-database",
            "db",
        ]
    )
    assert code == 2
    err = capsys.readouterr().err
    assert "acme" in err and "--allow-shared-stores" in err
    assert not (tmp_path / "w").exists()


def test_measuring_without_a_database_url_is_refused(monkeypatch, capsys):
    monkeypatch.delenv("OCTO_POSTGRES_URL", raising=False)
    assert scale_measure.main(["postgres", "--work-dir", "w", "--postgres-url", ""]) == 2
    assert "no Postgres URL" in capsys.readouterr().err


# --- review of #337, round 1 ---------------------------------------------------


def test_an_unmigrated_database_is_reported_not_crashed(monkeypatch):
    """A freshly created stand database has no tables yet: say so, don't traceback."""
    from sqlalchemy import create_engine

    from api.db import engine as db_engine

    empty = create_engine("sqlite://")
    monkeypatch.setattr(db_engine, "get_engine", lambda url: empty)
    with pytest.raises(scale_measure.StoreNotReady, match="alembic"):
        scale_measure.foreign_tenants("postgresql+psycopg://x@nowhere/db")


class _FakeNats:
    """Stands in for ``nats.connect``: records what the harness does with a broker."""

    def __init__(self, max_payload: int) -> None:
        self.max_payload = max_payload
        self.published: list[tuple[str, int, dict]] = []
        self.jetstream_used = False

    async def connect(self, *args, **kwargs):
        return self

    async def publish(self, subject, payload=b"", headers=None):
        from nats.errors import MaxPayloadError

        if len(payload) > self.max_payload:
            raise MaxPayloadError
        self.published.append((subject, len(payload), headers or {}))

    async def flush(self, timeout=None):
        return None

    def jetstream(self, *args, **kwargs):
        self.jetstream_used = True
        raise AssertionError("the harness must not manage the stand's streams")

    async def close(self):
        return None


def test_the_broker_probe_publishes_no_jetstream_message(monkeypatch):
    """A probe through nats_bus would create-or-update INGEST/EVENTS/JOBS with the
    harness's own OCTO_NATS_* defaults and leave the tier's messages for the
    stand's ingest worker; a core publish to a subject no stream captures does not."""
    import nats

    fake = _FakeNats(max_payload=1024)
    monkeypatch.setattr(nats, "connect", fake.connect)
    small = scale_measure.probe_broker("nats://x", b"x" * 100, headers={"Nats-Msg-Id": "m"})
    big = scale_measure.probe_broker("nats://x", b"x" * 2000, headers={"Nats-Msg-Id": "m"})
    assert small == {"max_payload": 1024, "accepted": True}
    assert big["accepted"] is False and "maximum payload" in big["refused"]
    assert [subject.split(".")[:2] for subject, _, _ in fake.published] == [["sizing", "probe"]]
    assert not fake.jetstream_used


def test_the_ingest_step_never_touches_the_bus_that_manages_streams(monkeypatch, tmp_path):
    import argparse

    import nats

    from api.services import clickhouse_client as ch
    from api.services import nats_bus, results_ingest

    def forbidden(*_a, **_k):
        raise AssertionError("nats_bus reconfigures a stand's streams on connect")

    monkeypatch.setattr(nats_bus, "get_bus", forbidden)
    monkeypatch.setattr(results_ingest, "publish_raw_results", forbidden)
    monkeypatch.setattr(nats, "connect", _FakeNats(max_payload=1024 * 1024).connect)
    inserted: dict[str, int] = {}

    class Client:
        def insert(self, table, rows, column_names):
            inserted[table] = len(rows)

    monkeypatch.setattr(ch, "get_client", lambda url: Client())
    settings = scale_measure.harness_settings("", tmp_path)
    run_dir = scale_measure.run_path(settings, "sizing-5", "sizing-5-r0")
    write_run_dir(run_dir, spec(assets=5, tenant_id="sizing-5"))
    args = argparse.Namespace(
        postgres_url="",
        clickhouse_url="http://ch",
        nats_url="nats://x",
        work_dir=str(tmp_path),
        tenant="sizing-5",
        run_id="sizing-5-r0",
    )
    result = scale_measure.child_ingest_run(args)
    assert result["nats_accepted"] is True and result["nats_max_payload"] == 1024 * 1024
    assert result["envelope_bytes"] > 0
    assert inserted[ch.VULN_TABLE] > 0


def test_zero_query_memory_is_below_resolution_not_a_measurement():
    """ClickHouse reports memory_usage=0 under its tracker's granularity."""
    tier = {
        "assets": 1000,
        "growth": {},
        "ingest": {"transform_cpu_seconds": 1.0, "rss_before_bytes": 0, "peak_rss_bytes": 1},
        "queries": [{"read_rows": 3000, "memory_bytes": 0}, {"read_rows": 4000, "memory_bytes": 0}],
        "server_memory": {"resident_bytes": 600},
    }
    assert "ch_query_memory_bytes_per_row" not in derive_coefficients({"clickhouse": [tier]})


def test_derive_keeps_the_archive_intercept_and_the_message_envelope():
    """A 1 MiB ceiling is hit by intercept + slope x hosts + envelope, not slope alone."""
    runs = [
        {
            "hosts": n,
            "report_stage_cpu_seconds": 0.001 * n,
            "run_dir_bytes": 50_000 + 11_000 * n,
            "archive_bytes": 65_536 + 360 * n,
            "rss_before_bytes": 0,
            "peak_rss_bytes": 1,
        }
        for n in (1000, 3000, 10000)
    ]
    ch_tiers = [
        {
            "assets": r["hosts"],
            "run": r,
            "growth": {},
            "queries": [],
            "server_memory": {"resident_bytes": 1},
            "ingest": {
                "transform_cpu_seconds": 0.1,
                "rss_before_bytes": 0,
                "peak_rss_bytes": 1,
                "envelope_bytes": 612,
            },
        }
        for r in runs
    ]
    c = derive_coefficients({"clickhouse": ch_tiers})
    assert c["archive_bytes_per_host"] == pytest.approx(360)
    assert c["archive_bytes_per_run"] == pytest.approx(65_536)
    assert c["run_dir_bytes_per_run"] == pytest.approx(50_000)
    assert c["ingest_envelope_bytes"] == 612


def test_harness_runs_are_marked_and_runs_dir_does_not_take_them_for_real_ones(tmp_path):
    write_run_dir(tmp_path / "runs" / "sizing-5-r0", spec(assets=5))
    _fake_run(tmp_path / "runs", "20260101T000000Z", hosts=10, per_host=1000)
    result = measure_runs_dir(tmp_path / "runs")
    assert [r["run"] for r in result["runs"]] == ["20260101T000000Z"]
    assert result["skipped"] == {"synthetic": 1, "resumed": 0}


def test_resumed_runs_do_not_count_toward_the_sensor_fit(tmp_path):
    """A --resume run skipped the stages its checkpoint had: its CPU is partial."""
    _fake_run(tmp_path, "a", hosts=10, per_host=1000)
    _fake_run(tmp_path, "b", hosts=30, per_host=1000)
    _fake_run(tmp_path, "c", hosts=20, per_host=1000)
    timings = json.loads((tmp_path / "c" / "stage_timings.json").read_text())
    timings["stages"].insert(
        0, {"name": "discover", "duration_sec": 0.0, "status": "skipped", "detail": "checkpoint"}
    )
    timings["resources"]["children_cpu_sec"] = 0.1
    (tmp_path / "c" / "stage_timings.json").write_text(json.dumps(timings))
    result = measure_runs_dir(tmp_path)
    assert result["skipped"]["resumed"] == 1
    assert result["fit"]["sensor_cpu_seconds_per_host"] == pytest.approx(0.5)


def test_sensor_fit_keeps_the_per_run_cost_and_the_cores_a_scan_keeps_busy(tmp_path):
    _fake_run(tmp_path, "a", hosts=10, per_host=1000)
    _fake_run(tmp_path, "b", hosts=30, per_host=1000)
    fit = measure_runs_dir(tmp_path)["fit"]
    # cpu = 2 + 0.1 h + 0.4 h over a 12.5 s pipeline: 7 s -> 0.56 cores, 17 s -> 1.36.
    assert fit["sensor_cpu_seconds_per_run"] == pytest.approx(2.0)
    assert fit["sensor_busy_cores"] == pytest.approx((7 / 12.5 + 17 / 12.5) / 2)
    assert fit["sensor_peak_cores"] == pytest.approx(17 / 12.5)
    assert fit["sensor_peak_rss_run_hosts"] == 30
    c = derive_coefficients({"runs_dir": {"fit": fit}})
    assert c["sensor_cpu_seconds_per_run"] == pytest.approx(2.0)
    assert c["sensor_peak_cores"] == pytest.approx(17 / 12.5)
