"""Sizing model: N assets / M sensors / K scans a day → CPU, RAM, volumes (#337).

The arithmetic half of ``docs/sizing.md``. ``scale_measure.py`` measures the
coefficients — bytes per row, CPU-seconds and resident memory per host — and
this turns a workload into requests, limits and storage with them. Every
formula is here, in one place, so the table in the doc can be regenerated for
another workload or from another stand's coefficients instead of re-derived by
hand::

    # The representative tiers, with the coefficients committed below
    python -m tests.fixtures.scale_sizing --tiers --markdown

    # One workload, with coefficients measured on a stand
    python -m tests.fixtures.scale_sizing --assets 20000 --sensors 4 \\
        --scans-per-day 48 --coefficients stand-coefficients.json --markdown

What is *not* a measurement is explicit: workload inputs (findings per asset,
request rate, how often an estate is re-scanned) are the operator's to state,
and the few policy choices (``headroom``, the shared-buffers share of RAM) are
named parameters. A coefficient nobody measured is ``None`` and prints as
``n/m``; it is never filled with a plausible number.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import math
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

GiB = 1024**3
MiB = 1024**2

#: Base64 inflates an archive by 4/3; the ingest message carries it inline.
BASE64_RATIO = 4 / 3
#: ``results_ingest.build_gateway_payload``'s default: larger archives are
#: published without the archive, and ClickHouse then gets no rows for the run.
INGEST_INLINE_CAP_BYTES = 4_000_000
#: ``NatsBus.publish_ingest`` publishes every run twice: the tenant subject and
#: the legacy ``ingest.raw_results`` copy, both captured by the INGEST stream.
INGEST_COPIES = 2
#: nats-server's default ``max_payload``; the shipped nats.conf does not raise it.
NATS_DEFAULT_MAX_PAYLOAD = 1024 * 1024
#: ``results_ingest.MAX_UNCOMPRESSED_BYTES``: a sensor upload that expands past
#: this is refused outright.
UPLOAD_EXPANSION_CAP_BYTES = 512 * MiB
#: API defaults (api/services/nats_bus.py) and the shipped nats.conf.
INGEST_MAX_BYTES_DEFAULT = 10 * GiB
EVENTS_MAX_BYTES_DEFAULT = 1 * GiB
NATS_MAX_FILE_SHIPPED = 4_000_000_000  # "4G" in nats.conf is decimal
#: PostgreSQL's default ``max_wal_size``: WAL the server keeps between checkpoints.
PG_MAX_WAL_BYTES = 1 * GiB


@dataclass(frozen=True)
class Coefficients:
    """Measured per-unit costs. ``None`` = not measured; never guessed.

    Field names end in their unit. ``*_per_host`` is per host *in one run*
    (projection and report cost scale with the run, not the estate).
    """

    source: str = "unset"

    # Postgres, bytes including indexes, after a VACUUM between rescans.
    pg_bytes_per_asset: float | None = None  # assets + asset_identifiers + asset_os
    pg_bytes_per_service: float | None = None  # asset_services
    pg_bytes_per_finding: float | None = None  # vulnerabilities, steady state
    pg_bytes_per_finding_observation: float | None = None  # vulnerability_events, never pruned
    pg_bytes_per_job: float | None = None  # jobs, never pruned
    pg_bytes_per_endpoint_item: float | None = None  # endpoint_software_items
    pg_bytes_per_endpoint_change: float | None = None  # endpoint_software_changes
    pg_bytes_per_endpoint_snapshot: float | None = None  # snapshot summary row

    # API process (one uvicorn worker per pod).
    api_idle_rss_bytes: float | None = None
    api_idle_cpu_millicores: float | None = None
    api_scorer_rss_bytes: float | None = None  # EPSS/KEV/exploit overlays, loaded once
    api_dashboard_rss_bytes: float | None = None  # peak added by /api/assets?limit=5000
    api_cpu_seconds_per_request: float | None = None  # list-route mix
    api_pg_cpu_seconds_per_request: float | None = None  # Postgres backends, same mix
    projection_cpu_seconds_per_run: float | None = None
    projection_cpu_seconds_per_host: float | None = None
    projection_rss_bytes_per_host: float | None = None
    projection_statements_per_host: float | None = None
    projection_pg_cpu_seconds_per_host: float | None = None  # Postgres backends
    # The ClickHouse transform with the database the ingest worker has
    # (api/app.py): its per-host lookups are statements and Postgres CPU too.
    ch_transform_cpu_seconds_per_host: float | None = None
    ch_transform_rss_bytes_per_host: float | None = None
    ch_transform_statements_per_host: float | None = None
    ch_transform_pg_cpu_seconds_per_host: float | None = None
    endpoint_cpu_seconds_per_item: float | None = None  # API side of a snapshot

    # Sensor: only the report stage runs here; scanning needs live targets.
    report_cpu_seconds_per_host: float | None = None
    report_rss_bytes_per_host: float | None = None
    # Whole pipeline, from a stand's stage_timings.json (runs-dir).
    sensor_cpu_seconds_per_host: float | None = None
    sensor_cpu_seconds_per_run: float | None = None
    sensor_busy_cores: float | None = None  # mean cores a scan keeps busy
    sensor_peak_cores: float | None = None  # the busiest run's
    sensor_peak_rss_bytes: float | None = None
    sensor_peak_rss_run_hosts: float | None = None  # the largest run it held for

    # Artifacts and the ingest message. The per-run intercepts matter at the
    # ceilings: an archive is ~64 KiB before its first host.
    run_dir_bytes_per_host: float | None = None
    run_dir_bytes_per_run: float | None = None
    archive_bytes_per_host: float | None = None
    archive_bytes_per_run: float | None = None
    ingest_envelope_bytes: float | None = None  # JSON fields + NATS headers around the archive
    run_dir_bytes_is_floor: bool = True  # report stage only; no raw tool output

    # ClickHouse.
    ch_bytes_per_vuln_row: float | None = None
    ch_bytes_per_port_row: float | None = None
    ch_query_memory_bytes_per_row: float | None = None  # tenant-wide diff fetch
    ch_idle_rss_bytes: float | None = None
    ch_system_log_bytes_per_hour: float | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Coefficients:
        """Build from a ``scale_measure derive`` result (or its ``coefficients``)."""
        body = data.get("coefficients", data)
        known = {f.name for f in dataclasses.fields(cls)}
        unknown = sorted(set(body) - known)
        if unknown:
            # A renamed coefficient silently falling back to None would print
            # "n/m" where the stand did measure it.
            raise ValueError(f"unknown coefficient(s): {', '.join(unknown)}")
        return cls(**body)

    def merged(self, other: Coefficients) -> Coefficients:
        """``other``'s measured values over this one's; ``None`` never overrides."""
        updates = {
            f.name: getattr(other, f.name)
            for f in dataclasses.fields(other)
            if f.name != "source" and getattr(other, f.name) is not None
        }
        source = self.source if other.source == "unset" else f"{other.source} (over {self.source})"
        return dataclasses.replace(self, **updates, source=source)


@dataclass(frozen=True)
class Workload:
    """What an installation does. Inputs, not measurements."""

    assets: int
    sensors: int
    scans_per_day: float
    #: Host observations per day across all runs. ``None`` = every asset once a
    #: day. Hosts per run is this divided by ``scans_per_day``.
    host_scans_per_day: float | None = None
    findings_per_asset: float = 3.0
    services_per_asset: float = 4.0
    api_replicas: int = 2
    #: ``OCTO_AGENT_RESULTS_MAX_CONCURRENT_INGESTS`` (default 4).
    concurrent_ingests: int = 4
    api_requests_per_second: float = 5.0
    clickhouse_enabled: bool = True
    run_retention_days: int = 30  # OCTO_RUN_RETENTION_DAYS
    clickhouse_ttl_days: int = 90  # table TTL in init.sql
    ingest_max_age_days: float = 7.0  # OCTO_NATS_INGEST_MAX_AGE_SECONDS
    #: Horizon for the tables nothing prunes (``vulnerability_events``, ``jobs``,
    #: ClickHouse ``system.*_log``): the size after this many days.
    horizon_days: int = 365
    endpoints: int = 0
    packages_per_endpoint: int = 1500
    endpoint_snapshots_per_day: float = 1.0
    endpoint_changed_fraction: float = 0.05
    endpoint_snapshot_retention_days: int = 90
    endpoint_change_retention_days: int = 365
    #: Multiplier on measured averages for requests and on volumes. A policy.
    headroom: float = 1.3
    #: ``shared_buffers`` as a share of the Postgres pod's memory (the
    #: PostgreSQL documentation's starting point is 25%).
    pg_shared_buffers_share: float = 0.25

    @property
    def daily_host_scans(self) -> float:
        return float(self.assets if self.host_scans_per_day is None else self.host_scans_per_day)

    @property
    def hosts_per_run(self) -> float:
        return self.daily_host_scans / self.scans_per_day if self.scans_per_day else 0.0


@dataclass
class Component:
    """Requests, limits and storage for one workload component."""

    name: str
    replicas: int | None = None
    cpu_request_millicores: float | None = None
    cpu_limit_millicores: float | None = None
    memory_request_bytes: float | None = None
    memory_limit_bytes: float | None = None
    storage_bytes: float | None = None  # size at the workload's horizon
    notes: list[str] = field(default_factory=list)


def _mul(*values: float | None) -> float | None:
    """Product, or ``None`` when any factor is unmeasured."""
    out = 1.0
    for value in values:
        if value is None:
            return None
        out *= value
    return out


def _add(*values: float | None) -> float | None:
    """Sum, or ``None`` when any term is unmeasured."""
    if any(value is None for value in values):
        return None
    return float(sum(value for value in values if value is not None))


# --------------------------------------------------------------------------
# The model
# --------------------------------------------------------------------------


def run_bytes(per_run: float | None, per_host: float | None, hosts: float) -> float | None:
    """A run's size from its fit: the fixed part plus the per-host part."""
    return _add(per_run, _mul(per_host, hosts))


def ingest_message_bytes(w: Workload, c: Coefficients) -> float | None:
    """One run's ingest message: the base64'd archive when it is inlined, plus its envelope."""
    archive = run_bytes(c.archive_bytes_per_run, c.archive_bytes_per_host, w.hosts_per_run)
    if archive is None or c.ingest_envelope_bytes is None:
        return None
    if archive > INGEST_INLINE_CAP_BYTES:
        return c.ingest_envelope_bytes  # published without the archive
    return archive * BASE64_RATIO + c.ingest_envelope_bytes


def max_hosts_per_run_for_clickhouse(c: Coefficients, max_payload: int = NATS_DEFAULT_MAX_PAYLOAD) -> float | None:
    """Largest run whose results still reach ClickHouse.

    Two ceilings apply and the lower wins: the broker refuses a message over
    ``max_payload``, and the gateway drops the archive over 4 MB. Both count the
    archive's per-run intercept and the message's envelope; the slope alone put
    this at ~2 100 hosts where 1 950 was refused (review of #337).
    """
    if not c.archive_bytes_per_host or c.archive_bytes_per_run is None or c.ingest_envelope_bytes is None:
        return None
    by_payload = ((max_payload - c.ingest_envelope_bytes) / BASE64_RATIO - c.archive_bytes_per_run) / c.archive_bytes_per_host
    by_inline = (INGEST_INLINE_CAP_BYTES - c.archive_bytes_per_run) / c.archive_bytes_per_host
    return min(by_payload, by_inline)


def api_memory_limit(w: Workload, c: Coefficients, hosts: float) -> float | None:
    """The API's memory limit when runs are ``hosts`` hosts."""
    base = _add(c.api_idle_rss_bytes, c.api_scorer_rss_bytes)
    per_ingest = _add(
        _mul(c.projection_rss_bytes_per_host, hosts),
        _mul(c.ch_transform_rss_bytes_per_host, hosts) if w.clickhouse_enabled else 0.0,
        # The upload is read into memory whole (routes/agents.py) and base64'd
        # into the ingest message beside it.
        _mul(run_bytes(c.archive_bytes_per_run, c.archive_bytes_per_host, hosts), 1 + BASE64_RATIO),
    )
    return _mul(_add(base, c.api_dashboard_rss_bytes, _mul(per_ingest, w.concurrent_ingests)), w.headroom)


def size_api(w: Workload, c: Coefficients) -> Component:
    hosts = w.hosts_per_run
    base = _add(c.api_idle_rss_bytes, c.api_scorer_rss_bytes)
    daily_cpu = _add(
        _mul(c.api_idle_cpu_millicores, 86400 / 1000, w.api_replicas),
        _mul(w.scans_per_day, c.projection_cpu_seconds_per_run),
        _mul(w.daily_host_scans, c.projection_cpu_seconds_per_host),
        _mul(w.daily_host_scans, c.ch_transform_cpu_seconds_per_host) if w.clickhouse_enabled else 0.0,
        _mul(w.api_requests_per_second, 86400, c.api_cpu_seconds_per_request),
        _mul(
            w.endpoints,
            w.endpoint_snapshots_per_day,
            w.packages_per_endpoint,
            c.endpoint_cpu_seconds_per_item,
        )
        if w.endpoints
        else 0.0,
    )
    per_replica_avg = None if daily_cpu is None else daily_cpu / 86400 / w.api_replicas * 1000
    component = Component(
        # Sensors scan (OCTO_JOB_EXECUTION_MODE=agent). main's overlays still
        # run local scans inside this pod; that footprint is the sensor's and
        # is not in these rows (#338 moves the default to agent mode).
        name="API (per replica, agent mode)",
        replicas=w.api_replicas,
        cpu_request_millicores=_mul(per_replica_avg, w.headroom),
        # One uvicorn process: Python work is bound to about one core by the
        # GIL however many ingests run at once.
        cpu_limit_millicores=1000.0,
        memory_request_bytes=_mul(base, w.headroom),
        memory_limit_bytes=api_memory_limit(w, c, hosts),
    )
    expanded = run_bytes(c.run_dir_bytes_per_run, c.run_dir_bytes_per_host, hosts)
    if expanded is not None and expanded > UPLOAD_EXPANSION_CAP_BYTES:
        component.notes.append(
            f"a {hosts:,.0f}-host run expands to {expanded / MiB:,.0f} MiB"
            f"{' or more' if c.run_dir_bytes_is_floor else ''}: a sensor upload over 512 MiB is refused"
        )
    ingest_cpu = _mul(hosts, _add(c.projection_cpu_seconds_per_host, c.projection_pg_cpu_seconds_per_host))
    if ingest_cpu is not None:
        component.notes.append(
            f"one run of {hosts:,.0f} hosts: >= {ingest_cpu:,.0f} CPU-s to project"
            + (
                f", {hosts * c.projection_statements_per_host:,.0f} SQL statements"
                if c.projection_statements_per_host
                else ""
            )
        )
    return component


def size_postgres(w: Workload, c: Coefficients) -> Component:
    estate = _add(
        _mul(w.assets, c.pg_bytes_per_asset),
        _mul(w.assets, w.services_per_asset, c.pg_bytes_per_service),
        _mul(w.assets, w.findings_per_asset, c.pg_bytes_per_finding),
    )
    # Every re-observation of a finding appends a vulnerability_events row and
    # nothing prunes them; jobs are the same, one row per scan. A jobs row is
    # only measurable where scans ran (``scale_measure postgres-live``), and it
    # is K rows a day against S x F observation rows: an unmeasured jobs term
    # is named in a note instead of voiding the volume the observations set.
    jobs = _mul(w.scans_per_day, w.horizon_days, c.pg_bytes_per_job)
    history = _add(
        _mul(w.daily_host_scans, w.findings_per_asset, w.horizon_days, c.pg_bytes_per_finding_observation),
        0.0 if jobs is None else jobs,
    )
    endpoint = 0.0
    if w.endpoints:
        retained_snapshots = min(w.endpoint_snapshot_retention_days, w.horizon_days) * w.endpoint_snapshots_per_day
        endpoint = _add(
            _mul(w.endpoints, w.packages_per_endpoint, max(retained_snapshots, 1.0), c.pg_bytes_per_endpoint_item),
            _mul(
                w.endpoints,
                w.packages_per_endpoint,
                w.endpoint_changed_fraction,
                w.endpoint_snapshots_per_day,
                min(w.endpoint_change_retention_days, w.horizon_days),
                c.pg_bytes_per_endpoint_change,
            ),
            _mul(w.endpoints, w.endpoint_snapshots_per_day, w.horizon_days, c.pg_bytes_per_endpoint_snapshot),
        )
    data = _add(estate, history, endpoint)
    # The hot set is what list pages and the projection touch on every run:
    # the estate tables. History is appended and read by id.
    memory = None if estate is None else max(estate / w.pg_shared_buffers_share, 1 * GiB)
    pg_cpu = _add(
        _mul(w.daily_host_scans, c.projection_pg_cpu_seconds_per_host),
        # The ClickHouse transform looks hosts up in Postgres too (api/app.py
        # hands the ingest worker the database).
        _mul(w.daily_host_scans, c.ch_transform_pg_cpu_seconds_per_host) if w.clickhouse_enabled else 0.0,
        _mul(w.api_requests_per_second, 86400, c.api_pg_cpu_seconds_per_request),
    )
    # The peak is every replica busy at once. A replica's Python side is held
    # to about one core by the GIL; its backends burn the measured Postgres
    # share of that — whichever of projecting or serving requests costs
    # Postgres more per API core (a list page's backends out-burn the API).
    shares = [
        pg / api
        for pg, api in (
            (c.projection_pg_cpu_seconds_per_host, c.projection_cpu_seconds_per_host),
            (c.api_pg_cpu_seconds_per_request, c.api_cpu_seconds_per_request),
        )
        if pg is not None and api
    ]
    peak = max(shares) * w.api_replicas * 1000.0 * w.headroom if shares else None
    component = Component(
        name="PostgreSQL",
        replicas=1,
        # Floors: 250m and one core, so an idle estimate does not starve
        # autovacuum and a checkpoint.
        cpu_request_millicores=None if pg_cpu is None else max(pg_cpu / 86400 * 1000 * w.headroom, 250.0),
        cpu_limit_millicores=None if peak is None else max(peak, 1000.0),
        memory_request_bytes=memory,
        memory_limit_bytes=memory,
        storage_bytes=None if data is None else (data + PG_MAX_WAL_BYTES) * w.headroom,
    )
    if history is not None and w.horizon_days:
        component.notes.append(
            f"grows {history / w.horizon_days / MiB:,.1f} MiB/day forever "
            "(vulnerability_events, jobs: no retention)"
        )
    if jobs is None:
        component.notes.append(
            f"plus {w.scans_per_day:g} jobs rows/day, not in the volume: row size n/m (postgres-live)"
        )
    return component


def size_clickhouse(w: Workload, c: Coefficients) -> Component:
    if not w.clickhouse_enabled:
        return Component(name="ClickHouse", replicas=0, notes=["disabled"])
    rows_vuln = w.assets * w.findings_per_asset
    rows_port = w.assets * w.services_per_asset
    data = _add(_mul(rows_vuln, c.ch_bytes_per_vuln_row), _mul(rows_port, c.ch_bytes_per_port_row))
    # ReplacingMergeTree: a rescan lands a second copy of every key until the
    # background merge collapses it, so the volume holds up to two.
    app = _mul(data, 2)
    logs = _mul(c.ch_system_log_bytes_per_hour, 24, w.horizon_days)
    query = _mul(max(rows_vuln, rows_port), c.ch_query_memory_bytes_per_row)
    memory = _add(c.ch_idle_rss_bytes, query)
    component = Component(
        name="ClickHouse",
        replicas=1,
        memory_request_bytes=_mul(memory, w.headroom),
        memory_limit_bytes=_mul(memory, w.headroom, 2),
        storage_bytes=_mul(_add(app, logs), w.headroom),
    )
    if logs is not None and app is not None and logs > app:
        component.notes.append(
            f"system.*_log tables ({logs / GiB:,.1f} GiB at {w.horizon_days} d) outweigh the data "
            f"({app / GiB:,.2f} GiB): default config sets no TTL on them"
        )
    return component


def size_nats(w: Workload, c: Coefficients, *, replicas: int = 1) -> Component:
    message = ingest_message_bytes(w, c)
    ingest = _mul(w.scans_per_day, w.ingest_max_age_days, INGEST_COPIES, message)
    component = Component(
        name="NATS JetStream (per node)",
        replicas=replicas,
        # JetStream reserves each stream's max_bytes up front: the volume and
        # max_file must hold INGEST + EVENTS at their configured caps.
        storage_bytes=(INGEST_MAX_BYTES_DEFAULT + EVENTS_MAX_BYTES_DEFAULT) * w.headroom,
    )
    if ingest is not None:
        component.notes.append(
            f"INGEST holds {min(ingest, INGEST_MAX_BYTES_DEFAULT) / MiB:,.0f} MiB at this rate "
            f"({w.ingest_max_age_days:g} days); the volume is sized by the reservation"
        )
    if message is not None and message > NATS_DEFAULT_MAX_PAYLOAD:
        component.notes.append(
            f"ingest message {message / MiB:,.1f} MiB > max_payload 1 MiB: publish refused"
        )
    archive = run_bytes(c.archive_bytes_per_run, c.archive_bytes_per_host, w.hosts_per_run)
    if archive is not None and archive > INGEST_INLINE_CAP_BYTES:
        component.notes.append("archive over the 4 MB inline cap: ClickHouse gets no rows for these runs")
    return component


def size_artifacts(w: Workload, c: Coefficients) -> Component:
    per_run = run_bytes(c.run_dir_bytes_per_run, c.run_dir_bytes_per_host, w.hosts_per_run)
    total = _mul(per_run, w.scans_per_day, w.run_retention_days, w.headroom)
    component = Component(name="Run artifacts (PVC or S3)", storage_bytes=total)
    if c.run_dir_bytes_is_floor:
        component.notes.append("floor: report-stage files only; raw tool output (nmap XML, nuclei, logs) adds to it")
    return component


def size_sensor(w: Workload, c: Coefficients) -> Component:
    """A sensor node, from a stand's runs (``scale_measure runs-dir``).

    A scan is bursty: it keeps ``sensor_busy_cores`` busy while it runs and
    nothing between runs, so the request reserves what a running scan uses and
    the limit what the busiest measured run reached. The daily CPU says how
    much of the day that is; spreading it over 24 h would under-request by the
    idle share.
    """
    hosts = w.hosts_per_run
    component = Component(name="Sensor (per node)", replicas=w.sensors)
    report_cpu = _mul(hosts, c.report_cpu_seconds_per_host)
    report_rss = _mul(hosts, c.report_rss_bytes_per_host)
    component.cpu_request_millicores = _mul(c.sensor_busy_cores, 1000, w.headroom)
    component.cpu_limit_millicores = _mul(c.sensor_peak_cores, 1000, w.headroom)
    daily = _add(
        _mul(w.scans_per_day, c.sensor_cpu_seconds_per_run),
        _mul(w.daily_host_scans, c.sensor_cpu_seconds_per_host),
    )
    if daily is not None and c.sensor_busy_cores and w.sensors:
        busy = daily / w.sensors / (c.sensor_busy_cores * 86400)
        component.notes.append(
            f"{daily / w.sensors:,.0f} CPU-s a day each: busy {busy * 100:.1f} % of the day at "
            f"{c.sensor_busy_cores:.1f} cores"
        )
    if c.sensor_peak_rss_bytes is not None:
        component.memory_request_bytes = c.sensor_peak_rss_bytes * w.headroom
        component.memory_limit_bytes = c.sensor_peak_rss_bytes * w.headroom * 1.5
        if c.sensor_peak_rss_run_hosts is not None and hosts > c.sensor_peak_rss_run_hosts:
            component.notes.append(
                f"memory measured on runs of up to {c.sensor_peak_rss_run_hosts:,.0f} hosts; "
                f"these runs are {hosts:,.0f}: re-measure before trusting the limit"
            )
    if report_cpu is not None and report_rss is not None:
        component.notes.append(
            f"report stage alone: {report_cpu:,.1f} CPU-s, +{report_rss / MiB:,.0f} MiB per {hosts:,.0f}-host run"
        )
    if c.sensor_busy_cores is None:
        component.notes.append("scan stages not measured here: needs a stand (runs-dir)")
    return component


def estimate(w: Workload, c: Coefficients) -> list[Component]:
    return [
        size_api(w, c),
        size_sensor(w, c),
        size_postgres(w, c),
        size_clickhouse(w, c),
        size_nats(w, c),
        size_artifacts(w, c),
    ]


# --------------------------------------------------------------------------
# Tiers and rendering
# --------------------------------------------------------------------------

#: Representative installations. The shape is the operator's to change; these
#: exist so the doc's table can be regenerated, not because they are typical.
TIERS: tuple[Workload, ...] = (
    Workload(assets=1_000, sensors=1, scans_per_day=4),
    Workload(assets=10_000, sensors=3, scans_per_day=24),
    Workload(assets=50_000, sensors=10, scans_per_day=100),
)


def fmt_bytes(value: float | None) -> str:
    if value is None:
        return "n/m"
    if value >= GiB:
        return f"{value / GiB:,.1f} GiB"
    return f"{max(value / MiB, 1):,.0f} MiB"


def fmt_cpu(value: float | None) -> str:
    if value is None:
        return "n/m"
    if value >= 1000:
        return f"{value / 1000:,.1f}"
    return f"{math.ceil(value / 10) * 10:,.0f}m"


FILLED_MARK = "†"


def _cells(components: list[Component]) -> dict[tuple[str, str], float | None]:
    return {
        (p.name, kind): value
        for p in components
        for kind, value in (
            ("cpu request", p.cpu_request_millicores),
            ("cpu limit", p.cpu_limit_millicores),
            ("memory request", p.memory_request_bytes),
            ("memory limit", p.memory_limit_bytes),
            ("volume", p.storage_bytes),
        )
    }


def filled_cells(
    w: Workload, merged: Coefficients, own: Coefficients
) -> tuple[set[tuple[str, str]], set[str]]:
    """Cells of ``w``'s estimate that lean on a coefficient ``own`` lacks.

    Found by ablation: each coefficient ``merged`` took from elsewhere is
    unset in turn, and every cell that moves depends on it.
    """
    borrowed = [
        f.name
        for f in dataclasses.fields(Coefficients)
        if f.name != "source"
        and f.type != "bool"
        and getattr(own, f.name) is None
        and getattr(merged, f.name) is not None
    ]
    baseline = _cells(estimate(w, merged))
    cells: set[tuple[str, str]] = set()
    used: set[str] = set()
    for name in borrowed:
        ablated = _cells(estimate(w, dataclasses.replace(merged, **{name: None})))
        moved = {key for key, value in baseline.items() if ablated.get(key) != value}
        if moved:
            cells |= moved
            used.add(name)
    return cells, used


def render_markdown(workloads: list[Workload], c: Coefficients, *, own: Coefficients | None = None) -> str:
    """The sizing table. With ``own``, ``c`` is ``own`` filled from elsewhere
    and every cell that leans on a filled coefficient is marked."""
    estimates = [estimate(w, c) for w in workloads]
    marks: list[set[tuple[str, str]]] = []
    borrowed: set[str] = set()
    for w in workloads:
        cells, used = filled_cells(w, c, own) if own is not None else (set(), set())
        marks.append(cells)
        borrowed |= used
    header = "| | " + " | ".join(
        f"{w.assets:,} assets / {w.sensors} sensor{'' if w.sensors == 1 else 's'} / {w.scans_per_day:g} scans/day"
        for w in workloads
    ) + " |"
    lines = [header, "|---|" + "---:|" * len(workloads)]

    def row(label: str, cells: list[str]) -> None:
        lines.append(f"| {label} | " + " | ".join(cells) + " |")

    def mark(index: int, name: str, kind: str, text: str) -> str:
        return f"{text} {FILLED_MARK}" if (name, kind) in marks[index] else text

    def pair(index: int, name: str, kind: str, request: str, limit: str) -> str:
        return f"{mark(index, name, kind + ' request', request)} / {mark(index, name, kind + ' limit', limit)}"

    row("hosts per run", [f"{w.hosts_per_run:,.0f}" for w in workloads])
    for index, name in enumerate(component.name for component in estimates[0]):
        parts = [components[index] for components in estimates]
        # The running components' rows always print: their n/m is the finding
        # (what a stand did not measure), not noise.
        always = name.startswith(("API", "Sensor", "PostgreSQL", "ClickHouse"))
        if always or any(p.cpu_request_millicores is not None or p.cpu_limit_millicores is not None for p in parts):
            row(
                f"{name}: CPU request / limit",
                [
                    pair(i, name, "cpu", fmt_cpu(p.cpu_request_millicores), fmt_cpu(p.cpu_limit_millicores))
                    for i, p in enumerate(parts)
                ],
            )
        if always or any(p.memory_request_bytes is not None or p.memory_limit_bytes is not None for p in parts):
            row(
                f"{name}: memory request / limit",
                [
                    pair(i, name, "memory", fmt_bytes(p.memory_request_bytes), fmt_bytes(p.memory_limit_bytes))
                    for i, p in enumerate(parts)
                ],
            )
        if any(p.storage_bytes is not None for p in parts) or name.startswith(("Run artifacts", "PostgreSQL", "ClickHouse")):
            # Say what the size is *of*: the unpruned stores at the horizon,
            # the artifact figure a floor while it comes from the report stage.
            qualifier = ""
            if name.startswith(("PostgreSQL", "ClickHouse")):
                horizons = {w.horizon_days for w in workloads}
                qualifier = f" ({horizons.pop()} d)" if len(horizons) == 1 else " (horizon)"
            elif name.startswith("Run artifacts") and c.run_dir_bytes_is_floor:
                qualifier = ", floor"
            row(
                f"{name}: volume{qualifier}",
                [mark(i, name, "volume", fmt_bytes(p.storage_bytes)) for i, p in enumerate(parts)],
            )
    notes: list[str] = []
    for w, components in zip(workloads, estimates, strict=True):
        for component in components:
            for note in component.notes:
                notes.append(f"- {w.assets:,} / {component.name}: {note}")
    ceiling = max_hosts_per_run_for_clickhouse(c)
    if ceiling is not None:
        notes.append(f"- largest run that still reaches ClickHouse at this archive size: ~{ceiling:,.0f} hosts")
    lines.extend(["", f"Coefficients: {c.source}", "", *notes])
    if borrowed:
        lines.extend(
            [
                "",
                f"{FILLED_MARK} leans on coefficients this stand did not measure, taken from "
                f"{MEASURED.source.split(':')[0]}: {', '.join(sorted(borrowed))}",
            ]
        )
    return "\n".join(lines)


def as_json(workloads: list[Workload], c: Coefficients) -> dict[str, Any]:
    return {
        "coefficients": dataclasses.asdict(c),
        "estimates": [
            {"workload": dataclasses.asdict(w), "components": [dataclasses.asdict(p) for p in estimate(w, c)]}
            for w in workloads
        ],
    }


def _spaced(value: float) -> str:
    return f"{value:,.0f}".replace(",", " ")


def hosts_at_api_memory_limit(c: Coefficients, limit_bytes: float, w: Workload | None = None) -> float | None:
    """Largest run an API replica's memory limit holds (the limit is linear in the run)."""
    w = w or Workload(assets=0, sensors=1, scans_per_day=1)
    at0, at1 = api_memory_limit(w, c, 0.0), api_memory_limit(w, c, 1.0)
    if at0 is None or at1 is None or at1 <= at0:
        return None
    return (limit_bytes - at0) / (at1 - at0)


def key_figures(c: Coefficients) -> dict[str, str]:
    """Figures docs/sizing.md quotes in prose, as it quotes them.

    The table is regenerated and compared whole; these are the numbers the
    text around it states, which drifted unseen before (review of #337).
    """
    figures: dict[str, str] = {}
    ceiling = max_hosts_per_run_for_clickhouse(c)
    if ceiling is not None:
        figures["clickhouse_ceiling_hosts"] = f"~{_spaced(math.floor(ceiling / 50) * 50)} hosts"
    per_host = _add(c.projection_cpu_seconds_per_host, c.ch_transform_cpu_seconds_per_host)
    if per_host:
        figures["ingest_hosts_per_second"] = f"~{1 / per_host:.0f} hosts a second"
    if c.ch_transform_cpu_seconds_per_host is not None:
        figures["ch_transform_ms_per_host"] = f"{c.ch_transform_cpu_seconds_per_host * 1000:.2f} ms"
    hosts = hosts_at_api_memory_limit(c, 4 * GiB)
    if hosts is not None:
        figures["api_hosts_at_4gi"] = f"~{_spaced(math.floor(hosts / 1000) * 1000)} hosts"
    return figures


#: ``scale_measure derive`` over the #337 sandbox runs; docs/sizing.md
#: § Measured coefficients has the environment and the raw figures. A stand
#: replaces them with ``--coefficients`` (and fills its gaps from these only
#: with ``--fill-from-sandbox``, cells marked) rather than by editing these.
#: The sensor's scan stages, a real jobs row and ClickHouse controls rows are
#: absent on purpose: nothing here could measure them.
MEASURED = Coefficients(
    source=(
        "#337 sandbox 2026-09-24: 4 shared vCPU, 16 GiB, PostgreSQL 16.13 (fsync off), "
        "ClickHouse 24.8.14, main at 1ed74b7 (ClickHouse step re-run with Postgres at 05447ad) "
        "— to be confirmed on kind/Arch"
    ),
    pg_bytes_per_asset=721.998,
    pg_bytes_per_service=557.875,
    pg_bytes_per_finding=1245.91,
    pg_bytes_per_finding_observation=261.934,
    pg_bytes_per_endpoint_item=465.579,
    pg_bytes_per_endpoint_change=311.296,
    pg_bytes_per_endpoint_snapshot=962.56,
    api_idle_rss_bytes=164888576,
    api_idle_cpu_millicores=2.0,
    api_scorer_rss_bytes=104652800,
    api_dashboard_rss_bytes=299008000,
    api_cpu_seconds_per_request=0.0189881,
    api_pg_cpu_seconds_per_request=0.0141786,
    projection_cpu_seconds_per_run=0.0,
    projection_cpu_seconds_per_host=0.0142705,
    projection_rss_bytes_per_host=7858.34,
    projection_statements_per_host=29.3417,
    projection_pg_cpu_seconds_per_host=0.00287245,
    ch_transform_cpu_seconds_per_host=0.00321548,
    ch_transform_rss_bytes_per_host=18718,
    ch_transform_statements_per_host=4.0,
    ch_transform_pg_cpu_seconds_per_host=0.000458135,
    endpoint_cpu_seconds_per_item=0.0001176,
    report_cpu_seconds_per_host=0.000831196,
    report_rss_bytes_per_host=37026.5,
    run_dir_bytes_per_host=11679.1,
    run_dir_bytes_per_run=1274130,
    archive_bytes_per_host=369.234,
    archive_bytes_per_run=75139.6,
    ingest_envelope_bytes=409,
    run_dir_bytes_is_floor=True,
    ch_bytes_per_vuln_row=17.9604,
    ch_bytes_per_port_row=3.26576,
    ch_query_memory_bytes_per_row=5.033,  # round 0's 50k tier; 10k reads 0 (below resolution)
    ch_idle_rss_bytes=699707392,
    ch_system_log_bytes_per_hour=1267358,  # idle; ~4.8 MB/h under ingest load (docs/sizing.md)
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.fixtures.scale_sizing",
        description="Turn a workload into CPU/RAM/volume sizing (#337).",
    )
    parser.add_argument("--tiers", action="store_true", help="the representative 1k/10k/50k tiers")
    parser.add_argument("--assets", type=int, default=None)
    parser.add_argument("--sensors", type=int, default=1)
    parser.add_argument("--scans-per-day", type=float, default=24)
    parser.add_argument("--host-scans-per-day", type=float, default=None, help="default: every asset once a day")
    parser.add_argument("--findings-per-asset", type=float, default=3.0)
    parser.add_argument("--services-per-asset", type=float, default=4.0)
    parser.add_argument("--api-replicas", type=int, default=2)
    parser.add_argument("--requests-per-second", type=float, default=5.0)
    parser.add_argument("--endpoints", type=int, default=0, help="Lariska agents")
    parser.add_argument("--no-clickhouse", action="store_true")
    parser.add_argument("--horizon-days", type=int, default=365)
    parser.add_argument("--coefficients", type=Path, default=None, help="scale_measure derive output")
    parser.add_argument(
        "--fill-from-sandbox",
        action="store_true",
        help="fill what --coefficients lacks from the #337 sandbox; every cell that leans on it is marked",
    )
    parser.add_argument("--markdown", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    coefficients, own = MEASURED, None
    if args.coefficients is not None:
        # A stand's table is the stand's: what it did not measure prints n/m.
        # The sandbox's figures come from other hardware and another version.
        coefficients = Coefficients.from_dict(json.loads(args.coefficients.read_text(encoding="utf-8")))
        if args.fill_from_sandbox:
            own = coefficients
            coefficients = MEASURED.merged(own)
    elif args.fill_from_sandbox:
        print("error: --fill-from-sandbox fills a stand's --coefficients", file=sys.stderr)
        return 2
    if args.tiers:
        workloads = list(TIERS)
    elif args.assets:
        workloads = [
            Workload(
                assets=args.assets,
                sensors=args.sensors,
                scans_per_day=args.scans_per_day,
                host_scans_per_day=args.host_scans_per_day,
                findings_per_asset=args.findings_per_asset,
                services_per_asset=args.services_per_asset,
                api_replicas=args.api_replicas,
                api_requests_per_second=args.requests_per_second,
                endpoints=args.endpoints,
                clickhouse_enabled=not args.no_clickhouse,
                horizon_days=args.horizon_days,
            )
        ]
    else:
        print("error: pass --tiers or --assets N", file=sys.stderr)
        return 2
    if args.markdown:
        print(render_markdown(workloads, coefficients, own=own))
    else:
        print(json.dumps(as_json(workloads, coefficients), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
