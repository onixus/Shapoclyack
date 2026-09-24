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
    ch_transform_cpu_seconds_per_host: float | None = None
    ch_transform_rss_bytes_per_host: float | None = None
    endpoint_cpu_seconds_per_item: float | None = None  # API side of a snapshot

    # Sensor: only the report stage runs here; scanning needs live targets.
    report_cpu_seconds_per_host: float | None = None
    report_rss_bytes_per_host: float | None = None
    sensor_cpu_seconds_per_host: float | None = None  # whole pipeline, from a stand
    sensor_peak_rss_bytes: float | None = None  # whole pipeline, from a stand

    # Artifacts and the ingest message.
    run_dir_bytes_per_host: float | None = None
    archive_bytes_per_host: float | None = None
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


def ingest_message_bytes(w: Workload, c: Coefficients) -> float | None:
    """One run's ingest message: the archive, base64'd, when it is inlined."""
    archive = _mul(c.archive_bytes_per_host, w.hosts_per_run)
    if archive is None:
        return None
    if archive > INGEST_INLINE_CAP_BYTES:
        return 0.0  # published without the archive; the envelope is noise
    return archive * BASE64_RATIO


def max_hosts_per_run_for_clickhouse(c: Coefficients, max_payload: int = NATS_DEFAULT_MAX_PAYLOAD) -> float | None:
    """Largest run whose results still reach ClickHouse.

    Two ceilings apply and the lower wins: the broker refuses a message over
    ``max_payload``, and the gateway drops the archive over 4 MB.
    """
    if not c.archive_bytes_per_host:
        return None
    by_payload = max_payload / BASE64_RATIO / c.archive_bytes_per_host
    by_inline = INGEST_INLINE_CAP_BYTES / c.archive_bytes_per_host
    return min(by_payload, by_inline)


def size_api(w: Workload, c: Coefficients) -> Component:
    hosts = w.hosts_per_run
    base = _add(c.api_idle_rss_bytes, c.api_scorer_rss_bytes)
    per_ingest = _add(
        _mul(c.projection_rss_bytes_per_host, hosts),
        _mul(c.ch_transform_rss_bytes_per_host, hosts) if w.clickhouse_enabled else 0.0,
        # The upload is read into memory whole (routes/agents.py) and base64'd
        # into the ingest message beside it.
        _mul(c.archive_bytes_per_host, hosts, 1 + BASE64_RATIO),
    )
    request = _mul(base, w.headroom)
    limit = _mul(_add(base, c.api_dashboard_rss_bytes, _mul(per_ingest, w.concurrent_ingests)), w.headroom)

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
        name="API (per replica)",
        replicas=w.api_replicas,
        cpu_request_millicores=_mul(per_replica_avg, w.headroom),
        # One uvicorn process: Python work is bound to about one core by the
        # GIL however many ingests run at once. The limit above that is for
        # the scanner subprocess of a local-mode scan, sized separately.
        cpu_limit_millicores=1000.0,
        memory_request_bytes=request,
        memory_limit_bytes=limit,
    )
    expanded = _mul(c.run_dir_bytes_per_host, hosts)
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
        _mul(w.api_requests_per_second, 86400, c.api_pg_cpu_seconds_per_request),
    )
    # The peak is every replica projecting at once. A replica's Python side is
    # held to about one core by the GIL, and its backends burn the measured
    # Postgres share of that.
    peak = None
    if c.projection_pg_cpu_seconds_per_host and c.projection_cpu_seconds_per_host:
        share = c.projection_pg_cpu_seconds_per_host / c.projection_cpu_seconds_per_host
        peak = share * w.api_replicas * 1000.0 * w.headroom
    component = Component(
        name="PostgreSQL",
        replicas=1,
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
    if message == 0.0:
        component.notes.append("archive over the 4 MB inline cap: ClickHouse gets no rows for these runs")
    return component


def size_artifacts(w: Workload, c: Coefficients) -> Component:
    per_run = _mul(c.run_dir_bytes_per_host, w.hosts_per_run)
    total = _mul(per_run, w.scans_per_day, w.run_retention_days, w.headroom)
    component = Component(name="Run artifacts (PVC or S3)", storage_bytes=total)
    if c.run_dir_bytes_is_floor:
        component.notes.append("floor: report-stage files only; raw tool output (nmap XML, nuclei, logs) adds to it")
    return component


def size_sensor(w: Workload, c: Coefficients) -> Component:
    hosts = w.hosts_per_run
    component = Component(name="Sensor (per node)", replicas=w.sensors)
    report_cpu = _mul(hosts, c.report_cpu_seconds_per_host)
    report_rss = _mul(hosts, c.report_rss_bytes_per_host)
    if c.sensor_cpu_seconds_per_host is not None and w.sensors:
        daily = w.daily_host_scans * c.sensor_cpu_seconds_per_host
        component.cpu_request_millicores = daily / 86400 / w.sensors * 1000 * w.headroom
    if c.sensor_peak_rss_bytes is not None:
        component.memory_request_bytes = c.sensor_peak_rss_bytes * w.headroom
        component.memory_limit_bytes = c.sensor_peak_rss_bytes * w.headroom * 1.5
    if report_cpu is not None and report_rss is not None:
        component.notes.append(
            f"report stage alone: {report_cpu:,.1f} CPU-s, +{report_rss / MiB:,.0f} MiB per {hosts:,.0f}-host run"
        )
    if c.sensor_cpu_seconds_per_host is None:
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


def render_markdown(workloads: list[Workload], c: Coefficients) -> str:
    estimates = [estimate(w, c) for w in workloads]
    header = "| | " + " | ".join(
        f"{w.assets:,} assets / {w.sensors} sensor{'' if w.sensors == 1 else 's'} / {w.scans_per_day:g} scans/day"
        for w in workloads
    ) + " |"
    lines = [header, "|---|" + "---:|" * len(workloads)]

    def row(label: str, cells: list[str]) -> None:
        lines.append(f"| {label} | " + " | ".join(cells) + " |")

    row("hosts per run", [f"{w.hosts_per_run:,.0f}" for w in workloads])
    for index, name in enumerate(component.name for component in estimates[0]):
        parts = [components[index] for components in estimates]
        # The sensor rows always print: their n/m is the finding, not noise.
        if any(p.cpu_request_millicores is not None or p.cpu_limit_millicores is not None for p in parts) or name.startswith("Sensor"):
            row(
                f"{name}: CPU request / limit",
                [f"{fmt_cpu(p.cpu_request_millicores)} / {fmt_cpu(p.cpu_limit_millicores)}" for p in parts],
            )
        if any(p.memory_request_bytes is not None or p.memory_limit_bytes is not None for p in parts) or name.startswith("Sensor"):
            row(
                f"{name}: memory request / limit",
                [f"{fmt_bytes(p.memory_request_bytes)} / {fmt_bytes(p.memory_limit_bytes)}" for p in parts],
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
            row(f"{name}: volume{qualifier}", [fmt_bytes(p.storage_bytes) for p in parts])
    notes: list[str] = []
    for w, components in zip(workloads, estimates, strict=True):
        for component in components:
            for note in component.notes:
                notes.append(f"- {w.assets:,} / {component.name}: {note}")
    ceiling = max_hosts_per_run_for_clickhouse(c)
    if ceiling is not None:
        notes.append(f"- largest run that still reaches ClickHouse at this archive size: ~{ceiling:,.0f} hosts")
    lines.extend(["", f"Coefficients: {c.source}", "", *notes])
    return "\n".join(lines)


def as_json(workloads: list[Workload], c: Coefficients) -> dict[str, Any]:
    return {
        "coefficients": dataclasses.asdict(c),
        "estimates": [
            {"workload": dataclasses.asdict(w), "components": [dataclasses.asdict(p) for p in estimate(w, c)]}
            for w in workloads
        ],
    }


#: ``scale_measure derive`` over the #337 sandbox runs; docs/sizing.md
#: § Measured coefficients has the environment and the raw figures. A stand
#: overrides them with ``--coefficients`` (measured values win, see
#: ``Coefficients.merged``) rather than by editing these. The sensor's scan
#: stages, a real jobs row and ClickHouse controls rows are absent on purpose:
#: nothing here could measure them.
MEASURED = Coefficients(
    source=(
        "#337 sandbox 2026-09-24: 4 shared vCPU, 16 GiB, PostgreSQL 16.13 (fsync off), "
        "ClickHouse 24.8.14, main at 1ed74b7 — to be confirmed on kind/Arch"
    ),
    pg_bytes_per_asset=722.0,
    pg_bytes_per_service=557.9,
    pg_bytes_per_finding=1246.0,
    pg_bytes_per_finding_observation=261.9,
    pg_bytes_per_endpoint_item=465.6,
    pg_bytes_per_endpoint_change=311.3,
    pg_bytes_per_endpoint_snapshot=962.6,
    api_idle_rss_bytes=164888576,
    api_idle_cpu_millicores=2.0,
    api_scorer_rss_bytes=104652800,
    api_dashboard_rss_bytes=299008000,
    api_cpu_seconds_per_request=0.01899,
    api_pg_cpu_seconds_per_request=0.01418,
    projection_cpu_seconds_per_run=0.0,
    projection_cpu_seconds_per_host=0.01427,
    projection_rss_bytes_per_host=7858.0,
    projection_statements_per_host=29.34,
    projection_pg_cpu_seconds_per_host=0.002872,
    ch_transform_cpu_seconds_per_host=0.0003324,
    ch_transform_rss_bytes_per_host=19270.0,
    endpoint_cpu_seconds_per_item=0.0001176,
    report_cpu_seconds_per_host=0.000573,
    report_rss_bytes_per_host=37490.0,
    run_dir_bytes_per_host=11690.0,
    archive_bytes_per_host=367.7,
    run_dir_bytes_is_floor=True,
    ch_bytes_per_vuln_row=16.5,
    ch_bytes_per_port_row=3.082,
    ch_query_memory_bytes_per_row=5.033,
    ch_idle_rss_bytes=699707392,
    ch_system_log_bytes_per_hour=1267358,
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
    parser.add_argument("--markdown", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    coefficients = MEASURED
    if args.coefficients is not None:
        coefficients = MEASURED.merged(
            Coefficients.from_dict(json.loads(args.coefficients.read_text(encoding="utf-8")))
        )
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
        print(render_markdown(workloads, coefficients))
    else:
        print(json.dumps(as_json(workloads, coefficients), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
