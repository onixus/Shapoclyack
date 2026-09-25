"""Measure the coefficients behind the sizing model (#337).

``scale_profile.py`` answers *how fast* a query path is at 1k / 10k / 50k
assets. This answers *how much* — bytes on disk, CPU-seconds and resident
memory — for the work that grows with the estate, so ``docs/sizing.md`` can
turn "N assets, M sensors, K scans a day" into requests, limits and volume
sizes from a measurement instead of a guess. ``scale_sizing.py`` is the other
half: it reads the coefficients this emits and does the arithmetic.

What it drives is the product's own code, not a model of it:

* **the sensor's report stage** — ``scanner.pipeline.report.build_reports``
  over Pulse-shaped artifacts written by ``pulse_probe.write_pulse_artifacts``
  for the same hosts, ports and CVEs ``scale_seed`` puts in ClickHouse;
* **the API's run projection** — ``run_completion.project_published_run``,
  what ``run_publisher`` runs when a run lands: asset upsert, vulnerability
  fold, service fingerprints;
* **the results gateway and ClickHouse** — ``results_ingest`` and
  ``ch_transform`` on that run's upload archive, then ``system.parts``;
* **the API process** — a real ``python -m api`` against the seeded database,
  loaded with the ``api_latency`` probe;
* **endpoint inventory** — ``endpoint_inventory.ingest_snapshot``, the path a
  Lariska submission takes.

Each measured step runs in a fresh child process so its peak RSS is its own
and not the high-water mark of whatever ran before it in this interpreter.

What it cannot drive is a scan. The scan stages shell out to naabu, nmap,
nuclei and Pulse against live targets, so the raw tool output in a run
directory (nmap XML, nuclei JSONL, logs) and the sensor's CPU per host are not
produced here. ``runs-dir`` measures those from real run directories on a
stand instead; everything this module synthesises is labelled as such in its
output.

Usage (docs/sizing.md § Re-measuring on a stand has the full sequence)::

    # Against a dedicated Postgres + ClickHouse — never production
    python -m tests.fixtures.scale_measure postgres --tiers 1000,10000,50000 \\
        --work-dir /tmp/sizing --out pg.json
    python -m tests.fixtures.scale_measure clickhouse --work-dir /tmp/sizing --out ch.json

    # Real run directories on a stand (read-only)
    python -m tests.fixtures.scale_measure runs-dir /var/lib/shapoclyack/output/runs --out runs.json

    # Coefficients for scale_sizing.py
    python -m tests.fixtures.scale_measure derive pg.json ch.json runs.json --out stand.json

Every result carries an ``environment`` block. A number without the machine it
was taken on is not a coefficient anyone can reuse.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import platform
import resource
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

from tests.fixtures.scale_seed import (
    SeedSpec,
    asset_fqdn,
    asset_ip,
    iter_port_rows,
    iter_vulnerability_rows,
    purge_clickhouse,
)

#: Tenants the harness writes under. Distinct from ``scale_seed``'s default so
#: a fixture seeded for ``scale_profile`` is never counted as a sizing tier.
TENANT_PREFIX = "sizing"

#: Postgres tables a scan result grows. Everything else is configuration or
#: per-login and does not scale with assets, findings or scans.
PG_GROWTH_TABLES: tuple[str, ...] = (
    "assets",
    "asset_identifiers",
    "asset_services",
    "asset_os",
    "vulnerabilities",
    "vulnerability_events",
    "jobs",
    "endpoint_devices",
    "endpoint_identifiers",
    "endpoint_inventory_snapshots",
    "endpoint_software_items",
    "endpoint_software_changes",
)

CH_TABLES: tuple[str, ...] = (
    "shapoclyack_vulnerabilities",
    "shapoclyack_open_ports",
    "shapoclyack_controls",
)

#: A finding sits on one of its host's open ports. HTTP(S) first, because that
#: is where Pulse ``--cve`` and nuclei put most of theirs.
_FINDING_PORT_PREFERENCE = (443, 80, 8443, 8080, 22)

_SEVERITY_BY_CVSS = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


#: Written into the ``stage_timings.json`` of every run this module builds.
SYNTHETIC_MARKER = "tests.fixtures.scale_measure"


def tenant_for(assets: int) -> str:
    return f"{TENANT_PREFIX}-{assets}"


# --------------------------------------------------------------------------
# Environment and process accounting
# --------------------------------------------------------------------------


def _meminfo_bytes(key: str) -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{key}:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None


def environment(*, postgres_url: str = "", clickhouse_url: str = "") -> dict[str, Any]:
    """Where a measurement was taken. Recorded next to every number."""
    env: dict[str, Any] = {
        "measured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "mem_total_bytes": _meminfo_bytes("MemTotal"),
    }
    try:
        env["loadavg"] = list(os.getloadavg())
    except OSError:
        env["loadavg"] = None
    try:
        env["git_commit"] = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        env["git_commit"] = None
    if postgres_url:
        env["postgres"] = _postgres_environment(postgres_url)
    if clickhouse_url:
        env["clickhouse"] = _clickhouse_environment(clickhouse_url)
    return env


def _postgres_environment(url: str) -> dict[str, Any]:
    from sqlalchemy import text

    from api.db.engine import get_engine

    # Durability settings change WAL volume and write CPU, and a lab server is
    # often run with them off. Recorded so nobody reads a fsync=off number as a
    # production one.
    names = (
        "server_version",
        "shared_buffers",
        "work_mem",
        "max_connections",
        "fsync",
        "synchronous_commit",
        "full_page_writes",
        "autovacuum",
    )
    with get_engine(url).connect() as conn:
        return {name: conn.execute(text(f"SHOW {name}")).scalar() for name in names}


def _clickhouse_environment(url: str) -> dict[str, Any]:
    from api.services import clickhouse_client as ch

    client = ch.get_client(url)
    return {
        "version": client.query("SELECT version()").result_rows[0][0],
        "uptime_seconds": client.query("SELECT uptime()").result_rows[0][0],
    }


@dataclass(frozen=True)
class ProcSample:
    """CPU-seconds and memory of one process, from ``/proc``."""

    cpu_seconds: float
    rss_bytes: int
    hwm_bytes: int


def proc_sample(pid: int) -> ProcSample | None:
    """``None`` when the process is not visible (gone, or another host's)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    # comm (field 2) may contain spaces; everything after the closing paren
    # is space-separated, starting at field 3.
    fields = stat.rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    cpu = (int(fields[11]) + int(fields[12])) / ticks
    values: dict[str, int] = {}
    for line in status.splitlines():
        key, _, rest = line.partition(":")
        if key in ("VmRSS", "VmHWM"):
            values[key] = int(rest.split()[0]) * 1024
    return ProcSample(cpu, values.get("VmRSS", 0), values.get("VmHWM", 0))


def self_usage() -> dict[str, float]:
    """This process's CPU-seconds so far and its peak RSS in bytes."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        # Linux reports ru_maxrss in KiB.
        "max_rss_bytes": usage.ru_maxrss * 1024,
    }


def current_rss_bytes() -> int:
    sample = proc_sample(os.getpid())
    return sample.rss_bytes if sample else 0


# --------------------------------------------------------------------------
# Synthetic hosts and run directories (pure except for the files written)
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class HostObservation:
    """One host as a scan saw it. Derived from the ``scale_seed`` rows."""

    index: int
    ip: str
    fqdn: str | None
    ports: tuple[tuple[int, str], ...]
    #: ``(cve, cvss)`` — the same pairs ``scale_seed`` writes to ClickHouse.
    cves: tuple[tuple[str, float], ...]


def iter_hosts(spec: SeedSpec) -> Iterator[HostObservation]:
    """Hosts with the ports and CVEs ``scale_seed`` generates for them.

    Grouped out of ``iter_port_rows``/``iter_vulnerability_rows`` rather than
    re-drawn, so the Postgres side of a tier and its ClickHouse side describe
    the same estate: asset #9000 has the same CVEs in both stores.
    """
    from tests.fixtures.scale_seed import iter_identifier_rows

    fqdns = {
        row["identifier_value"].split(".", 1)[0]: row["identifier_value"]
        for row in iter_identifier_rows(spec)
        if row["identifier_type"] == "fqdn"
    }
    ports_by_ip: dict[str, list[tuple[int, str]]] = {}
    for row in iter_port_rows(spec, run_id="sizing"):
        ports_by_ip.setdefault(row[1], []).append((int(row[2]), str(row[3])))
    cves_by_ip: dict[str, list[tuple[str, float]]] = {}
    for row in iter_vulnerability_rows(spec):
        cves_by_ip.setdefault(row[1], []).append((str(row[2]), float(row[3])))
    for index in range(spec.assets):
        ip = asset_ip(index)
        label = asset_fqdn(index).split(".", 1)[0]
        yield HostObservation(
            index=index,
            ip=ip,
            fqdn=fqdns.get(label),
            ports=tuple(ports_by_ip.get(ip, ())),
            cves=tuple(cves_by_ip.get(ip, ())),
        )


def finding_port(host: HostObservation) -> int:
    """The open TCP port a host's findings are reported on."""
    tcp = [port for port, proto in host.ports if proto == "tcp"]
    for preferred in _FINDING_PORT_PREFERENCE:
        if preferred in tcp:
            return preferred
    return tcp[0] if tcp else 0


def severity_for(cvss: float) -> str:
    for floor, name in _SEVERITY_BY_CVSS:
        if cvss >= floor:
            return name
    return "unknown"


def write_run_dir(run_dir: Path, spec: SeedSpec) -> dict[str, Any]:
    """Write a Pulse-backed run for ``spec``'s hosts through the scanner's writers.

    ``write_pulse_artifacts`` lays down ``services.json``/``os.json``/
    ``pulse_cves.json`` as the Pulse stage does, then ``build_reports`` turns
    them into everything the report stage writes (``alive_hosts.json``,
    ``vulnerabilities.json``, findings, CSV, SARIF, Markdown, HTML). Those are
    the files the API projection reads.

    Not produced, because no scanner ran: nmap XML, nuclei JSONL, the tool
    logs, ``diff.json`` and the PDF. Byte counts from this directory are
    therefore a *floor* for a real run of the same size. Enrichment databases
    (CVSS4, GeoIP, ASN) are off: they are downloads, not part of the repo.
    """
    from scanner.pipeline.protocol import format_endpoint
    from scanner.pipeline.pulse_probe import write_pulse_artifacts
    from scanner.pipeline.report import build_reports
    from scanner.pipeline.service_schema import CveRecord, OsRecord, ServiceRecord
    from scanner.pipeline.utils import write_lines

    run_dir.mkdir(parents=True, exist_ok=True)
    services: list[ServiceRecord] = []
    os_records: list[OsRecord] = []
    cves: list[CveRecord] = []
    alive: list[str] = []
    open_ports: list[str] = []
    hostnames: dict[str, dict[str, Any]] = {}
    for host in iter_hosts(spec):
        alive.append(host.ip)
        if host.fqdn:
            hostnames[host.ip] = {"primary": host.fqdn, "names": [host.fqdn]}
        for port, proto in host.ports:
            open_ports.append(format_endpoint(host.ip, str(port), proto))
            services.append(
                ServiceRecord(ip=host.ip, port=port, protocol=proto, service="unknown", host=host.fqdn or "")
            )
        os_records.append(OsRecord(ip=host.ip, family="Linux", detail="Linux 5.x", confidence=80))
        port = finding_port(host)
        for cve, cvss in host.cves:
            cves.append(
                CveRecord(
                    cve_id=cve,
                    ip=host.ip,
                    port=port,
                    cvss=cvss,
                    severity=severity_for(cvss),
                    title=cve,
                    confidence=80,
                )
            )

    started = time.process_time()
    # What the ports stage leaves behind; the ClickHouse transform reads it.
    write_lines(run_dir / "open_ports.txt", open_ports)
    write_pulse_artifacts(run_dir, services, os_records, cves)
    build_reports(
        output_dir=run_dir,
        total_targets=len(alive),
        alive_hosts=alive,
        open_ports=open_ports,
        nmap_dir=run_dir / "nmap",
        markdown_summary=True,
        html_summary=True,
        csv_export=True,
        json_export=True,
        sarif_export=True,
        hostnames_map=hostnames,
        cvss4_enabled=False,
        geoip_enabled=False,
        asn_enabled=False,
        report_primary=True,
    )
    cpu = time.process_time() - started
    # The projection reads stage_timings.json only when vulnerabilities.json is
    # empty; written anyway so a zero-finding tier is still an assessed run.
    # ``synthetic`` is what keeps ``runs-dir`` from taking this directory for a
    # real scan's and replacing the report-stage floor with it.
    (run_dir / "stage_timings.json").write_text(
        json.dumps(
            {
                "synthetic": SYNTHETIC_MARKER,
                "stages": [{"name": "pulse", "status": "ok"}, {"name": "report", "status": "ok"}],
            }
        ),
        encoding="utf-8",
    )
    return {
        "hosts": len(alive),
        "ports": len(open_ports),
        "findings": len(cves),
        "report_stage_cpu_seconds": round(cpu, 3),
    }


def directory_bytes(root: Path) -> dict[str, int]:
    """Apparent size of every file under ``root``, by path relative to it."""
    return {
        str(path.relative_to(root)): path.stat().st_size
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def upload_archive(root: Path) -> bytes:
    """The upload archive a sensor would send for ``root``.

    Same packing as ``agent.worker._tar_directory`` (sorted ``rglob``, gzip at
    tarfile's default level). Reimplemented rather than imported so measuring
    a run does not import the sensor and its dependencies.
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tf:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                tf.add(path, arcname=str(path.relative_to(root)))
    return buffer.getvalue()


# --------------------------------------------------------------------------
# Postgres
# --------------------------------------------------------------------------


def harness_settings(postgres_url: str, work_dir: Path):
    """API ``Settings`` for driving services in-process, never for serving.

    ``env="dev"`` for the same reason ``tests.conftest.make_settings`` uses it:
    nothing here authenticates anybody, and the production checks refuse to
    build settings without secrets the harness has no use for. NATS and
    ClickHouse are off so the projection measures Postgres work only — the
    asset-event publish and the ClickHouse ingest are separate consumers.
    """
    from api.settings import Settings

    return Settings(
        env="dev",
        output_dir=work_dir / "output",
        state_dir=work_dir / "state",
        config_path=Path("scanner/config/default.yaml"),
        postgres_url=postgres_url,
        nats_url="",
        clickhouse_url="",
        jwt_secret="sizing-harness",
    )


def pg_table_sizes(postgres_url: str, tables: tuple[str, ...] = PG_GROWTH_TABLES) -> dict[str, dict[str, int]]:
    """Heap, index, TOAST and total bytes plus exact row count per table."""
    from sqlalchemy import text

    from api.db.engine import get_engine

    out: dict[str, dict[str, int]] = {}
    with get_engine(postgres_url).connect() as conn:
        for table in tables:
            row = conn.execute(
                text(
                    """
                    SELECT pg_relation_size(c.oid),
                           pg_indexes_size(c.oid),
                           COALESCE(pg_total_relation_size(NULLIF(c.reltoastrelid, 0)), 0),
                           pg_total_relation_size(c.oid)
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = current_schema() AND c.relname = :table
                    """
                ),
                {"table": table},
            ).one_or_none()
            if row is None:
                continue
            # Identifiers come from the constant tuple above, never from input.
            rows = conn.execute(text(f'SELECT count(*) FROM "{table}"')).scalar_one()
            out[table] = {
                "heap": int(row[0]),
                "indexes": int(row[1]),
                "toast": int(row[2]),
                "total": int(row[3]),
                "rows": int(rows),
            }
    return out


def size_delta(before: dict[str, dict[str, int]], after: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    """Per-table growth between two :func:`pg_table_sizes` snapshots."""
    delta: dict[str, dict[str, int]] = {}
    for table, now in after.items():
        was = before.get(table, {})
        change = {key: value - int(was.get(key, 0)) for key, value in now.items()}
        if any(change.values()):
            delta[table] = change
    return delta


def with_application_name(postgres_url: str, name: str) -> str:
    """``postgres_url`` with ``application_name`` set, so its backends can be told apart."""
    from sqlalchemy.engine import make_url

    return make_url(postgres_url).update_query_dict({"application_name": name}).render_as_string(
        hide_password=False
    )


@dataclass(frozen=True)
class BackendCpu:
    """CPU-seconds of a set of Postgres backends at one instant."""

    pids: frozenset[int]
    cpu_seconds: float


def pg_backend_cpu(postgres_url: str, *, application_name: str | None = None) -> BackendCpu | None:
    """CPU-seconds of the backends serving this database, when on this host.

    The projection's cost is split between the API process and the Postgres
    backends running its statements; the second half only shows up here.
    ``application_name`` narrows it to one client's connections, so anything
    else talking to the database meanwhile is not billed to the measurement.
    ``None`` when the server is remote — its processes are not in ``/proc``.
    """
    from sqlalchemy import text

    from api.db.engine import get_engine

    query = "SELECT pid FROM pg_stat_activity WHERE datname = current_database()"
    params: dict[str, str] = {}
    if application_name:
        query += " AND application_name = :name"
        params["name"] = application_name
    with get_engine(postgres_url).connect() as conn:
        pids = [int(pid) for (pid,) in conn.execute(text(query), params)]
    samples = [proc_sample(pid) for pid in pids]
    if not samples or any(sample is None for sample in samples):
        return None
    return BackendCpu(frozenset(pids), sum(sample.cpu_seconds for sample in samples if sample is not None))


def backend_cpu_delta(before: BackendCpu | None, after: BackendCpu | None) -> float | None:
    """CPU the backends burnt between two samples, when that is knowable.

    A backend that exits in between takes its CPU with it — a pool closing an
    overflow connection does exactly that under concurrency — and the sum
    would then undercount, or go negative. Only a set that merely grew (new
    backends are counted from zero, which is right) gives an answer.
    """
    if before is None or after is None or not before.pids <= after.pids:
        return None
    return after.cpu_seconds - before.cpu_seconds


def _ensure_tenant(postgres_url: str, tenant_id: str) -> None:
    """The tenant row every tier's assets hang off (``assets.tenant_id`` is an FK)."""
    from tests.fixtures import scale_seed

    scale_seed._ensure_tenant(postgres_url, tenant_id)  # noqa: SLF001


def run_path(settings, tenant_id: str, run_id: str) -> Path:
    """Where a published run of ``tenant_id`` lives on the local backend."""
    from api.services.artifact_store import keys
    from api.services.artifact_store import workspace

    return workspace.scratch_run_dir(settings, keys.run_ref(run_id, tenant_id))


def child_build_run(args: argparse.Namespace) -> dict[str, Any]:
    """Child step: write one tier's run directory (the sensor's report stage)."""
    spec = SeedSpec(tenant_id=args.tenant, assets=args.assets, seed=args.seed)
    settings = harness_settings(args.postgres_url, Path(args.work_dir))
    run_dir = run_path(settings, args.tenant, args.run_id)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    rss_before = current_rss_bytes()
    stats = write_run_dir(run_dir, spec)
    files = directory_bytes(run_dir)
    usage = self_usage()
    return {
        **stats,
        "run_dir_bytes": sum(files.values()),
        "files": files,
        "archive_bytes": len(upload_archive(run_dir)),
        "rss_before_bytes": rss_before,
        "peak_rss_bytes": int(usage["max_rss_bytes"]),
    }


class StatementCounter:
    """Count SQL statements on an engine while the context is open.

    The count is the machine-independent half of the projection cost: each
    statement is a round-trip, sub-millisecond on a local socket and the
    dominant term once the database is across a network (same reasoning as
    ``scale_profile.postgres_query_counts``).
    """

    def __init__(self, engine) -> None:
        self.engine = engine
        self.count = 0

    def _before(self, *_args: Any, **_kwargs: Any) -> None:
        self.count += 1

    def __enter__(self) -> StatementCounter:
        from sqlalchemy import event

        event.listen(self.engine, "before_cursor_execute", self._before)
        return self

    def __exit__(self, *_exc: Any) -> None:
        from sqlalchemy import event

        event.remove(self.engine, "before_cursor_execute", self._before)


def child_project_run(args: argparse.Namespace) -> dict[str, Any]:
    """Child step: project one published run into Postgres, as the API does.

    ``project_published_run`` rather than ``on_run_published``: the latter
    adds only the notification fan-out, which is a thread sending to whatever
    channels a tenant configured — not work that scales with the run.
    """
    from api.db.engine import get_engine
    from api.services import run_completion

    # Every connection this step opens carries its own name, so the backend
    # CPU below is this projection's and not whatever else shares the server.
    backend_name = f"sizing-harness-{os.getpid()}"
    url = with_application_name(args.postgres_url, backend_name)
    settings = harness_settings(url, Path(args.work_dir))
    _ensure_tenant(url, args.tenant)
    source = run_path(settings, args.tenant, args.source_run_id)
    target = run_path(settings, args.tenant, args.run_id)
    if source != target:
        # A rescan is the same hosts under a new run id: copy the directory
        # rather than rebuilding it, so only the projection is being timed.
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)

    # The risk scorer loads the EPSS/KEV/exploit overlays on first use and then
    # keeps them for the life of the process. That is a per-replica constant,
    # not a per-host cost, so it is measured apart from the projection.
    from api.services.risk_scoring import get_scorer

    rss_imports = current_rss_bytes()
    cpu_imports = self_usage()["cpu_seconds"]
    get_scorer()
    scorer = {
        "cpu_seconds": round(self_usage()["cpu_seconds"] - cpu_imports, 3),
        "rss_bytes": current_rss_bytes() - rss_imports,
    }

    before = pg_table_sizes(url)
    backend_before = pg_backend_cpu(url, application_name=backend_name)
    rss_before = current_rss_bytes()
    cpu_before = self_usage()["cpu_seconds"]
    wall_started = time.monotonic()
    with StatementCounter(get_engine(url)) as statements:
        run_completion.project_published_run(
            settings,
            f"sizing-{args.run_id}",
            run_id=args.run_id,
            tenant_id=args.tenant,
            status="succeeded",
        )
    wall = time.monotonic() - wall_started
    usage = self_usage()
    backend_cpu = backend_cpu_delta(backend_before, pg_backend_cpu(url, application_name=backend_name))
    after = pg_table_sizes(url)
    return {
        "run_id": args.run_id,
        "api_cpu_seconds": round(usage["cpu_seconds"] - cpu_before, 3),
        "postgres_backend_cpu_seconds": None if backend_cpu is None else round(backend_cpu, 3),
        "wall_seconds": round(wall, 3),
        "statements": statements.count,
        "process_rss_after_imports_bytes": rss_imports,
        "scorer_load": scorer,
        "rss_before_bytes": rss_before,
        "peak_rss_bytes": int(usage["max_rss_bytes"]),
        "tables_after": after,
        "growth": size_delta(before, after),
    }


def pg_vacuum(postgres_url: str, tables: tuple[str, ...] = PG_GROWTH_TABLES) -> None:
    """Plain ``VACUUM`` (not FULL): what autovacuum would have done by now.

    It does not return space to the OS; it makes dead row versions reusable,
    which is the difference between a table that bloats once per update round
    and one that bloats forever.
    """
    from api.db.engine import get_engine

    engine = get_engine(postgres_url)
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        for table in tables:
            conn.exec_driver_sql(f'VACUUM "{table}"')


#: Store URLs reach a child through its environment, not its argv: they carry
#: passwords, and a command line is readable by every local user in ``ps``.
_URL_ENV = {"postgres_url": "OCTO_POSTGRES_URL", "clickhouse_url": "OCTO_CLICKHOUSE_URL", "nats_url": "OCTO_NATS_URL"}


def _run_child(step: str, **kwargs: Any) -> dict[str, Any]:
    """Run one measured step in a fresh interpreter and return its JSON."""
    argv = [sys.executable, "-m", "tests.fixtures.scale_measure", step]
    env = dict(os.environ)
    for key, value in kwargs.items():
        if key in _URL_ENV:
            env[_URL_ENV[key]] = str(value or "")
            continue
        argv.extend([f"--{key.replace('_', '-')}", str(value)])
    completed = subprocess.run(argv, capture_output=True, text=True, check=False, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"{step} failed ({completed.returncode}):\n{completed.stderr[-4000:]}")
    return json.loads(completed.stdout.strip().splitlines()[-1])


def measure_postgres_tier(
    postgres_url: str, work_dir: Path, *, assets: int, seed: int, rescans: int = 2
) -> dict[str, Any]:
    """One tier: build its run, project it, then re-project it ``rescans`` times.

    The first projection is what registering an estate of ``assets`` hosts
    costs. The rescans are what *keeping* it costs: every one re-observes the
    same hosts and findings. A ``VACUUM`` separates them, so the growth of the
    second rescan is what survives routine maintenance — the per-scan growth
    that does not level off.
    """
    tenant = tenant_for(assets)
    common = {"postgres_url": postgres_url, "work_dir": work_dir, "tenant": tenant, "assets": assets, "seed": seed}
    first_run = f"sizing-{assets}-r0"
    build = _run_child("_build-run", run_id=first_run, **common)
    projections = [
        _run_child("_project-run", run_id=first_run, source_run_id=first_run, **common)
    ]
    for index in range(1, rescans + 1):
        pg_vacuum(postgres_url)
        projections.append(
            _run_child(
                "_project-run",
                run_id=f"sizing-{assets}-r{index}",
                source_run_id=first_run,
                **common,
            )
        )
    return {"assets": assets, "tenant": tenant, "run": build, "projections": projections}


# --------------------------------------------------------------------------
# Results ingest: NATS gateway payload and ClickHouse
# --------------------------------------------------------------------------


#: Core-NATS subject the broker probe publishes to. No stream captures it (the
#: streams take ``jobs.>``, ``ingest.>`` and ``events.>``) and nothing
#: subscribes, so the broker drops the message once it has checked its size.
PROBE_SUBJECT_PREFIX = "sizing.probe"


def nats_header_bytes(headers: dict[str, str]) -> int:
    """Size of the header block nats-py sends ahead of a message with ``headers``."""
    lines = "".join(f"{key}: {value}\r\n" for key, value in headers.items())
    return len(f"NATS/1.0\r\n{lines}\r\n".encode("utf-8"))


def probe_broker(nats_url: str, body: bytes, *, headers: dict[str, str]) -> dict[str, Any]:
    """Would the stand's broker take this ingest message? Asked without touching its streams.

    The first version published through ``nats_bus``, whose connect creates or
    *updates* JOBS/INGEST/EVENTS with whatever ``OCTO_NATS_*`` the harness's
    environment held — resetting a stand's retention and replica count — and
    left each tier's run in INGEST for the stand's ClickHouse worker to ingest
    during the measurement (review of #337). A bare connection and one core
    publish to :data:`PROBE_SUBJECT_PREFIX` exercise the same ``max_payload``
    check and leave nothing behind.
    """
    import asyncio

    import nats

    subject = f"{PROBE_SUBJECT_PREFIX}.{os.getpid()}"

    async def probe() -> dict[str, Any]:
        nc = await nats.connect(nats_url, connect_timeout=5, max_reconnect_attempts=0)
        try:
            found: dict[str, Any] = {"max_payload": int(nc.max_payload)}
            try:
                await nc.publish(subject, body, headers=headers)
                await nc.flush(timeout=5)
            except Exception as exc:  # noqa: BLE001 - the refusal is the finding
                return {**found, "accepted": False, "refused": str(exc) or type(exc).__name__}
            return {**found, "accepted": True}
        finally:
            await nc.close()

    try:
        return asyncio.run(probe())
    except Exception as exc:  # noqa: BLE001 - an unreachable broker is a recorded fact, not a crash
        return {"max_payload": None, "accepted": None, "refused": f"broker unreachable: {type(exc).__name__}"}


def child_ingest_run(args: argparse.Namespace) -> dict[str, Any]:
    """Child step: one run through the results gateway and the ClickHouse transform.

    Four separate facts, measured on the real code:

    * whether the gateway accepts the archive at all —
      ``results_ingest.validate_archive`` refuses one that expands past
      ``MAX_UNCOMPRESSED_BYTES`` (512 MiB), the same check the upload route
      makes, so a sensor could not deliver such a run;
    * what the gateway would publish by default — ``build_gateway_payload``
      inlines the archive only up to its 4 MB default, and without the archive
      ``ch_transform`` has nothing to read — and how much of that message is
      envelope (JSON fields and NATS headers) rather than archive;
    * whether the broker accepts that message (``--nats-url``), asked by
      :func:`probe_broker`, which publishes nothing to JetStream;
    * what the transform costs and what ClickHouse receives when the archive
      *is* inlined — forced here so bytes per row can be measured at every tier.
      With ``--postgres-url`` the transform makes the per-host criticality and
      exposure lookups the API's ingest worker makes (``api/app.py`` hands it
      settings with the database), and their statements and backend CPU are
      counted like the projection's.
    """
    from contextlib import nullcontext

    from api.db.engine import get_engine
    from api.services import ch_transform
    from api.services import clickhouse_client as ch
    from api.services import nats_bus, results_ingest

    backend_name = f"sizing-harness-{os.getpid()}"
    url = with_application_name(args.postgres_url, backend_name) if args.postgres_url else ""
    settings = harness_settings(url, Path(args.work_dir))
    run_dir = run_path(settings, args.tenant, args.run_id)
    archive = upload_archive(run_dir)
    common = {
        "job_id": f"sizing-{args.run_id}",
        "run_id": args.run_id,
        "agent_id": "sizing-harness",
        "exit_code": 0,
        "archive_bytes": archive,
        "tenant_id": args.tenant,
    }
    result: dict[str, Any] = {"archive_bytes": len(archive)}
    try:
        default = results_ingest.build_gateway_payload(**common)
    except results_ingest.IngestError as exc:
        result["gateway_refused"] = str(exc)
    else:
        body = json.dumps(default, separators=(",", ":")).encode("utf-8")
        # The headers NatsBus.publish_ingest sends with it (publish_json).
        headers = {
            "Nats-Msg-Id": nats_bus.ingest_msg_id(
                job_id=common["job_id"], run_id=args.run_id, archive_sha256=str(default["archive_sha256"])
            ),
            "tenant_id": args.tenant,
        }
        result["gateway_payload_bytes"] = len(body)
        result["archive_inlined_by_default"] = "archive_b64" in default
        result["envelope_bytes"] = len(body) - len(default.get("archive_b64") or "") + nats_header_bytes(headers)
        if args.nats_url:
            probe = probe_broker(args.nats_url, body, headers=headers)
            result["nats_max_payload"] = probe["max_payload"]
            result["nats_accepted"] = probe["accepted"]
            if "refused" in probe:
                result["nats_refused"] = probe["refused"]

    # Only the fields ch_transform reads, built by hand: the gateway refuses to
    # build a payload for an archive past its expansion ceiling, and the rows
    # are still worth measuring there.
    forced = {
        "tenant_id": args.tenant,
        "run_id": args.run_id,
        "archive_b64": base64.b64encode(archive).decode("ascii"),
    }
    backend_before = pg_backend_cpu(url, application_name=backend_name) if url else None
    rss_before = current_rss_bytes()
    cpu_before = self_usage()["cpu_seconds"]
    with StatementCounter(get_engine(url)) if url else nullcontext() as statements:
        vuln_rows, port_rows, control_rows = ch_transform.transform_ingest_payload(forced, settings=settings)
    cpu_transform = self_usage()["cpu_seconds"] - cpu_before
    if url:
        backend_cpu = backend_cpu_delta(backend_before, pg_backend_cpu(url, application_name=backend_name))
        result["transform_statements"] = statements.count
        result["transform_postgres_cpu_seconds"] = None if backend_cpu is None else round(backend_cpu, 3)
    client = ch.get_client(args.clickhouse_url)
    inserted = {
        "vulnerabilities": ch.insert_rows(client, ch.VULN_TABLE, ch.VULN_COLUMNS, vuln_rows),
        "open_ports": ch.insert_rows(client, ch.PORTS_TABLE, ch.PORT_COLUMNS, port_rows),
        "controls": ch.insert_rows(client, ch.CONTROLS_TABLE, ch.CONTROL_COLUMNS, control_rows),
    }
    usage = self_usage()
    result.update(
        {
            "rows": inserted,
            "transform_with_postgres": bool(url),
            "transform_cpu_seconds": round(cpu_transform, 3),
            "insert_client_cpu_seconds": round(usage["cpu_seconds"] - cpu_before - cpu_transform, 3),
            "rss_before_bytes": rss_before,
            "peak_rss_bytes": int(usage["max_rss_bytes"]),
        }
    )
    return result


def ch_table_stats(clickhouse_url: str, database: str = "shapoclyack") -> dict[str, dict[str, int]]:
    """Active-part rows and bytes per table: what the volume actually holds."""
    from api.services import clickhouse_client as ch

    client = ch.get_client(clickhouse_url)
    rows = client.query(
        """
        SELECT table, sum(rows), sum(bytes_on_disk), sum(data_compressed_bytes),
               sum(data_uncompressed_bytes), count()
        FROM system.parts
        WHERE active AND database = {db:String}
        GROUP BY table
        ORDER BY table
        """,
        parameters={"db": database},
    ).result_rows
    return {
        str(table): {
            "rows": int(count),
            "bytes_on_disk": int(disk),
            "compressed_bytes": int(compressed),
            "uncompressed_bytes": int(uncompressed),
            "active_parts": int(parts),
        }
        for table, count, disk, compressed, uncompressed, parts in rows
    }


def ch_server_memory(clickhouse_url: str) -> dict[str, int | None]:
    """Resident memory as the server reports it, and its own tracked total."""
    from api.services import clickhouse_client as ch

    client = ch.get_client(clickhouse_url)
    metrics = dict(
        client.query(
            "SELECT metric, value FROM system.asynchronous_metrics "
            "WHERE metric IN ('MemoryResident', 'CGroupMemoryUsed')"
        ).result_rows
    )
    tracked = client.query("SELECT value FROM system.metrics WHERE metric = 'MemoryTracking'").result_rows
    return {
        "resident_bytes": int(metrics["MemoryResident"]) if "MemoryResident" in metrics else None,
        "tracked_bytes": int(tracked[0][0]) if tracked else None,
    }


def ch_system_log_growth(clickhouse_url: str, *, since: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bytes the server's own ``system.*_log`` tables hold, per hour of uptime.

    The image's default configuration keeps query, trace, text, metric and
    asynchronous-metric logs with no TTL, and they grow whether or not a scan
    ever runs. ``since`` is an earlier sample of the same server: the rate is
    then the growth between the two, which leaves out whatever the server did
    before it (a measurement run, a first merge) and is the steady rate. With
    no earlier sample — or one from before a restart — it is bytes over uptime.
    """
    from api.services import clickhouse_client as ch

    client = ch.get_client(clickhouse_url)
    client.command("SYSTEM FLUSH LOGS")
    uptime = int(client.query("SELECT uptime()").result_rows[0][0])
    tables = ch_table_stats(clickhouse_url, database="system")
    logs = {name: stats for name, stats in tables.items() if name.endswith("_log")}
    total = sum(stats["bytes_on_disk"] for stats in logs.values())
    rate = round(total / (uptime / 3600.0)) if uptime else None
    window = uptime
    if since and 0 < int(since.get("uptime_seconds", 0)) < uptime:
        window = uptime - int(since["uptime_seconds"])
        rate = round((total - int(since["bytes_on_disk"])) / (window / 3600.0))
    return {
        "uptime_seconds": uptime,
        "bytes_on_disk": total,
        "bytes_per_hour": rate,
        "window_seconds": window,
        "tables": logs,
    }


def measure_clickhouse_tier(
    clickhouse_url: str,
    work_dir: Path,
    *,
    assets: int,
    seed: int,
    postgres_url: str = "",
    nats_url: str = "",
    reingest: bool = True,
) -> dict[str, Any]:
    """Ingest one tier's run, merge, and measure; optionally ingest it again.

    ``OPTIMIZE … FINAL`` stands in for the background merges a live server
    runs eventually, so bytes per row are steady-state bytes. The re-ingest
    (a rescan of the same hosts) shows the other half: the tables are
    ``ReplacingMergeTree`` on ``(tenant, ip, cve|port)``, so a rescan adds a
    full copy of the rows until the next merge collapses it. That transient
    copy is the headroom the volume needs.
    """
    from api.services import clickhouse_client as ch
    from tests.fixtures.scale_profile import clickhouse_read_stats

    tenant = tenant_for(assets)
    run_id = f"sizing-{assets}-r0"
    # Built here rather than reused from the Postgres pass, so the upload this
    # measures is exactly the run whose bytes it reports.
    build = _run_child(
        "_build-run",
        postgres_url=postgres_url,
        work_dir=work_dir,
        tenant=tenant,
        assets=assets,
        seed=seed,
        run_id=run_id,
    )
    if postgres_url:
        # The transform looks every host up in the registry; a run the
        # projection registered finds its assets there, so this tier's must be
        # too (idempotent: scale_seed inserts ON CONFLICT DO NOTHING).
        from tests.fixtures.scale_seed import seed_postgres

        seed_postgres(postgres_url, SeedSpec(tenant_id=tenant, assets=assets, seed=seed))
    client = ch.get_client(clickhouse_url)

    def optimize() -> None:
        for table in CH_TABLES:
            client.command(f"OPTIMIZE TABLE shapoclyack.{table} FINAL")

    def ingest() -> dict[str, Any]:
        return _run_child(
            "_ingest-run",
            postgres_url=postgres_url,
            clickhouse_url=clickhouse_url,
            nats_url=nats_url,
            work_dir=work_dir,
            tenant=tenant,
            assets=assets,
            seed=seed,
            run_id=run_id,
        )

    # A tier measured before lands on its own earlier rows, which the merge
    # collapses, and its growth would read as zero. Start from none.
    purge_clickhouse(clickhouse_url, tenant, wait=True)
    optimize()
    before = ch_table_stats(clickhouse_url)
    first = ingest()
    optimize()
    merged = ch_table_stats(clickhouse_url)
    out: dict[str, Any] = {
        "assets": assets,
        "tenant": tenant,
        "run": build,
        "ingest": first,
        "growth": _ch_delta(before, merged),
        "queries": clickhouse_read_stats(clickhouse_url, tenant),
        "server_memory": ch_server_memory(clickhouse_url),
    }
    if reingest:
        again = ingest()
        unmerged = ch_table_stats(clickhouse_url)
        optimize()
        out["reingest"] = {
            "ingest": again,
            "growth_before_merge": _ch_delta(merged, unmerged),
            "growth_after_merge": _ch_delta(merged, ch_table_stats(clickhouse_url)),
        }
    return out


def _ch_delta(before: dict[str, dict[str, int]], after: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    return {
        table: {key: value - int(before.get(table, {}).get(key, 0)) for key, value in stats.items()}
        for table, stats in after.items()
    }


# --------------------------------------------------------------------------
# The API process under the api_latency probe
# --------------------------------------------------------------------------

#: The page the dashboard asks for (``assets.MAX_LIMIT``): the largest single
#: response the API builds, and the one that sets a replica's memory peak.
DASHBOARD_PATH = "/api/assets?limit=5000"
#: ``application_name`` of the API-under-test's database connections.
API_BACKEND_NAME = "sizing-harness-api"


def _wait_http(url: str, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def measure_api(
    postgres_url: str,
    work_dir: Path,
    *,
    tenant: str,
    port: int,
    concurrency: tuple[int, ...] = (1, 8, 32),
    requests: int = 40,
    idle_seconds: float = 60.0,
) -> dict[str, Any]:
    """Start ``python -m api`` on the seeded database and account for it.

    Measured from ``/proc`` on the API's own PID, so the numbers are the
    replica's: resident memory at rest, CPU burnt by the in-process workers
    while nothing is asked of it, CPU per request under the ``api_latency``
    route mix, and the peak (``VmHWM``) after the dashboard's 5000-row page.
    ``python -m api`` is one uvicorn process — exactly what a pod runs.
    """
    from tests.fixtures import api_latency

    api_dir = work_dir / "api"
    api_dir.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "OCTO_ENV": "dev",
        "OCTO_API_HOST": "127.0.0.1",
        "OCTO_API_PORT": str(port),
        # Named, so the Postgres CPU each request costs can be read off the
        # API's own backends (pg_backend_cpu) and nobody else's.
        "OCTO_POSTGRES_URL": with_application_name(postgres_url, API_BACKEND_NAME),
        "OCTO_OUTPUT_DIR": str(api_dir / "output"),
        "OCTO_STATE_DIR": str(api_dir / "state"),
        "OCTO_NATS_URL": "",
        "OCTO_CLICKHOUSE_URL": "",
        "OCTO_LOG_LEVEL": "WARNING",
        # The retro matcher's first tick on a fresh process re-reads every
        # stored fingerprint (hundreds of thousands after the tiers): a one-off
        # sweep that would be read as the replica's idle cost. Off, and named
        # as unmeasured in docs/sizing.md.
        "OCTO_RETRO_MATCH_ENABLED": "false",
    }
    base_url = f"http://127.0.0.1:{port}"
    log_path = api_dir / "api.log"
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen([sys.executable, "-m", "api"], env=env, stdout=log, stderr=log)
        try:
            if not _wait_http(f"{base_url}/livez", timeout=180):
                raise RuntimeError(f"API did not come up on {base_url}; see {log_path}")
            # Startup work (migrations check, leader elections, first sweeps)
            # settles before the idle window opens.
            time.sleep(10)
            idle_start = proc_sample(proc.pid)
            time.sleep(idle_seconds)
            idle_end = proc_sample(proc.pid)
            assert idle_start is not None and idle_end is not None

            token = api_latency.login(base_url, "admin", "admin-change-me")
            cells: list[dict[str, Any]] = []
            for conc in concurrency:
                for path in (*api_latency.DEFAULT_PATHS, DASHBOARD_PATH):
                    before = proc_sample(proc.pid)
                    pg_before = pg_backend_cpu(postgres_url, application_name=API_BACKEND_NAME)
                    cell_started = time.monotonic()
                    probe = api_latency.probe_path(
                        base_url,
                        path,
                        token=token,
                        tenant_id=tenant,
                        concurrency=conc,
                        requests=requests,
                        timeout=120.0,
                    )
                    after = proc_sample(proc.pid)
                    pg_cpu = backend_cpu_delta(
                        pg_before, pg_backend_cpu(postgres_url, application_name=API_BACKEND_NAME)
                    )
                    cell_wall = time.monotonic() - cell_started
                    assert before is not None and after is not None
                    cells.append(
                        {
                            "path": path,
                            "concurrency": conc,
                            "requests": probe.n,
                            "errors": probe.errors,
                            "p95_ms": probe.p95_ms,
                            "cpu_ms_per_request": round(
                                (after.cpu_seconds - before.cpu_seconds) * 1000 / max(probe.n, 1), 2
                            ),
                            # Cores the process kept busy: one uvicorn worker
                            # tops out near 1.0 however many clients wait.
                            "cpu_cores_busy": round((after.cpu_seconds - before.cpu_seconds) / cell_wall, 2),
                            "postgres_cpu_ms_per_request": (
                                None if pg_cpu is None else round(pg_cpu * 1000 / max(probe.n, 1), 2)
                            ),
                            "rss_after_bytes": after.rss_bytes,
                        }
                    )
            final = proc_sample(proc.pid)
            assert final is not None
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
    idle_cpu = idle_end.cpu_seconds - idle_start.cpu_seconds
    return {
        "tenant": tenant,
        "idle": {
            "seconds": idle_seconds,
            "rss_bytes": idle_end.rss_bytes,
            "cpu_seconds": round(idle_cpu, 3),
            "cpu_millicores": round(idle_cpu / idle_seconds * 1000, 1),
        },
        "requests": cells,
        "peak_rss_bytes": final.hwm_bytes,
        "final_rss_bytes": final.rss_bytes,
    }


# --------------------------------------------------------------------------
# Endpoint inventory (Lariska agents)
# --------------------------------------------------------------------------


def _software_template() -> list[dict[str, Any]]:
    """The package shapes from the committed schema-v1 fixture."""
    fixture = Path(__file__).with_name("endpoint_inventory_v1_valid.json")
    return list(json.loads(fixture.read_text(encoding="utf-8"))["software"])


def snapshot_request(device: int, *, packages: int, generation: int, changed: float, tag: str = "sizing"):
    """A schema-v1 snapshot for one synthetic device.

    Package *shapes* (publisher, architecture, source, version style) come from
    ``endpoint_inventory_v1_valid.json``; names are made unique per index so a
    snapshot really carries ``packages`` rows. ``generation`` > 0 bumps the
    version of the first ``changed`` fraction — an upgrade, which is what the
    change log records. ``tag`` goes into the snapshot and agent ids, which are
    unique across tenants: a second measurement under another tenant must not
    replay the first one's snapshots.
    """
    from api.schemas import EndpointInventorySnapshotRequest

    template = _software_template()
    bumped = int(packages * changed) if generation else 0
    software = []
    for index in range(packages):
        shape = template[index % len(template)]
        version = str(shape.get("version") or "1.0")
        if index < bumped:
            version = f"{version}+sizing{generation}"
        software.append({**shape, "name": f"{shape['name']}-{index:04d}", "version": version})
    return EndpointInventorySnapshotRequest(
        schema_version=1,
        snapshot_id=f"snap_{tag}_{device:05d}_{generation}",
        agent_id=f"{tag}-agent-{device:05d}",
        collected_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        hostname=f"endpoint-{device:05d}.sizing.example.internal",
        os_family="linux",
        os_name="Ubuntu",
        os_version="24.04",
        os_arch="x86_64",
        agent_version="1.0.0",
        identifiers=[{"identifier_type": "mac_hash", "value_hash": f"{device:032x}"}],
        software=software,
    )


def child_endpoints(args: argparse.Namespace) -> dict[str, Any]:
    """Child step: ``--devices`` first snapshots, then one upgrade round each."""
    from api.services import endpoint_inventory

    settings = harness_settings(args.postgres_url, Path(args.work_dir))
    endpoint_inventory.configure(settings)
    _ensure_tenant(args.postgres_url, args.tenant)

    def submit(generation: int) -> dict[str, Any]:
        before = pg_table_sizes(args.postgres_url)
        cpu_before = self_usage()["cpu_seconds"]
        for device in range(args.devices):
            request = snapshot_request(
                device, packages=args.packages, generation=generation, changed=args.changed, tag=args.tenant
            )
            endpoint_inventory.ingest_snapshot(
                tenant_id=args.tenant, agent_id=request.agent_id, request=request
            )
        cpu = self_usage()["cpu_seconds"] - cpu_before
        return {
            "snapshots": args.devices,
            "api_cpu_seconds": round(cpu, 3),
            "growth": size_delta(before, pg_table_sizes(args.postgres_url)),
        }

    rss_before = current_rss_bytes()
    first = submit(0)
    upgrade = submit(1)
    return {
        "tenant": args.tenant,
        "devices": args.devices,
        "packages": args.packages,
        "changed": args.changed,
        "first": first,
        "upgrade": upgrade,
        "rss_before_bytes": rss_before,
        "peak_rss_bytes": int(self_usage()["max_rss_bytes"]),
    }


# --------------------------------------------------------------------------
# A stand's own database (read-only)
# --------------------------------------------------------------------------

#: Tables worth a per-row figure from real data, beyond the growth tables:
#: what the synthetic runs never write (audit, publications, deliveries).
PG_LIVE_TABLES: tuple[str, ...] = PG_GROWTH_TABLES + (
    "audit_events",
    "auth_events",
    "risk_score_snapshots",
    "run_publications",
    "nats_outbox",
    "webhook_deliveries",
    "generated_reports",
    "workflow_event_markers",
    "software_cve_matches",
)

#: Below this many rows a bytes-per-row figure is mostly page granularity.
LIVE_MIN_ROWS = 1000

#: Real-data figures that replace the synthetic ones in ``derive``.
_LIVE_COEFFICIENTS = {
    "jobs": "pg_bytes_per_job",
    "vulnerabilities": "pg_bytes_per_finding",
    "vulnerability_events": "pg_bytes_per_finding_observation",
    "asset_services": "pg_bytes_per_service",
    "endpoint_software_items": "pg_bytes_per_endpoint_item",
    "endpoint_software_changes": "pg_bytes_per_endpoint_change",
    "endpoint_inventory_snapshots": "pg_bytes_per_endpoint_snapshot",
}


def pg_live_row_costs(postgres_url: str) -> dict[str, dict[str, float]]:
    """Bytes per row of every table that grows, from a database that has history.

    Read-only, and cheap on a large database: the row count is the planner's
    estimate (``reltuples``, current after autovacuum's ANALYZE) rather than a
    ``count(*)`` over a table that may hold a billion rows. What it measures
    that the synthetic tiers cannot: a ``jobs`` row as real scans wrote it,
    real findings' evidence, and whatever bloat routine maintenance leaves.
    """
    from sqlalchemy import text

    from api.db.engine import get_engine

    out: dict[str, dict[str, float]] = {}
    with get_engine(postgres_url).connect() as conn:
        for table in PG_LIVE_TABLES:
            row = conn.execute(
                text(
                    """
                    SELECT c.reltuples, pg_total_relation_size(c.oid)
                    FROM pg_class c
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = current_schema() AND c.relname = :table
                    """
                ),
                {"table": table},
            ).one_or_none()
            if row is None:
                continue
            rows, total = max(float(row[0]), 0.0), int(row[1])
            out[table] = {
                "rows_estimate": rows,
                "total_bytes": total,
                "bytes_per_row": round(total / rows, 1) if rows else None,
            }
    return out


# --------------------------------------------------------------------------
# Real run directories (a stand, read-only)
# --------------------------------------------------------------------------


def _json_len(path: Path) -> int | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return len(data) if isinstance(data, list) else None


def _resumed(timings: dict[str, Any]) -> bool:
    """A ``--resume`` run skipped what its checkpoint had done (StageTimer.skip)."""
    return any(
        isinstance(stage, dict) and stage.get("status") == "skipped" and stage.get("detail") == "checkpoint"
        for stage in timings.get("stages", [])
    )


def measure_runs_dir(root: Path, *, archive: bool = False) -> dict[str, Any]:
    """Bytes per run and per host from run directories a stand actually wrote.

    ``root`` is ``$OCTO_OUTPUT_DIR/runs`` (both layouts: ``runs/<run_id>`` and
    ``runs/_tenants/<tenant>/<run_id>``). A directory counts as a run when it
    has ``alive_hosts.json``; its host count is that list's length, and its
    target count ``summary.json``'s ``total_targets`` when the report wrote one.
    Nothing is written. ``archive`` also gzips each run the way the sensor
    does, which reads every byte — leave it off on a large volume.

    Two kinds of directory are left out and counted instead: the ones this
    module synthesised (their files are a floor, not a scan's), and runs that
    resumed from a checkpoint (their CPU covers only the stages they re-ran).
    """
    candidates = [path.parent for path in root.rglob("alive_hosts.json")]
    runs: list[dict[str, Any]] = []
    skipped = {"synthetic": 0, "resumed": 0}
    for run_dir in sorted(set(candidates)):
        try:
            timings = json.loads((run_dir / "stage_timings.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            timings = {}
        if not isinstance(timings, dict):
            timings = {}
        if timings.get("synthetic"):
            skipped["synthetic"] += 1
            continue
        if _resumed(timings):
            skipped["resumed"] += 1
            continue
        try:
            summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            summary = {}
        files = directory_bytes(run_dir)
        entry: dict[str, Any] = {
            "run": str(run_dir.relative_to(root)),
            "hosts": _json_len(run_dir / "alive_hosts.json"),
            "targets": summary.get("total_targets") if isinstance(summary, dict) else None,
            "findings": _json_len(run_dir / "vulnerabilities.json"),
            "bytes": sum(files.values()),
            "largest_files": sorted(files.items(), key=lambda item: -item[1])[:5],
            "pipeline_wall_sec": timings.get("pipeline_wall_sec"),
            # Written by scanner/pipeline/stage_timing.py since #337; absent
            # from runs made by an older sensor.
            "resources": timings.get("resources"),
            "stages": {
                stage.get("name"): stage.get("duration_sec")
                for stage in timings.get("stages", [])
                if isinstance(stage, dict) and stage.get("status") == "ok"
            },
        }
        if archive:
            entry["archive_bytes"] = len(upload_archive(run_dir))
        runs.append(entry)
    return {"root": str(root), "runs": runs, "skipped": skipped, "fit": fit_runs(runs)}


# --------------------------------------------------------------------------
# Coefficients (pure)
# --------------------------------------------------------------------------


def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float] | None:
    """Least-squares ``y = intercept + slope * x``; ``None`` below two distinct x."""
    xs = {x for x, _ in points}
    if len(xs) < 2:
        return None
    n = len(points)
    mean_x = sum(x for x, _ in points) / n
    mean_y = sum(y for _, y in points) / n
    sxx = sum((x - mean_x) ** 2 for x, _ in points)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in points)
    slope = sxy / sxx
    return mean_y - slope * mean_x, slope


def fit_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """Bytes, CPU and memory per host (and per run) across real runs, when there are enough.

    Sensor CPU is fitted against alive hosts, the model's unit. Discovery also
    scales with the address space swept (``targets``), so a stand whose runs
    sweep large, sparse ranges should read the per-run intercept with that in
    mind; the targets are recorded per run for exactly that reading.
    """
    points = [(float(r["hosts"]), float(r["bytes"])) for r in runs if r.get("hosts")]
    fit = linear_fit(points)
    archive_points = [
        (float(r["hosts"]), float(r["archive_bytes"])) for r in runs if r.get("hosts") and "archive_bytes" in r
    ]
    archive_fit = linear_fit(archive_points)
    measured = [r for r in runs if r.get("hosts") and isinstance(r.get("resources"), dict)]

    def cpu(run: dict[str, Any]) -> float:
        return float(run["resources"]["cpu_sec"]) + float(run["resources"]["children_cpu_sec"])

    cpu_fit = linear_fit([(float(r["hosts"]), cpu(r)) for r in measured])
    # Cores the scan kept busy on average over its wall time: what a sensor
    # needs while it scans (the request), and the busiest run (the limit).
    cores = [cpu(r) / float(r["pipeline_wall_sec"]) for r in measured if r.get("pipeline_wall_sec")]
    # The scan process at its peak plus its largest tool: a floor for the pod,
    # since tools that ran side by side (nse_concurrency) add up.
    peaks = [
        (float(r["resources"]["max_rss_mb"]) + float(r["resources"]["children_max_rss_mb"])) * 2**20
        for r in measured
    ]
    return {
        "runs_with_hosts": len(points),
        "bytes_per_run": round(fit[0]) if fit else None,
        "bytes_per_host": round(fit[1]) if fit else None,
        "archive_bytes_per_run": round(archive_fit[0]) if archive_fit else None,
        "archive_bytes_per_host": round(archive_fit[1]) if archive_fit else None,
        "runs_with_resources": len(measured),
        "sensor_cpu_seconds_per_run": round(max(cpu_fit[0], 0.0), 3) if cpu_fit else None,
        "sensor_cpu_seconds_per_host": round(cpu_fit[1], 4) if cpu_fit else None,
        "sensor_busy_cores": round(sum(cores) / len(cores), 3) if cores else None,
        "sensor_peak_cores": round(max(cores), 3) if cores else None,
        "sensor_peak_rss_bytes": round(max(peaks)) if peaks else None,
        # The peak holds for runs up to this size; memory grows with a run.
        "sensor_peak_rss_run_hosts": max(r["hosts"] for r in measured) if measured else None,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def merge_results(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Several commands' output as one, with its coefficients derived.

    List sections (tiers, endpoint runs) are concatenated, so two files that
    each measured part of a section add up instead of the later one winning.
    """
    merged: dict[str, Any] = {}
    for document in documents:
        for key, value in document.items():
            if key == "coefficients":
                continue
            if isinstance(value, list) and isinstance(merged.get(key), list):
                merged[key] = [*merged[key], *value]
            else:
                merged[key] = value
    return {**merged, "coefficients": derive_coefficients(merged)}


def _slope(points: list[tuple[float, float]]) -> float | None:
    """Per-unit cost: the fitted slope, or the ratio when there is one point."""
    points = [(x, y) for x, y in points if x]
    if not points:
        return None
    fit = linear_fit(points)
    if fit is None:
        return sum(y for _, y in points) / sum(x for x, _ in points)
    return fit[1]


def _intercept(points: list[tuple[float, float]]) -> float | None:
    fit = linear_fit(points)
    return None if fit is None else max(fit[0], 0.0)


def _table_total(growth: dict[str, dict[str, int]], *tables: str) -> int:
    return sum(int(growth.get(table, {}).get("total", 0)) for table in tables)


def _table_rows(growth: dict[str, dict[str, int]], table: str) -> int:
    return int(growth.get(table, {}).get("rows", 0))


def _round(value: float | None, significant: int = 6) -> float | None:
    """Significant digits, not decimals: CPU-seconds per item are ~1e-5."""
    return None if value is None else float(f"{value:.{significant}g}")


def derive_coefficients(results: dict[str, Any]) -> dict[str, Any]:
    """Collapse raw measurements into ``scale_sizing.Coefficients`` fields.

    Per-unit costs are slopes across tiers, so a fixed per-run or per-process
    cost lands in the intercept instead of inflating the per-host figure. A
    field whose measurement is absent from ``results`` is left out, which
    ``Coefficients`` reads as not measured.
    """
    out: dict[str, Any] = {}
    pg = results.get("postgres") or []
    if pg:
        first = [tier["projections"][0] for tier in pg]
        rescans = [p for tier in pg for p in tier["projections"][1:]]
        # Last rescan of each tier: after a VACUUM, so what it adds is what
        # stays — the per-observation growth, net of reusable dead tuples.
        settled = [tier["projections"][-1] for tier in pg if len(tier["projections"]) > 1]
        out["pg_bytes_per_asset"] = _slope(
            [
                (tier["assets"], _table_total(p["growth"], "assets", "asset_identifiers", "asset_os"))
                for tier, p in zip(pg, first, strict=True)
            ]
        )
        out["pg_bytes_per_service"] = _slope(
            [(_table_rows(p["growth"], "asset_services"), _table_total(p["growth"], "asset_services")) for p in first]
        )
        # Steady state: the first write plus whatever the rescans added.
        out["pg_bytes_per_finding"] = _slope(
            [
                (
                    _table_rows(tier["projections"][0]["growth"], "vulnerabilities"),
                    sum(_table_total(p["growth"], "vulnerabilities") for p in tier["projections"]),
                )
                for tier in pg
            ]
        )
        if settled:
            out["pg_bytes_per_finding_observation"] = _slope(
                [
                    (_table_rows(p["growth"], "vulnerability_events"), _table_total(p["growth"], "vulnerability_events"))
                    for p in settled
                ]
            )
        base = rescans or first
        hosts = {p["run_id"]: tier["assets"] for tier in pg for p in tier["projections"]}
        out["projection_cpu_seconds_per_host"] = _slope([(hosts[p["run_id"]], p["api_cpu_seconds"]) for p in base])
        out["projection_cpu_seconds_per_run"] = _intercept([(hosts[p["run_id"]], p["api_cpu_seconds"]) for p in base])
        out["projection_statements_per_host"] = _slope([(hosts[p["run_id"]], p["statements"]) for p in base])
        pg_cpu = [
            (hosts[p["run_id"]], p["postgres_backend_cpu_seconds"])
            for p in base
            if p.get("postgres_backend_cpu_seconds") is not None
        ]
        if pg_cpu:
            out["projection_pg_cpu_seconds_per_host"] = _slope(pg_cpu)
        out["projection_rss_bytes_per_host"] = _slope(
            [
                (tier["assets"], max(p["peak_rss_bytes"] - p["rss_before_bytes"] for p in tier["projections"]))
                for tier in pg
            ]
        )
        scorer = sorted(p["scorer_load"]["rss_bytes"] for tier in pg for p in tier["projections"])
        out["api_scorer_rss_bytes"] = scorer[len(scorer) // 2]

    ch = results.get("clickhouse") or []
    # The sensor-side figures: the ClickHouse pass builds its own runs (the ones
    # it uploads), so those win when both passes ran.
    runs = [tier["run"] for tier in ch if "run" in tier] or [tier["run"] for tier in pg if "run" in tier]
    if runs:
        out["report_cpu_seconds_per_host"] = _slope([(r["hosts"], r["report_stage_cpu_seconds"]) for r in runs])
        out["report_rss_bytes_per_host"] = _slope(
            [(r["hosts"], r["peak_rss_bytes"] - r["rss_before_bytes"]) for r in runs]
        )
        out["run_dir_bytes_per_host"] = _slope([(r["hosts"], r["run_dir_bytes"]) for r in runs])
        out["archive_bytes_per_host"] = _slope([(r["hosts"], r["archive_bytes"]) for r in runs])
        # The intercepts matter at the ceilings: a run's archive is ~64 KiB
        # before its first host, and against a 1 MiB max_payload that is the
        # difference between the ceiling the review measured and ~150 hosts
        # more (review of #337).
        out["run_dir_bytes_per_run"] = _intercept([(r["hosts"], r["run_dir_bytes"]) for r in runs])
        out["archive_bytes_per_run"] = _intercept([(r["hosts"], r["archive_bytes"]) for r in runs])
        out["run_dir_bytes_is_floor"] = True

    if ch:
        def rows_bytes(table: str) -> list[tuple[float, float]]:
            return [
                (tier["growth"][table]["rows"], tier["growth"][table]["bytes_on_disk"])
                for tier in ch
                if table in tier["growth"]
            ]

        out["ch_bytes_per_vuln_row"] = _slope(rows_bytes("shapoclyack_vulnerabilities"))
        out["ch_bytes_per_port_row"] = _slope(rows_bytes("shapoclyack_open_ports"))
        out["ch_transform_cpu_seconds_per_host"] = _slope(
            [(tier["assets"], tier["ingest"]["transform_cpu_seconds"]) for tier in ch]
        )
        out["ch_transform_rss_bytes_per_host"] = _slope(
            [(tier["assets"], tier["ingest"]["peak_rss_bytes"] - tier["ingest"]["rss_before_bytes"]) for tier in ch]
        )
        # Measured with the database the ingest worker has (api/app.py): the
        # per-host lookups are part of the cost, and a figure taken without
        # them is not the production one (review of #337).
        with_pg = [tier for tier in ch if tier["ingest"].get("transform_with_postgres")]
        if with_pg:
            out["ch_transform_statements_per_host"] = _slope(
                [(tier["assets"], tier["ingest"]["transform_statements"]) for tier in with_pg]
            )
            pg_cpu = [
                (tier["assets"], tier["ingest"]["transform_postgres_cpu_seconds"])
                for tier in with_pg
                if tier["ingest"].get("transform_postgres_cpu_seconds") is not None
            ]
            if pg_cpu:
                out["ch_transform_pg_cpu_seconds_per_host"] = _slope(pg_cpu)
        envelopes = [tier["ingest"]["envelope_bytes"] for tier in ch if tier["ingest"].get("envelope_bytes")]
        if envelopes:
            out["ingest_envelope_bytes"] = max(envelopes)
        largest = max(ch, key=lambda tier: tier["assets"])
        # memory_usage is 0 below the tracker's resolution: that is "too small
        # to see", not a coefficient of zero.
        probes = [q for q in largest.get("queries", []) if q.get("read_rows") and q.get("memory_bytes")]
        if probes:
            out["ch_query_memory_bytes_per_row"] = max(q["memory_bytes"] / q["read_rows"] for q in probes)
        out["ch_idle_rss_bytes"] = largest["server_memory"]["resident_bytes"]
    if results.get("clickhouse_server_memory", {}).get("resident_bytes"):
        # Measured with nothing running, which is what "idle" should mean.
        out["ch_idle_rss_bytes"] = results["clickhouse_server_memory"]["resident_bytes"]
    logs = results.get("clickhouse_system_logs")
    if logs and logs.get("bytes_per_hour") is not None:
        out["ch_system_log_bytes_per_hour"] = logs["bytes_per_hour"]

    api = results.get("api")
    if api:
        out["api_idle_rss_bytes"] = api["idle"]["rss_bytes"]
        out["api_idle_cpu_millicores"] = api["idle"]["cpu_millicores"]
        dashboard = [cell for cell in api["requests"] if cell["path"] == DASHBOARD_PATH]
        lists = [cell for cell in api["requests"] if cell["path"] != DASHBOARD_PATH]
        if dashboard:
            out["api_dashboard_rss_bytes"] = max(api["peak_rss_bytes"] - api["idle"]["rss_bytes"], 0)
        served = sum(cell["requests"] for cell in lists)
        if served:
            out["api_cpu_seconds_per_request"] = (
                sum(cell["cpu_ms_per_request"] * cell["requests"] for cell in lists) / served / 1000
            )
        with_pg = [cell for cell in lists if cell.get("postgres_cpu_ms_per_request") is not None]
        if with_pg:
            out["api_pg_cpu_seconds_per_request"] = (
                sum(cell["postgres_cpu_ms_per_request"] * cell["requests"] for cell in with_pg)
                / sum(cell["requests"] for cell in with_pg)
                / 1000
            )

    endpoint_runs = results.get("endpoints") or []
    if endpoint_runs:
        # Each figure from the run with the most rows of its kind: a few dozen
        # rows is page granularity, not a row size.
        def most(table: str, phase: str) -> dict[str, Any]:
            return max(endpoint_runs, key=lambda run: _table_rows(run[phase]["growth"], table))

        items_run = most("endpoint_software_items", "first")
        items = _table_rows(items_run["first"]["growth"], "endpoint_software_items")
        if items:
            out["pg_bytes_per_endpoint_item"] = _table_total(items_run["first"]["growth"], "endpoint_software_items") / items
            out["endpoint_cpu_seconds_per_item"] = items_run["first"]["api_cpu_seconds"] / items
        changes_run = most("endpoint_software_changes", "upgrade")
        changes = _table_rows(changes_run["upgrade"]["growth"], "endpoint_software_changes")
        if changes:
            out["pg_bytes_per_endpoint_change"] = (
                _table_total(changes_run["upgrade"]["growth"], "endpoint_software_changes") / changes
            )
        snapshots_run = most("endpoint_inventory_snapshots", "first")
        snapshots = _table_rows(snapshots_run["first"]["growth"], "endpoint_inventory_snapshots")
        if snapshots:
            out["pg_bytes_per_endpoint_snapshot"] = (
                _table_total(snapshots_run["first"]["growth"], "endpoint_inventory_snapshots") / snapshots
            )

    for table, stats in (results.get("postgres_live") or {}).items():
        field_name = _LIVE_COEFFICIENTS.get(table)
        if field_name and stats.get("bytes_per_row") and stats.get("rows_estimate", 0) >= LIVE_MIN_ROWS:
            # Real rows beat synthetic ones wherever there are enough of them.
            out[field_name] = stats["bytes_per_row"]

    fit = (results.get("runs_dir") or {}).get("fit") or {}
    if fit.get("bytes_per_host") is not None:
        # Real runs replace the report-stage floor.
        out["run_dir_bytes_per_host"] = fit["bytes_per_host"]
        out["run_dir_bytes_is_floor"] = False
    if fit.get("archive_bytes_per_host") is not None:
        out["archive_bytes_per_host"] = fit["archive_bytes_per_host"]
    for name in (
        "sensor_cpu_seconds_per_host",
        "sensor_cpu_seconds_per_run",
        "sensor_busy_cores",
        "sensor_peak_cores",
        "sensor_peak_rss_bytes",
        "sensor_peak_rss_run_hosts",
    ):
        if fit.get(name) is not None:
            out[name] = fit[name]
    if fit.get("archive_bytes_per_run") is not None:
        out["archive_bytes_per_run"] = fit["archive_bytes_per_run"]
    if fit.get("bytes_per_run") is not None:
        out["run_dir_bytes_per_run"] = max(fit["bytes_per_run"], 0)

    env = next((value for key, value in sorted(results.items()) if key.startswith("environment")), {})
    out["source"] = (
        f"scale_measure {env.get('measured_at', '?')}, {env.get('cpu_count', '?')} CPU, "
        f"{(env.get('mem_total_bytes') or 0) / 1024**3:.0f} GiB, commit {env.get('git_commit') or '?'}"
    )
    return {key: _round(value) if isinstance(value, float) else value for key, value in out.items()}


def _tiers(raw: str) -> list[int]:
    try:
        tiers = sorted({int(part) for part in raw.split(",") if part.strip()})
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"tiers must be integers: {raw!r}") from exc
    if not tiers or tiers[0] <= 0:
        raise argparse.ArgumentTypeError("tiers must be positive integers")
    return tiers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tests.fixtures.scale_measure",
        description="Measure the sizing-model coefficients (#337).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def common(p: argparse.ArgumentParser, *, work_dir: bool = True, writes: bool | None = None) -> None:
        p.add_argument("--postgres-url", default=os.environ.get("OCTO_POSTGRES_URL", ""))
        p.add_argument("--clickhouse-url", default=os.environ.get("OCTO_CLICKHOUSE_URL", ""))
        p.add_argument("--nats-url", default=os.environ.get("OCTO_NATS_URL", ""))
        p.add_argument("--seed", type=int, default=1337)
        if work_dir:
            p.add_argument("--work-dir", type=Path, required=True, help="scratch space for run directories")
        if work_dir if writes is None else writes:
            p.add_argument(
                "--allow-shared-stores",
                action="store_true",
                help="measure even though other tenants have data in these stores (never production)",
            )
            p.add_argument(
                "--i-own-database",
                default="",
                metavar="NAME",
                help="the name of the dedicated database the URL points at; required to write to it",
            )
        p.add_argument("--out", type=Path, default=None, help="also write the JSON here")

    pg = sub.add_parser("postgres", help="project synthetic runs; bytes, CPU, RSS, statements")
    common(pg)
    pg.add_argument("--tiers", type=_tiers, default=[1000, 10000, 50000])
    pg.add_argument("--rescans", type=int, default=2)

    chp = sub.add_parser("clickhouse", help="ingest each tier's run into ClickHouse; bytes per row")
    common(chp)
    chp.add_argument("--tiers", type=_tiers, default=[1000, 10000, 50000])

    api = sub.add_parser("api", help="run python -m api on the seeded database; RSS and CPU")
    common(api)
    api.add_argument("--tenant", required=True, help="tenant the probe reads, e.g. sizing-50000")
    api.add_argument("--port", type=int, required=True, help="loopback port for the API under test")
    api.add_argument("--requests", type=int, default=40)
    api.add_argument("--idle-seconds", type=float, default=60.0)

    ep = sub.add_parser("endpoints", help="ingest Lariska snapshots; bytes per software row")
    common(ep)
    ep.add_argument("--devices", type=int, default=20)
    ep.add_argument("--packages", type=int, default=1500)
    ep.add_argument("--changed", type=float, default=0.05)
    # Many devices with few packages is how the per-snapshot row gets measured
    # above page granularity; a second run needs its own tenant.
    ep.add_argument("--tenant", default=f"{TENANT_PREFIX}-endpoints")

    purge = sub.add_parser("purge", help="remove every row the harness wrote (sizing-* tenants)")
    common(purge, work_dir=False, writes=True)
    purge.add_argument("--demo-accounts", action="store_true", help="also drop the seed:dev users `api` created")

    logs = sub.add_parser(
        "ch-system-logs",
        help="growth of ClickHouse's own system.*_log tables (runs SYSTEM FLUSH LOGS; writes nothing else)",
    )
    common(logs, work_dir=False)
    logs.add_argument("--since", type=Path, default=None, help="an earlier ch-system-logs result from the same server")

    live = sub.add_parser("postgres-live", help="bytes per row from a database with real history (read-only)")
    live.add_argument("--postgres-url", default=os.environ.get("OCTO_POSTGRES_URL", ""))
    live.add_argument("--out", type=Path, default=None)

    runs = sub.add_parser("runs-dir", help="bytes per run/host from real run directories (read-only)")
    runs.add_argument("root", type=Path, help="$OCTO_OUTPUT_DIR/runs")
    runs.add_argument("--archive", action="store_true", help="also gzip each run as the sensor does")
    runs.add_argument("--out", type=Path, default=None)

    derive = sub.add_parser("derive", help="merge result files and derive the model's coefficients")
    derive.add_argument("results", type=Path, nargs="+")
    derive.add_argument("--out", type=Path, default=None)

    for name in ("_build-run", "_project-run", "_ingest-run", "_endpoints"):
        child = sub.add_parser(name, help=argparse.SUPPRESS)
        # Set by _run_child through the environment (see _URL_ENV).
        child.add_argument("--postgres-url", default=os.environ.get("OCTO_POSTGRES_URL", ""))
        child.add_argument("--clickhouse-url", default=os.environ.get("OCTO_CLICKHOUSE_URL", ""))
        child.add_argument("--nats-url", default=os.environ.get("OCTO_NATS_URL", ""))
        child.add_argument("--work-dir", required=True)
        child.add_argument("--tenant", required=True)
        child.add_argument("--seed", type=int, default=1337)
        child.add_argument("--assets", type=int, default=0)
        child.add_argument("--run-id", default="")
        child.add_argument("--source-run-id", default="")
        child.add_argument("--devices", type=int, default=0)
        child.add_argument("--packages", type=int, default=0)
        child.add_argument("--changed", type=float, default=0.0)
    return parser


# --------------------------------------------------------------------------
# Whose stores these are
# --------------------------------------------------------------------------


class StoreNotReady(RuntimeError):
    """The store cannot be checked yet: not migrated, or not reachable."""


def _harness_tenant(tenant_id: str) -> bool:
    """Tenants a measurement may share a store with: its own ``sizing-*``, and
    ``scale_seed``'s fixture tenant (``scale_profile`` runs on the same stores)."""
    from tests.fixtures.scale_seed import DEFAULT_TENANT

    return tenant_id.startswith(f"{TENANT_PREFIX}-") or tenant_id == DEFAULT_TENANT


#: Where an installation's own use shows before it has scanned anything:
#: sensors registered, schedules set, tokens and integrations configured,
#: memberships granted, as well as assets, findings and endpoints. A row here
#: under any tenant but the harness's is somebody's. The first version looked
#: at assets, findings and endpoints only, and passed a production database
#: that had tenants and accounts but no scan yet (review of #337).
_OWNED_BY_TENANT: tuple[str, ...] = (
    "assets",
    "vulnerabilities",
    "endpoint_devices",
    "jobs",
    "agents",
    "scan_schedules",
    "service_tokens",
    "webhook_subscriptions",
    "notification_channels",
    "user_tenants",
)

#: ``created_by`` of the demo accounts ``python -m api`` seeds in dev mode —
#: which the ``api`` step does to a dedicated database itself.
DEV_SEED = "seed:dev"


def current_database(postgres_url: str) -> str:
    from sqlalchemy import text

    from api.db.engine import get_engine

    with get_engine(postgres_url).connect() as conn:
        return str(conn.execute(text("SELECT current_database()")).scalar_one())


def foreign_tenants(postgres_url: str = "", clickhouse_url: str = "") -> list[str]:
    """Everything in the stores that is not the harness's own.

    The measuring commands write rows, VACUUM tables, purge ClickHouse rows of
    their tenants and — for ``api`` — start an API in dev mode, which seeds the
    demo accounts and runs the in-process workers against whatever the
    database holds. None of that belongs in a database somebody uses, so any
    of these counts:

    * a tenant other than the harness's — or ``default`` once it holds
      anything, since ``python -m api`` creates it, empty, on first start;
    * a row under such a tenant in :data:`_OWNED_BY_TENANT`;
    * a console account the dev-mode seed did not create;
    * ClickHouse rows no harness run wrote.

    Raises :class:`StoreNotReady` for a database that is not migrated, rather
    than failing on the first missing table.
    """
    from api.services.tenants import DEFAULT_TENANT_ID

    found: list[str] = []
    if postgres_url:
        from sqlalchemy import inspect, text

        from api.db.engine import get_engine

        engine = get_engine(postgres_url)
        try:
            present = set(inspect(engine).get_table_names())
        except Exception as exc:  # noqa: BLE001 - unreachable, refused, wrong credentials
            raise StoreNotReady(f"cannot read the database's tables: {type(exc).__name__}: {exc}") from exc
        missing = sorted({"tenants", "users", *_OWNED_BY_TENANT} - present)
        if missing:
            raise StoreNotReady(
                f"the database is not migrated (no {', '.join(missing[:3])}"
                f"{', …' if len(missing) > 3 else ''}); run `alembic -c api/db/alembic.ini upgrade head` "
                "against it first"
            )
        with engine.connect() as conn:
            for (tenant,) in conn.execute(text("SELECT tenant_id FROM tenants")):
                if not _harness_tenant(str(tenant)) and tenant != DEFAULT_TENANT_ID:
                    found.append(str(tenant))
            for table in _OWNED_BY_TENANT:
                # Identifiers come from the constant tuple above, never from input.
                for (tenant,) in conn.execute(text(f'SELECT DISTINCT tenant_id FROM "{table}"')):
                    if tenant is not None and not _harness_tenant(str(tenant)):
                        found.append(str(tenant) if tenant != DEFAULT_TENANT_ID else f"{tenant} ({table})")
            accounts = conn.execute(
                text("SELECT username FROM users WHERE created_by IS DISTINCT FROM :seed ORDER BY username"),
                {"seed": DEV_SEED},
            )
            found.extend(f"users:{username}" for (username,) in accounts)
    if clickhouse_url:
        from api.services import clickhouse_client as ch

        client = ch.get_client(clickhouse_url)
        # ClickHouse keeps a UUID derived from the tenant id, not the id, so the
        # harness's rows are recognised by their run id instead: its runs are
        # ``sizing-*`` and scale_seed stamps ``scale-seed``. A tenant with a
        # finding and no such port row is somebody else's.
        ours = (
            f"SELECT tenant_id FROM {ch.PORTS_TABLE} "
            "WHERE startsWith(run_id, 'sizing-') OR run_id = 'scale-seed'"
        )
        query = (
            f"SELECT DISTINCT toString(tenant_id) FROM {ch.PORTS_TABLE} "
            "WHERE NOT (startsWith(run_id, 'sizing-') OR run_id = 'scale-seed') "
            f"UNION DISTINCT SELECT DISTINCT toString(tenant_id) FROM {ch.VULN_TABLE} "
            f"WHERE tenant_id NOT IN ({ours})"
        )
        found.extend(f"clickhouse:{tenant}" for (tenant,) in client.query(query).result_rows)
    return sorted(set(found))


#: Tables whose rows never go, by design: the audit trail refuses DELETE
#: (migration 0037, #327). Its rows age out through the audit retention prune.
_IMMUTABLE_TABLES = frozenset({"audit_events"})


def purge_harness_rows(
    postgres_url: str, *, demo_accounts: bool = False, clickhouse_url: str = ""
) -> dict[str, Any]:
    """Remove every row the harness wrote: the ``sizing-*`` tenants and all they own.

    ``scale_seed --purge`` removes a tenant's assets and identifiers; a sizing
    run also leaves findings, events, services, OS guesses, endpoint
    inventory, risk snapshots, the tenant rows and ClickHouse rows (review of
    #337). Every table with a ``tenant_id`` is cleared of ``sizing-*`` rows —
    in passes, so foreign keys without ON DELETE CASCADE are satisfied in
    whatever order they need — then the tenants. ``demo_accounts`` also drops
    the ``seed:dev`` users an ``api`` step created, whose passwords are
    published in this repository. The audit trail is immutable and is only
    counted.
    """
    from sqlalchemy import inspect, text
    from sqlalchemy.exc import DBAPIError

    from api.db.engine import get_engine

    engine = get_engine(postgres_url)
    pattern = f"{TENANT_PREFIX}-%"
    inspector = inspect(engine)
    names = set(inspector.get_table_names())
    tables = sorted(
        table
        for table in names
        if table not in _IMMUTABLE_TABLES
        and table != "tenants"
        and "tenant_id" in {column["name"] for column in inspector.get_columns(table)}
    )
    with engine.connect() as conn:
        tenants = [
            str(tenant)
            for (tenant,) in conn.execute(
                text("SELECT tenant_id FROM tenants WHERE tenant_id LIKE :p"), {"p": pattern}
            )
        ]
    deleted: dict[str, int] = {}
    pending = list(tables)
    while pending:
        blocked: list[str] = []
        for table in pending:
            try:
                with engine.begin() as conn:
                    # Identifiers come from the database's own catalogue.
                    count = conn.execute(
                        text(f'DELETE FROM "{table}" WHERE tenant_id LIKE :p'), {"p": pattern}
                    ).rowcount
            except DBAPIError:
                blocked.append(table)
                continue
            if count:
                deleted[table] = deleted.get(table, 0) + count
        if len(blocked) == len(pending):
            break
        pending = blocked
    with engine.begin() as conn:
        if not pending:
            deleted["tenants"] = conn.execute(
                text("DELETE FROM tenants WHERE tenant_id LIKE :p"), {"p": pattern}
            ).rowcount
        demo = (
            conn.execute(text("DELETE FROM users WHERE created_by = :seed"), {"seed": DEV_SEED}).rowcount
            if demo_accounts
            else 0
        )
        kept = {
            table: conn.execute(
                text(f'SELECT count(*) FROM "{table}" WHERE tenant_id LIKE :p'), {"p": pattern}
            ).scalar_one()
            for table in sorted(_IMMUTABLE_TABLES & names)
        }
    if clickhouse_url:
        for tenant in tenants:
            purge_clickhouse(clickhouse_url, tenant, wait=True)
    return {
        "tenants": len(tenants),
        "deleted": deleted,
        "not_deleted": pending,
        "demo_accounts": demo,
        "kept_immutable": {table: count for table, count in kept.items() if count},
        "clickhouse_purged": bool(clickhouse_url),
    }


def _emit(payload: dict[str, Any], out: Path | None) -> None:
    text = json.dumps(payload, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text + "\n", encoding="utf-8")
    print(text)


_CHILDREN = {
    "_build-run": child_build_run,
    "_project-run": child_project_run,
    "_ingest-run": child_ingest_run,
    "_endpoints": child_endpoints,
}


def _require(value: str, name: str) -> bool:
    if value:
        return True
    print(f"error: no {name} URL (--{name.lower()}-url or $OCTO_{name.upper()}_URL)", file=sys.stderr)
    return False


def _owns_database(args: argparse.Namespace) -> bool:
    """The writing commands name the database they may write to, and it must be this one.

    A URL pasted from the wrong environment points at a database whose name
    the operator did not type; comparing with ``current_database()`` catches
    that before anything is written (review of #337).
    """
    if not args.i_own_database:
        print(
            "error: pass --i-own-database with the name of the database the harness may write to "
            "(a dedicated one: it adds tenants, VACUUMs tables and, for `api`, seeds demo accounts)",
            file=sys.stderr,
        )
        return False
    try:
        actual = current_database(args.postgres_url)
    except Exception as exc:  # noqa: BLE001 - unreachable or refused: say which, not a traceback
        print(f"error: cannot reach the database: {type(exc).__name__}", file=sys.stderr)
        return False
    if actual != args.i_own_database:
        print(
            f"error: --i-own-database names {args.i_own_database!r}, but the URL points at {actual!r}",
            file=sys.stderr,
        )
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in _CHILDREN:
        # One line of JSON on stdout: the parent reads the last line.
        print(json.dumps(_CHILDREN[args.command](args)))
        return 0
    if args.command == "runs-dir":
        _emit(
            {"environment_runs_dir": environment(), "runs_dir": measure_runs_dir(args.root, archive=args.archive)},
            args.out,
        )
        return 0
    if args.command == "postgres-live":
        if not _require(args.postgres_url, "Postgres"):
            return 2
        _emit(
            {
                "environment_postgres_live": environment(postgres_url=args.postgres_url),
                "postgres_live": pg_live_row_costs(args.postgres_url),
            },
            args.out,
        )
        return 0
    if args.command == "derive":
        _emit(merge_results([json.loads(path.read_text(encoding="utf-8")) for path in args.results]), args.out)
        return 0

    if args.command == "ch-system-logs":
        if not _require(args.clickhouse_url, "ClickHouse"):
            return 2
        since = None
        if args.since is not None:
            since = json.loads(args.since.read_text(encoding="utf-8")).get("clickhouse_system_logs")
        _emit(
            {
                "environment_ch_system_logs": environment(clickhouse_url=args.clickhouse_url),
                "clickhouse_system_logs": ch_system_log_growth(args.clickhouse_url, since=since),
                "clickhouse_server_memory": ch_server_memory(args.clickhouse_url),
            },
            args.out,
        )
        return 0

    # ClickHouse alone can run without Postgres: the transform then skips the
    # per-host criticality/exposure lookups the ingest worker makes (#337).
    if args.command != "clickhouse" and not _require(args.postgres_url, "Postgres"):
        return 2
    if args.command == "clickhouse" and not _require(args.clickhouse_url, "ClickHouse"):
        return 2
    if args.postgres_url and not _owns_database(args):
        return 2
    if args.command == "purge":
        report = purge_harness_rows(
            args.postgres_url, demo_accounts=args.demo_accounts, clickhouse_url=args.clickhouse_url
        )
        _emit({"purge": report}, args.out)
        return 0 if not report["not_deleted"] else 1
    if not args.allow_shared_stores:
        try:
            foreign = foreign_tenants(
                args.postgres_url,
                args.clickhouse_url if args.command == "clickhouse" else "",
            )
        except StoreNotReady as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if foreign:
            print(
                "error: these stores hold data of other tenants ("
                + ", ".join(foreign[:5])
                + (", …" if len(foreign) > 5 else "")
                + "); point the harness at a dedicated database and ClickHouse, "
                "or pass --allow-shared-stores if this is a disposable one",
                file=sys.stderr,
            )
            return 2
    args.work_dir.mkdir(parents=True, exist_ok=True)
    env = environment(postgres_url=args.postgres_url, clickhouse_url=args.clickhouse_url)
    if args.command == "postgres":
        result: dict[str, Any] = {
            "postgres": [
                measure_postgres_tier(
                    args.postgres_url, args.work_dir, assets=assets, seed=args.seed, rescans=args.rescans
                )
                for assets in args.tiers
            ]
        }
    elif args.command == "clickhouse":
        result = {
            "clickhouse": [
                measure_clickhouse_tier(
                    args.clickhouse_url,
                    args.work_dir,
                    assets=assets,
                    seed=args.seed,
                    postgres_url=args.postgres_url,
                    nats_url=args.nats_url,
                )
                for assets in args.tiers
            ]
        }
    elif args.command == "api":
        result = {
            "api": measure_api(
                args.postgres_url,
                args.work_dir,
                tenant=args.tenant,
                port=args.port,
                requests=args.requests,
                idle_seconds=args.idle_seconds,
            )
        }
    elif args.command == "endpoints":
        result = {
            "endpoints": [
                _run_child(
                    "_endpoints",
                    postgres_url=args.postgres_url,
                    work_dir=args.work_dir,
                    tenant=args.tenant,
                    devices=args.devices,
                    packages=args.packages,
                    changed=args.changed,
                )
            ]
        }
    else:  # pragma: no cover - argparse restricts the choices
        return 2
    # Environment keyed by command, so result files from several commands
    # merge in ``derive`` without one overwriting where another was measured.
    _emit({f"environment_{args.command}": env, **result}, args.out)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
