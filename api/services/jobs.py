"""Scan jobs — the control plane's unit of work (Postgres-backed since P1.2).

Jobs used to live in a module-level ``_JOBS`` dict guarded by a
``threading.Lock`` and dumped to ``state/api_jobs.json`` after every mutation.
That has three failure modes this module no longer has: a second API replica
kept its own queue (so an agent could claim a job twice, once per replica),
the lock only serialised claims *within* one process, and anything not yet
flushed to the file died with the process.

The table is the queue now. ``claim_job`` takes a row lock
(``SELECT … FOR UPDATE SKIP LOCKED``) so concurrent claims across replicas
hand out distinct jobs, and every status change is a committed UPDATE rather
than a whole-file rewrite.

Since P1.3 every status write goes through ``api/services/job_states.py``:
statuses are no longer assigned, they are *transitioned*, and an illegal move
(a late upload for a job that already failed, a second terminal write) raises
instead of silently overwriting. Leases and idempotency keys are the next
slices (ROADMAP P1.4-P1.5).
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agents as agents_service
from api.services import assets as assets_service
from api.services import config_override as config_override_service
from api.services import job_states
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import pagination
from api.services import results_ingest
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services.targets import parse_target_payload
from api.settings import Settings

_log = logging.getLogger(__name__)


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def _parse_iso(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).replace(tzinfo=None) if parsed.tzinfo else parsed


def _to_info(row: models.Job) -> JobInfo:
    return JobInfo(
        job_id=row.job_id,
        status=row.status,  # type: ignore[arg-type]
        run_id=row.run_id,
        mode=row.mode,
        command=list(row.command or []),
        started_at=_iso(row.started_at),
        finished_at=_iso(row.finished_at),
        exit_code=row.exit_code,
        error=row.error,
        requested_by=row.requested_by or "",
        target_counts=dict(row.target_counts) if row.target_counts else None,
        execution=row.execution,  # type: ignore[arg-type]
        assigned_agent_id=row.assigned_agent_id,
        tenant_id=row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        asset_upsert_error=row.asset_upsert_error,
    )


def load_jobs(settings: Settings) -> None:
    """Import the pre-P1 JSON queue once, then reconcile this replica's orphans.

    Local-mode jobs run in an in-process thread (see ``_run_job``): that
    executor dies with the process, so a local job still ``queued``/``running``
    at startup was orphaned by a crash or restart and will never be updated
    again — fail it here rather than leaving it stuck forever.

    Unlike the pre-P1 version, the queue is now shared, so "still running" no
    longer implies "mine": only rows carrying this replica's ``owner_id`` are
    reconciled. A local job orphaned by a replica that never returns under the
    same id stays running until the P1.4 lease reaper lands. Agent-mode jobs
    are untouched in either case — their executor is a remote process
    independent of this one.
    """
    path = settings.state_dir / "api_jobs.json"
    if path.is_file():
        _import_legacy_jobs(settings, path)

    now = _now()
    with get_session(settings.postgres_url) as session:
        orphans = session.execute(
            select(models.Job).where(
                models.Job.execution == "local",
                # `claimed` is an agent-only state, so it cannot appear here.
                models.Job.status.in_((job_states.QUEUED, job_states.RUNNING)),
                or_(
                    models.Job.owner_id == settings.instance_id,
                    models.Job.owner_id.is_(None),
                ),
            )
        ).scalars().all()
        for row in orphans:
            job_states.check_transition(row.job_id, row.status, job_states.FAILED)
            row.status = job_states.FAILED
            row.finished_at = now
            row.error = "Interrupted by API process restart before completion"
    if orphans:
        _log.info("Reconciled %d orphaned local job(s) after restart", len(orphans))
    _refresh_job_gauges(settings)


def _import_legacy_jobs(settings: Settings, path: Path) -> None:
    """Copy ``state/api_jobs.json`` into the table, once.

    The file is renamed to ``*.imported`` afterwards so a restart cannot
    resurrect jobs that were since deleted, and so an operator can still see
    what was carried over.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _log.warning("Ignoring unreadable legacy job queue at %s", path)
        return
    if not isinstance(raw, list):
        return

    known_tenants = {tenant["tenant_id"] for tenant in tenants_service.list_tenants()}
    imported = 0
    with get_session(settings.postgres_url) as session:
        for item in raw:
            if not (isinstance(item, dict) and item.get("job_id")):
                continue
            job_id = str(item["job_id"])
            if session.get(models.Job, job_id) is not None:
                continue
            tenant_id = str(item.get("tenant_id") or tenants_service.DEFAULT_TENANT_ID)
            if tenant_id not in known_tenants:
                # The column is a FK; a job whose tenant was deleted would
                # abort the whole import, so re-home it rather than drop it.
                _log.warning(
                    "Legacy job %s references unknown tenant %s; importing under %s",
                    job_id,
                    tenant_id,
                    tenants_service.DEFAULT_TENANT_ID,
                )
                tenant_id = tenants_service.DEFAULT_TENANT_ID
            options = dict(item.get("scan_options") or {})
            row = models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                status=str(item.get("status") or "queued"),
                execution=str(item.get("execution") or "local"),
                mode=str(item.get("mode") or options.get("mode") or "balanced"),
                run_id=item.get("run_id"),
                command=list(item.get("command") or []),
                scan_options=options,
                target_counts=item.get("target_counts"),
                requested_by=str(item.get("requested_by") or ""),
                assigned_agent_id=item.get("assigned_agent_id"),
                # Pre-P1 jobs have no owner; load_jobs treats NULL as
                # "this replica" so they still get reconciled once.
                owner_id=None,
                queued_at=_parse_iso(item.get("queued_at"))
                or _parse_iso(item.get("started_at"))
                or _now(),
                started_at=_parse_iso(item.get("started_at")),
                finished_at=_parse_iso(item.get("finished_at")),
                exit_code=item.get("exit_code"),
                error=item.get("error"),
                asset_upsert_error=item.get("asset_upsert_error"),
            )
            if insert_if_absent(session, row, job_id):
                imported += 1
    try:
        path.replace(path.with_suffix(path.suffix + ".imported"))
    except OSError:
        _log.warning("Could not rename %s after import; it will be re-imported", path)
    if imported:
        _log.info("Imported %d job(s) from the pre-P1 queue at %s", imported, path)


JOB_SORT_FIELDS = ("started_at", "finished_at", "status", "job_id", "mode", "tenant_id")
JOB_QUERY_FIELDS = ("job_id", "run_id", "mode", "status", "requested_by", "tenant_id", "assigned_agent_id")

JOB_SORT_COLUMNS = {
    "started_at": models.Job.started_at,
    "finished_at": models.Job.finished_at,
    "status": models.Job.status,
    "job_id": models.Job.job_id,
    "mode": models.Job.mode,
    "tenant_id": models.Job.tenant_id,
}


def list_jobs(
    settings: Settings,
    *,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
    sort: str | None = None,
    order: str | None = None,
    tenant_id: str | None = None,
) -> tuple[list[JobInfo], int]:
    """Return ``(page, total_after_filtering)`` — see api/services/pagination.py.

    Filtered, counted, and sliced in SQL. ``NULLS LAST`` keeps the documented
    ordering rule that a job which never started does not outrank one that
    did, in both directions.
    """
    column = JOB_SORT_COLUMNS.get(sort or "", models.Job.started_at)
    ascending = (order or "").lower() == "asc"
    direction = column.asc().nullslast() if ascending else column.desc().nullslast()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.Job.tenant_id == tenant_id)
        if q and q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(
                or_(
                    func.lower(models.Job.job_id).like(needle),
                    func.lower(func.coalesce(models.Job.run_id, "")).like(needle),
                    func.lower(models.Job.mode).like(needle),
                    func.lower(models.Job.status).like(needle),
                    func.lower(models.Job.requested_by).like(needle),
                    func.lower(models.Job.tenant_id).like(needle),
                    func.lower(func.coalesce(models.Job.assigned_agent_id, "")).like(needle),
                )
            )
        total = session.execute(
            select(func.count()).select_from(models.Job).where(*filters)
        ).scalar_one()
        rows = session.execute(
            select(models.Job)
            .where(*filters)
            .order_by(direction, models.Job.job_id)
            .offset(offset)
            .limit(limit)
        ).scalars().all()
        return [_to_info(row) for row in rows], total


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return _to_info(row) if row else None


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.Job).delete()


def _update_job(settings: Settings, job_id: str, **fields: Any) -> None:
    """Apply ``fields`` to a job row, validating any status change.

    Validation lives here rather than at each call site so a future writer
    cannot reintroduce a bare assignment: every path that moves a job — local
    executor, agent claim, result upload, restart reconciliation, cancel — goes
    through this function. Use ``force_status`` for the rare repair/test case
    that must ignore the lifecycle.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        if "status" in fields:
            job_states.check_transition(job_id, row.status, str(fields["status"]))
        for key, value in fields.items():
            setattr(row, key, value)
        session.flush()
        snapshot = (
            (row.status, row.execution, row.started_at, row.finished_at)
            if "status" in fields
            else None
        )
    if snapshot is not None:
        _record_job_metrics(settings, *snapshot)


def force_status(settings: Settings, job_id: str, status: str, **fields: Any) -> None:
    """Set a status without lifecycle validation.

    The escape hatch for tests that need to stage a state directly, and for an
    operator repair where the row is already wrong. Nothing in the request path
    may call this — use the transitions in ``job_states``.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        row.status = status
        for key, value in fields.items():
            setattr(row, key, value)
    _refresh_job_gauges(settings)


def _record_job_metrics(
    settings: Settings,
    status: str,
    execution: str,
    started_at: datetime | None,
    finished_at: datetime | None,
) -> None:
    if status in {"succeeded", "failed"} and started_at and finished_at:
        duration = (finished_at - started_at).total_seconds()
        if duration >= 0:
            metrics_service.JOB_DURATION_SECONDS.labels(
                status=status, execution=execution or "local"
            ).observe(duration)
    _refresh_job_gauges(settings)


def _refresh_job_gauges(settings: Settings) -> None:
    """Publish queued/running counts.

    These are now counted in the shared table rather than per-process, so two
    replicas no longer report two different queue depths for the same queue —
    one of the known gaps called out in docs/slo.md.

    ``claimed`` (P1.3) counts as running: the job is out with a worker and no
    longer waiting, so folding it into the queue depth would read as a backlog
    that nothing is working on.
    """
    with get_session(settings.postgres_url) as session:
        counts = dict(
            session.execute(
                select(models.Job.status, func.count())
                .where(models.Job.status.in_(tuple(job_states.ACTIVE)))
                .group_by(models.Job.status)
            ).all()
        )
    metrics_service.JOBS_QUEUED.set(counts.get(job_states.QUEUED, 0))
    metrics_service.JOBS_RUNNING.set(sum(counts.get(s, 0) for s in job_states.IN_FLIGHT))


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def _prepare_target_inputs(
    settings: Settings,
    job_id: str,
    request: StartScanRequest,
) -> tuple[Path | None, dict[str, int] | None, list[str]]:
    """Write per-job input files when overrides are provided.

    Returns (inputs_dir, target_counts, extra_cli_args).
    """
    parsed = parse_target_payload(
        ranges_text=request.ranges,
        domains_text=request.domains,
        ports_text=request.ports,
        ports_udp_text=request.ports_udp,
    )
    if parsed is None:
        return None, None, []

    inputs_dir = settings.state_dir / "job_inputs" / job_id
    inputs_dir.mkdir(parents=True, exist_ok=True)
    extra: list[str] = []
    counts: dict[str, int] = {}

    if parsed.ranges is not None and parsed.domains is not None:
        ranges_path = inputs_dir / "ranges.txt"
        domains_path = inputs_dir / "domains.txt"
        _write_lines(ranges_path, parsed.ranges)
        _write_lines(domains_path, parsed.domains)
        extra.extend(["--ranges", str(ranges_path), "--domains", str(domains_path)])
        counts["ranges"] = len(parsed.ranges)
        counts["domains"] = len(parsed.domains)

    if parsed.ports is not None:
        ports_path = inputs_dir / "ports.txt"
        _write_lines(ports_path, parsed.ports)
        extra.extend(["--ports-file", str(ports_path)])
        counts["ports"] = len(parsed.ports)

    if parsed.ports_udp is not None:
        ports_udp_path = inputs_dir / "ports_udp.txt"
        _write_lines(ports_udp_path, parsed.ports_udp)
        extra.extend(["--ports-udp-file", str(ports_udp_path)])
        counts["ports_udp"] = len(parsed.ports_udp)

    return inputs_dir, counts or None, extra


def _build_command(
    settings: Settings,
    request: StartScanRequest,
    *,
    run_id: str | None,
    target_args: list[str],
    config_path: str,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "scanner.main",
        "--config",
        config_path,
        "--mode",
        request.mode,
    ]
    if request.delta:
        command.append("--delta")
    if request.skip_nse:
        command.append("--skip-nse")
    if request.notify:
        command.append("--notify")
    if request.export_defectdojo:
        command.append("--export-defectdojo")
    if run_id:
        command.extend(["--run-id", run_id])
    command.extend(target_args)
    return command


def _upsert_assets_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort asset-registry upsert (Phase 7) — never fails the scan/upload.

    Covers both execution paths: local-mode scans land here from _run_job,
    agent-uploaded results land here from complete_job.

    A failure here used to leave no trace outside the pod log: the job still
    read as "succeeded", the scan artifacts were all present, and the asset list
    was simply empty — so the only way to learn why was to catch the log before
    the pod was replaced. Record the reason on the job instead.
    """
    if not run_id:
        return
    try:
        assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        logging.exception("Asset upsert failed for run %s (tenant=%s)", run_id, tenant_id)
        if job_id:
            _update_job(settings, job_id, asset_upsert_error=f"{type(exc).__name__}: {exc}"[:2000])


def _run_job(settings: Settings, job_id: str, command: list[str]) -> None:
    try:
        # A local job goes queued → running with no claim step: this process is
        # the worker. If it was cancelled while the thread was still starting,
        # the transition is rejected and the scan never launches.
        _update_job(settings, job_id, status=job_states.RUNNING, started_at=_now())
    except job_states.InvalidJobTransition as exc:
        _log.info("Not starting job %s: %s", job_id, exc)
        return
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        # Best-effort: read latest_run.json after completion.
        run_id = None
        pointer = settings.state_dir / "latest_run.json"
        if pointer.exists():
            try:
                run_id = json.loads(pointer.read_text(encoding="utf-8")).get("run_id")
            except json.JSONDecodeError:
                run_id = None
        status = job_states.SUCCEEDED if completed.returncode == 0 else job_states.FAILED
        error = None
        if completed.returncode != 0:
            error = (completed.stderr or completed.stdout or f"exit {completed.returncode}")[:2000]
        _update_job(
            settings,
            job_id,
            status=status,
            finished_at=_now(),
            exit_code=completed.returncode,
            run_id=str(run_id) if run_id else None,
            error=error,
        )
        if status == job_states.SUCCEEDED:
            job = get_job(settings, job_id)
            tenant_id = job.tenant_id if job else tenants_service.DEFAULT_TENANT_ID
            # Tag the run before the asset upsert: an untagged run reads back as
            # the default tenant, which would leak it to every tenant's run list.
            if run_id:
                runs_service.write_run_tenant(settings, str(run_id), tenant_id, job_id=job_id)
            _upsert_assets_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
    except Exception as exc:  # noqa: BLE001
        logging.exception("Scan job %s failed", job_id)
        try:
            _update_job(
                settings,
                job_id,
                status=job_states.FAILED,
                finished_at=_now(),
                error=str(exc)[:2000],
            )
        except job_states.InvalidJobTransition:
            # The scan itself finished and the job is already terminal — this
            # is post-completion bookkeeping (run tagging) blowing up. Record it
            # without rewriting the outcome the scan actually had.
            _update_job(settings, job_id, error=str(exc)[:2000])


def start_scan(settings: Settings, request: StartScanRequest, *, username: str) -> JobInfo:
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")

    tenant_id = (request.tenant_id or tenants_service.DEFAULT_TENANT_ID).strip()
    tenant = tenants_service.get_tenant(tenant_id)
    if tenant is None:
        raise ValueError(f"Unknown tenant_id: {tenant_id}")
    if tenant.get("status") != "active":
        raise ValueError(f"Tenant is not active: {tenant_id}")

    job_id = uuid.uuid4().hex[:12]
    execution = "agent" if settings.job_execution_mode == "agent" else "local"
    run_id = request.run_id
    if execution == "agent" and not run_id:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    _, target_counts, target_args = _prepare_target_inputs(settings, job_id, request)
    # Local scans run in this container, so apply the installation config
    # overrides by merging them into a job-specific config file. Agents run
    # their own mounted config, so overrides don't reach them — they keep the
    # base config (documented limitation).
    if execution == "local":
        config_path = config_override_service.effective_config_path(settings, job_id)
    else:
        config_path = str(settings.config_path)
    command = _build_command(
        settings, request, run_id=run_id, target_args=target_args, config_path=config_path
    )

    row = models.Job(
        job_id=job_id,
        tenant_id=tenant_id,
        status=job_states.QUEUED,
        execution=execution,
        mode=request.mode,
        run_id=run_id,
        command=command,
        scan_options={
            "mode": request.mode,
            "delta": request.delta,
            "skip_nse": request.skip_nse,
            "notify": request.notify,
            "export_defectdojo": request.export_defectdojo,
        },
        target_counts=target_counts,
        requested_by=username,
        assigned_agent_id=None,
        # Only local jobs are bound to this process; an agent job is claimable
        # by any worker and must not be reconciled when this replica restarts.
        owner_id=settings.instance_id if execution == "local" else None,
        queued_at=_now(),
    )
    with get_session(settings.postgres_url) as session:
        session.add(row)
        session.flush()
        info = _to_info(row)
    _refresh_job_gauges(settings)

    if execution == "local":
        thread = threading.Thread(target=_run_job, args=(settings, job_id, command), daemon=True)
        thread.start()
    elif execution == "agent" and settings.nats_url:
        _publish_job_offer(settings, job_id)

    return info


def _publish_job_offer(settings: Settings, job_id: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        opts = dict(row.scan_options or {})
        payload = {
            "job_id": row.job_id,
            "run_id": row.run_id or "",
            "mode": row.mode or opts.get("mode") or "balanced",
            "delta": bool(opts.get("delta", False)),
            "skip_nse": bool(opts.get("skip_nse", False)),
            "notify": bool(opts.get("notify", False)),
            "export_defectdojo": bool(opts.get("export_defectdojo", False)),
            "inputs": _read_job_inputs(settings, row.job_id),
            "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        }
    bus = nats_bus.get_bus(settings.nats_url)
    if bus is None:
        _log.warning(
            "NATS configured but unavailable; job %s stays queued for HTTP claim",
            job_id,
        )
        return
    if bus.publish_job_offer(payload):
        _log.info("Published jobs.scan offer for %s", job_id)
    else:
        _log.warning(
            "Failed to publish jobs.scan for %s; HTTP claim still available",
            job_id,
        )


def _read_job_inputs(settings: Settings, job_id: str) -> dict[str, str]:
    inputs_dir = settings.state_dir / "job_inputs" / job_id
    if not inputs_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for name in ("ranges.txt", "domains.txt", "ports.txt", "ports_udp.txt"):
        path = inputs_dir / name
        if path.is_file():
            out[name] = path.read_text(encoding="utf-8")
    return out


def claim_job(
    settings: Settings,
    agent_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
) -> AgentClaimResponse | None:
    """Assign a queued agent job to ``agent_id``, or return None.

    When ``job_id`` is set (NATS pull path), assign that specific job if still queued.
    When ``tenant_id`` is set, only jobs for that tenant are eligible.

    The candidate row is locked with ``FOR UPDATE SKIP LOCKED`` (a no-op on the
    SQLite fallback, which has a single writer anyway): two agents claiming
    concurrently — against the same replica or different ones — each get a
    different job instead of both being handed the head of the queue.
    """
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise LookupError("Unknown agent_id; register first")
    effective_tenant = tenant_id or agent.tenant_id

    with get_session(settings.postgres_url) as session:
        query = (
            select(models.Job)
            .where(
                models.Job.execution == "agent",
                models.Job.status == "queued",
                models.Job.assigned_agent_id.is_(None),
                models.Job.tenant_id == effective_tenant,
            )
            .order_by(models.Job.queued_at, models.Job.job_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job_id:
            query = query.where(models.Job.job_id == job_id)
        row = session.execute(query).scalars().first()
        if row is None:
            return None

        # `claimed`, not `running` (P1.3): the agent owns the job but has not
        # reported working on it. Its first heartbeat naming this job promotes
        # it (see mark_running), which is also the signal the P1.4 reaper needs
        # to tell "taken by a worker that died" from "actually scanning".
        job_states.check_transition(row.job_id, row.status, job_states.CLAIMED)
        row.status = job_states.CLAIMED
        row.assigned_agent_id = agent_id
        row.started_at = _now()
        if not row.run_id:
            row.run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        session.flush()

        opts = dict(row.scan_options or {})
        claimed_id = row.job_id
        response = AgentClaimResponse(
            job_id=claimed_id,
            run_id=row.run_id,
            mode=row.mode or opts.get("mode") or "balanced",
            delta=bool(opts.get("delta", False)),
            skip_nse=bool(opts.get("skip_nse", False)),
            notify=bool(opts.get("notify", False)),
            export_defectdojo=bool(opts.get("export_defectdojo", False)),
            inputs=_read_job_inputs(settings, claimed_id),
            tenant_id=row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        )
    _refresh_job_gauges(settings)
    agents_service.touch_job(agent_id, claimed_id, status="busy")
    return response


def mark_running(settings: Settings, job_id: str, *, agent_id: str) -> None:
    """Promote a claimed job to running when its agent reports working on it.

    Called from the agent heartbeat, which names the job the worker is on. Any
    other state is left alone: repeated heartbeats during a scan would
    otherwise attempt running → running, and a heartbeat arriving after the
    results upload must not resurrect a finished job. A heartbeat from an agent
    that does not hold the job is ignored outright.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.status != job_states.CLAIMED:
            return
        if row.assigned_agent_id != agent_id:
            return
        row.status = job_states.RUNNING
        if row.started_at is None:
            row.started_at = _now()
    _refresh_job_gauges(settings)


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
) -> JobInfo:
    """Cancel a job that has not started executing yet.

    Legal from ``queued`` (nothing has picked it up) and ``claimed`` (an agent
    holds it but has not reported starting). A ``running`` job is refused: see
    ``job_states`` — there is no channel to stop an in-flight scan, and marking
    the row cancelled would claim a stop that never happened.

    The reason is stored in ``error`` rather than a new column: it is the field
    the UI and API already surface for "why did this job end this way".
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            raise LookupError("Job not found")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        job_states.check_transition(job_id, row.status, job_states.CANCELLED)
        row.status = job_states.CANCELLED
        row.finished_at = _now()
        row.error = f"Cancelled by {username}"[:2000]
    _refresh_job_gauges(settings)
    result = get_job(settings, job_id)
    assert result is not None
    return result


def complete_job(
    settings: Settings,
    job_id: str,
    *,
    agent_id: str,
    exit_code: int,
    error: str | None = None,
    run_id: str | None = None,
    archive_bytes: bytes | None = None,
    tenant_id: str | None = None,
) -> JobInfo:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            raise LookupError("Job not found")
        if row.execution != "agent":
            raise ValueError("Job is not an agent job")
        if row.assigned_agent_id != agent_id:
            raise PermissionError("Job is assigned to a different agent")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        status = job_states.SUCCEEDED if exit_code == 0 else job_states.FAILED
        # Checked before the archive is ingested, not after: a duplicate upload
        # for a job that already finished — or one an operator cancelled while
        # the agent was still working — must not overwrite the run directory
        # and re-publish to NATS before being rejected.
        job_states.check_transition(job_id, row.status, status)
        resolved_run_id = run_id or row.run_id

    if archive_bytes:
        if not resolved_run_id:
            raise ValueError("run_id required when uploading results")
        # Gateway: validate + publish to ingest.raw_results (idempotent Msg-Id).
        if settings.nats_url:
            try:
                results_ingest.publish_raw_results(
                    nats_url=settings.nats_url,
                    job_id=job_id,
                    run_id=str(resolved_run_id),
                    agent_id=agent_id,
                    exit_code=exit_code,
                    archive_bytes=archive_bytes,
                    error=error,
                    tenant_id=job_tenant,
                )
            except results_ingest.IngestError as exc:
                raise ValueError(str(exc)) from exc
        dest = settings.output_dir / "runs" / str(resolved_run_id)
        try:
            results_ingest.extract_run_archive(archive_bytes, dest)
            results_ingest.update_latest_run_pointer(settings.state_dir, str(resolved_run_id))
            runs_service.write_run_tenant(
                settings, str(resolved_run_id), job_tenant, job_id=job_id
            )
        except results_ingest.IngestError as exc:
            raise ValueError(str(exc)) from exc
        _upsert_assets_best_effort(
            settings, tenant_id=job_tenant, run_id=str(resolved_run_id), job_id=job_id
        )

    _update_job(
        settings,
        job_id,
        status=status,
        finished_at=_now(),
        exit_code=exit_code,
        run_id=str(resolved_run_id) if resolved_run_id else None,
        error=(error[:2000] if error else None),
    )
    agents_service.touch_job(agent_id, None, status="idle")
    result = get_job(settings, job_id)
    assert result is not None
    return result
