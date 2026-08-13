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
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agents as agents_service
from api.services import asset_events
from api.services import assets as assets_service
from api.services import config_override as config_override_service
from api.services import job_states
from api.services import metrics as metrics_service
from api.services import nats_bus
from api.services import pagination
from api.services import results_ingest
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services import wordlists as wordlists_service
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
        attempts=row.attempts or 0,
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
            row.claimed_until = None
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
        # Locked, not just read: two writers racing on one job (an operator
        # cancelling while the local executor starts it, say) would otherwise
        # both validate against the same stale status and the later commit
        # would win regardless of what the earlier one decided.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        if "status" in fields:
            job_states.check_transition(job_id, row.status, str(fields["status"]))
            if fields["status"] in job_states.TERMINAL:
                # A finished job holds no lease. Cleared here rather than at
                # each terminal call site so the reaper can never see a
                # leftover deadline on a row it has no business touching.
                fields.setdefault("claimed_until", None)
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


def _wordlist_overrides(
    settings: Settings, job_id: str, tenant_id: str, wordlist_id: str | None
) -> dict | None:
    """Materialize a tenant's selected brute-force wordlist to a job-scoped file
    and return the config override that points the matching stage at it.

    Returns ``None`` when no wordlist was requested. Raises ``ValueError`` when
    the id is unknown or belongs to another tenant — selecting a wordlist that
    cannot be found must fail the scan request, not run it without one.

    Selecting a *subdomain* list turns on the CT/brute-force discovery stage
    (``ct.enabled`` + ``ct.brute_force.enabled``) with the uploaded list; a
    *bucket* list turns on cloud discovery. Enabling ``ct`` also lets its
    configured providers run (default ``crtsh``, a passive third-party CT-log
    query) — brute force is nested under that stage and cannot run without it.
    """
    if not wordlist_id:
        return None
    resolved = wordlists_service.get_for_scan(wordlist_id, tenant_id=tenant_id)
    if resolved is None:
        raise ValueError(f"Unknown wordlist_id: {wordlist_id}")
    kind, content = resolved

    dest_dir = settings.state_dir / "wordlists"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{job_id}.txt"
    dest.write_text(content + "\n", encoding="utf-8")
    path = str(dest)

    if kind == "bucket":
        return {"cloud": {"enabled": True, "wordlist_file": path}}
    return {"ct": {"enabled": True, "brute_force": {"enabled": True, "wordlist_file": path}}}


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


def _publish_asset_events_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort publish of the run's Phase 10.1 events (Phase 10.2).

    Called from the same two places as ``_upsert_assets_best_effort`` and for
    the same reason — those are the only two points where a finished run's
    artifacts are on disk under a known tenant, whether the scan ran locally or
    came up from an agent.

    Deliberately quieter than the asset upsert on failure: an empty asset list
    is a broken installation worth recording on the job, while an unpublished
    event is a missed notification whose payload is still in ``diff.json``.
    """
    if not run_id or not settings.asset_events_enabled or not settings.nats_url:
        return
    try:
        asset_events.publish_run_events(
            nats_url=settings.nats_url,
            run_dir=settings.output_dir / "runs" / run_id,
            tenant_id=tenant_id,
            run_id=run_id,
            job_id=job_id,
            max_events=settings.asset_events_max_per_run,
        )
    except Exception:  # noqa: BLE001
        logging.exception("Asset event publish failed for run %s (tenant=%s)", run_id, tenant_id)


def _lease_deadline(settings: Settings) -> datetime:
    return _now() + timedelta(seconds=max(settings.job_lease_seconds, 1))


def renew_lease(settings: Settings, job_id: str, *, agent_id: str | None = None) -> bool:
    """Push a job's lease deadline forward. Returns whether it applied.

    The proof of life for an in-flight job: agents renew from their heartbeat,
    local jobs from a thread beside the scan (``_renewing_lease``). Only jobs
    that are actually in flight are touched, and when ``agent_id`` is given it
    must be the agent holding the job — a stray heartbeat naming someone else's
    job must not keep that job alive.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.status not in job_states.IN_FLIGHT:
            return False
        if agent_id is not None and row.assigned_agent_id != agent_id:
            return False
        row.claimed_until = _lease_deadline(settings)
        return True


@contextmanager
def _renewing_lease(settings: Settings, job_id: str) -> Iterator[None]:
    """Keep a local job's lease alive for as long as this process runs it.

    A local scan has no heartbeat to ride on — it is a ``subprocess`` in a
    thread — so without this its lease would lapse mid-scan and the reaper
    would fail a job that is running perfectly well. Renewing from beside the
    scan is also what finally closes the P1.2 residual: if this replica dies,
    the renewals stop with it and the job stops looking attended.

    Failures are logged, not raised: a database blip during a two-hour scan
    should cost a renewal, not the scan.
    """
    stop = threading.Event()
    # Renew several times per lease so a single missed tick is not fatal.
    interval = max(settings.job_lease_seconds / 3.0, 1.0)

    def _loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_lease(settings, job_id):
                    return  # Terminal already — nothing left to hold.
            except Exception:  # noqa: BLE001
                _log.warning("Lease renewal failed for job %s", job_id, exc_info=True)

    thread = threading.Thread(target=_loop, name=f"octo-lease-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)


def reap_expired_leases(settings: Settings) -> dict[str, int]:
    """Sweep jobs whose executor stopped renewing, and return what was done.

    An expired lease means the executor is gone rather than slow — it had the
    whole lease window, several renewal intervals, to say otherwise. What
    happens next differs by execution mode:

    - **agent** jobs go back to ``queued`` for another worker, until
      ``job_max_attempts`` hand-outs have been used. A target that kills
      whatever picks it up would otherwise cycle through the fleet forever.
    - **local** jobs are failed outright. Their only executor was the thread in
      the process that died; no other replica will ever pick the row up, so
      requeueing it would just park it in the queue for good.

    Safe to run in every replica (there is no leader election until P1.6): rows
    are taken with ``FOR UPDATE SKIP LOCKED``, so two reapers sweeping at once
    handle different jobs rather than the same one twice.
    """
    now = _now()
    outcome = {"requeued": 0, "failed": 0}
    requeued_agent_jobs: list[str] = []
    # (execution, started_at) per job failed here, so the duration histogram
    # sees them once the transaction commits. Without this, giving up on a job
    # would be invisible to SLO 3 exactly when executors are dying.
    failed_for_metrics: list[tuple[str, datetime | None]] = []
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Job)
            .where(
                models.Job.status.in_(tuple(job_states.IN_FLIGHT)),
                models.Job.claimed_until.is_not(None),
                models.Job.claimed_until < now,
            )
            .with_for_update(skip_locked=True)
        ).scalars().all()
        for row in rows:
            retriable = row.execution == "agent" and row.attempts < settings.job_max_attempts
            if retriable:
                job_states.check_transition(row.job_id, row.status, job_states.QUEUED)
                row.status = job_states.QUEUED
                row.assigned_agent_id = None
                row.claimed_until = None
                # The attempt never produced a run, so it must not be counted
                # as a started job by the duration histogram.
                row.started_at = None
                outcome["requeued"] += 1
                requeued_agent_jobs.append(row.job_id)
                _log.warning(
                    "Requeued job %s: lease expired after attempt %d/%d",
                    row.job_id,
                    row.attempts,
                    settings.job_max_attempts,
                )
            else:
                job_states.check_transition(row.job_id, row.status, job_states.FAILED)
                row.status = job_states.FAILED
                row.finished_at = now
                row.claimed_until = None
                row.error = (
                    f"Lease expired after {row.attempts} attempt(s): the {row.execution} "
                    "executor stopped reporting and never returned"
                )
                outcome["failed"] += 1
                failed_for_metrics.append((row.execution or "local", row.started_at))
                _log.warning(
                    "Failed job %s: lease expired after %d attempt(s) (execution=%s)",
                    row.job_id,
                    row.attempts,
                    row.execution,
                )
    for name, count in outcome.items():
        if count:
            metrics_service.JOB_LEASE_EXPIRED_TOTAL.labels(outcome=name).inc(count)
    for execution, started_at in failed_for_metrics:
        _record_job_metrics(settings, job_states.FAILED, execution, started_at, now)
    if outcome["requeued"] or outcome["failed"]:
        _refresh_job_gauges(settings)
    # Republished after the transaction commits, so an agent cannot claim the
    # offer before the row is actually back on the queue.
    if settings.nats_url:
        for job_id in requeued_agent_jobs:
            _publish_job_offer(settings, job_id)
    return outcome


def _run_job(settings: Settings, job_id: str, command: list[str]) -> None:
    try:
        # A local job goes queued → running with no claim step: this process is
        # the worker. If it was cancelled while the thread was still starting,
        # the transition is rejected and the scan never launches.
        _update_job(
            settings,
            job_id,
            status=job_states.RUNNING,
            started_at=_now(),
            claimed_until=_lease_deadline(settings),
            attempts=1,
        )
    except job_states.InvalidJobTransition as exc:
        _log.info("Not starting job %s: %s", job_id, exc)
        return
    try:
        with _renewing_lease(settings, job_id):
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
            _publish_asset_events_best_effort(
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


class IdempotentReplay(Exception):
    """A scan start whose key already created a job. Carries that job.

    An exception rather than a return value because the caller has to answer
    differently (200, not 202): nothing was accepted by this request.
    """

    def __init__(self, job: JobInfo) -> None:
        super().__init__(f"Idempotency key already started job {job.job_id}")
        self.job = job


def note_start_replay() -> None:
    """Count a scan-start request answered from an existing job."""
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(operation="start").inc()


def find_by_idempotency_key(settings: Settings, *, tenant_id: str, key: str) -> JobInfo | None:
    """The job a previous request with this key created, if any (P1.5)."""
    if not key:
        return None
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.Job).where(
                models.Job.tenant_id == tenant_id,
                models.Job.idempotency_key == key,
            )
        ).scalars().first()
        return _to_info(row) if row else None


def start_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    idempotency_key: str | None = None,
) -> JobInfo:
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
        extra = _wordlist_overrides(settings, job_id, tenant_id, request.wordlist_id)
        config_path = config_override_service.effective_config_path(settings, job_id, extra)
    else:
        if request.wordlist_id:
            # A custom wordlist lives in the API's Postgres and is materialized
            # onto the API pod's filesystem; a remote agent runs its own mounted
            # config and never sees it. Rather than silently ignore the request,
            # refuse it — the same class of limitation as installation overrides
            # not reaching agents.
            raise ValueError(
                "wordlist_id is only supported in local execution mode, "
                "not with remote agents"
            )
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
        idempotency_key=(idempotency_key or None),
        queued_at=_now(),
    )
    try:
        with get_session(settings.postgres_url) as session:
            session.add(row)
            session.flush()
            info = _to_info(row)
    except IntegrityError:
        # Lost the race on (tenant_id, idempotency_key): another replica — or
        # this one, serving the client's retry concurrently — already created
        # the job. The caller wanted one scan for this key and there is one.
        existing = find_by_idempotency_key(
            settings, tenant_id=tenant_id, key=idempotency_key or ""
        )
        if existing is None:
            raise
        _log.info("Idempotent scan start: key already created job %s", existing.job_id)
        # Raised rather than returned so the caller can answer 200 here too:
        # this request accepted nothing, exactly like the sequential replay the
        # route detects before calling in.
        raise IdempotentReplay(existing) from None
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
        # `started_at` deliberately stays unset until the agent reports
        # starting (mark_running). Stamping it here would fold the
        # claim-to-heartbeat delay into every job-duration observation, and
        # would show a job that never ran as having executed.
        row.started_at = None
        # The lease starts at the claim, not at the first heartbeat: an agent
        # that dies between the two is exactly the case P1.4 has to catch.
        row.claimed_until = _lease_deadline(settings)
        row.attempts = (row.attempts or 0) + 1
        attempt = row.attempts
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
            # The fencing token for this hand-out: a lease that expired and was
            # reissued bumps it, so a late upload from the previous attempt can
            # be told apart from the current one even when both come from the
            # same agent_id (a restarted worker keeps its id).
            attempt=attempt,
        )
    _refresh_job_gauges(settings)
    agents_service.touch_job(agent_id, claimed_id, status="busy")
    return response


def mark_running(settings: Settings, job_id: str, *, agent_id: str) -> None:
    """Record an agent's heartbeat for the job it is working on.

    Two things ride on this one signal: a claimed job is promoted to running,
    and an in-flight job's lease is pushed forward (P1.4) — the heartbeat is
    the only regular evidence the API gets that a remote worker is still alive.

    Any other state is left alone: repeated heartbeats during a scan would
    otherwise attempt running → running, and a heartbeat arriving after the
    results upload must not resurrect a finished job. A heartbeat from an agent
    that does not hold the job is ignored outright.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.status not in job_states.IN_FLIGHT:
            return
        if row.assigned_agent_id != agent_id:
            return
        row.claimed_until = _lease_deadline(settings)
        if row.status != job_states.CLAIMED:
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
    """Cancel a job nothing has picked up yet.

    Legal only from ``queued``. Once an agent has claimed a job it starts
    scanning without asking the API again, so cancelling a ``claimed`` (or
    ``running``) job would show a stop that never happened while the scan went
    on hitting the targets — see ``job_states``. An abandoned claimed job is
    handled by the lease reaper instead.

    The reason is stored in ``error`` rather than a new column: it is the field
    the UI and API already surface for "why did this job end this way".
    """
    with get_session(settings.postgres_url) as session:
        # Locked for the same reason as _update_job: a local job's executor
        # thread may be transitioning the very same row to running right now,
        # and cancelling a job that has already started is exactly the outcome
        # this endpoint must never report.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise LookupError("Job not found")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        job_states.check_transition(job_id, row.status, job_states.CANCELLED)
        row.status = job_states.CANCELLED
        row.finished_at = _now()
        row.claimed_until = None
        row.error = f"Cancelled by {username}"[:2000]
    _refresh_job_gauges(settings)
    result = get_job(settings, job_id)
    assert result is not None
    return result


class ResultsConflict(ValueError):
    """A second upload for a finished job that is not a replay of the first."""


class ResultsInFlight(ResultsConflict):
    """A duplicate upload arrived while the first one is still being ingested."""


class StaleAttempt(ValueError):
    """An upload from a lease that has already expired and been reissued."""


def _release_results_reservation(settings: Settings, job_id: str, key: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        # Only clear our own reservation, and only while the job is still
        # unfinished: once it is terminal the key is the record of what
        # produced that outcome, not a reservation.
        if row is not None and row.status not in job_states.TERMINAL:
            if row.results_idempotency_key == key:
                row.results_idempotency_key = None


def _classify_replay(
    row: models.Job, *, exit_code: int, idempotency_key: str | None
) -> JobInfo | None:
    """Decide whether an upload for an already-finished job is a replay.

    Returns the stored outcome for a replay, raises ``ResultsConflict`` for an
    upload that contradicts it, and returns ``None`` when this is not a replay
    question at all (a cancelled job, say) so the caller's normal transition
    check produces the error.

    With a key, the comparison is exact. Without one — older agents, and the
    legacy shared-token path — the fallback is the natural key: the same agent
    reporting the same exit code for a job it still owns is the retry we are
    trying to survive, and it cannot be confused with a different result,
    because a different result carries a different exit code.
    """
    if row.status == job_states.CANCELLED:
        return None
    if idempotency_key:
        if row.results_idempotency_key == idempotency_key:
            return _replayed(row)
        if row.results_idempotency_key:
            raise ResultsConflict(
                f"Job {row.job_id} already has results from a different upload"
            )
        return None
    if row.exit_code == exit_code:
        return _replayed(row)
    return None


def _replayed(row: models.Job) -> JobInfo:
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(operation="results").inc()
    _log.info("Replayed results upload for job %s; returning the stored outcome", row.job_id)
    return _to_info(row)


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
    idempotency_key: str | None = None,
    attempt: int | None = None,
) -> JobInfo:
    """Record an agent's result upload. Replays return the original outcome.

    P1.3 made a second upload an error, which is right for a *different*
    result but wrong for the case that actually happens: the upload succeeded
    and the response never made it back, so the agent sends the same bytes
    again. Under P1.5 that replay is answered with the job as it already
    stands — no re-extraction, no second NATS publish, no error for the agent
    to interpret. Two uploads that genuinely disagree still conflict.

    ``attempt`` is the fencing token from the claim response. A lease that
    expired and was reissued bumped it, so an upload carrying an older value is
    a straggler from an attempt that has already been replaced — and since a
    restarted worker keeps its ``agent_id``, that is the only way to tell the
    two apart. Omitted by pre-P1.5 agents, which are then unfenced.
    """
    with get_session(settings.postgres_url) as session:
        # Locked for the whole check: concurrent uploads for the same job must
        # be decided one at a time, or both would read a non-terminal row and
        # both go on to extract the archive.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            raise LookupError("Job not found")
        if row.execution != "agent":
            raise ValueError("Job is not an agent job")
        if row.assigned_agent_id != agent_id:
            raise PermissionError("Job is assigned to a different agent")
        job_tenant = row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        if tenant_id is not None and job_tenant != tenant_id:
            raise PermissionError("Cross-tenant job access denied")
        if attempt is not None and attempt != (row.attempts or 0):
            raise StaleAttempt(
                f"Job {job_id} is on attempt {row.attempts}; upload is from attempt {attempt}"
            )
        status = job_states.SUCCEEDED if exit_code == 0 else job_states.FAILED
        if row.status in job_states.TERMINAL:
            replay = _classify_replay(row, exit_code=exit_code, idempotency_key=idempotency_key)
            if replay is not None:
                return replay
        elif idempotency_key:
            if row.results_idempotency_key == idempotency_key:
                # Same key, job not finished: the first request holding this key
                # is still ingesting. Answering 409 tells the client to retry
                # rather than letting two handlers extract into one run
                # directory and race to terminalize the job.
                raise ResultsInFlight(
                    f"An upload with this key is already being processed for job {job_id}"
                )
            # Reserve the key inside the locked transaction, so the duplicate
            # above can recognise it. Cleared again if this upload fails.
            row.results_idempotency_key = idempotency_key
        # Checked before the archive is ingested, not after: a duplicate upload
        # for a job that already finished — or one an operator cancelled while
        # the agent was still working — must not overwrite the run directory
        # and re-publish to NATS before being rejected.
        job_states.check_transition(job_id, row.status, status)
        resolved_run_id = run_id or row.run_id

    try:
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
            # Gated on the outcome, matching the local path. An agent may attach
            # diagnostics to a *failed* run, and a partial diff read as a change
            # set would alert on hosts and ports that a broken scan simply
            # failed to observe — a disappearance is not a discovery.
            if status == job_states.SUCCEEDED:
                _publish_asset_events_best_effort(
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
            # Recorded with the outcome, so a later upload can be told apart from
            # the one that produced it.
            results_idempotency_key=(idempotency_key or None),
        )
    except Exception:
        # The reservation above is only meaningful while this upload is in
        # flight. Releasing it lets the agent retry with the same key instead
        # of meeting its own abandoned reservation forever.
        if idempotency_key:
            _release_results_reservation(settings, job_id, idempotency_key)
        raise
    agents_service.touch_job(agent_id, None, status="idle")
    result = get_job(settings, job_id)
    assert result is not None
    return result
