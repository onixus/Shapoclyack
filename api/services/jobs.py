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

import hashlib
import json
import logging
import sys
import threading
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import agents as agents_service
from api.services import artifact_store
from api.services import audit as audit_service
from api.services import config_override as config_override_service
from api.services.artifact_store import workspace as artifact_workspace
from api.services import job_states
from api.services import job_dispatch
from api.services import job_inputs
from api.services import job_leases
from api.services import job_reaper
from api.services import job_results
from api.services import job_store
from api.services import local_scan_executor
from api.services import metrics as metrics_service
from api.services import pagination
from api.services import run_completion
from api.services import run_ids
from api.services import runs as runs_service
from api.services import scan_admission
from api.services import scan_policy
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.services import scan_intents
from api.services import scan_surface
from api.settings import Settings

_log = logging.getLogger(__name__)

# Compatibility names for the scanner input contract. Layout ownership lives
# in job_inputs; keeping aliases here avoids breaking existing callers while
# preventing two copies of the file list from drifting.
SCAN_SCOPE_INPUT = job_inputs.SCAN_SCOPE_INPUT
PROMOTED_DOMAINS_INPUT = job_inputs.PROMOTED_DOMAINS_INPUT
SCAN_POLICY_INPUT = job_inputs.SCAN_POLICY_INPUT
_JOB_INPUT_FILES = job_inputs.JOB_INPUT_FILES

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


def _to_info(
    row: models.Job,
    live_groups: set[tuple[str, str]] | None = None,
) -> JobInfo:
    return job_store.to_info(row, live_groups)


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
    surface: str | None = None,
) -> tuple[list[JobInfo], int]:
    """Return ``(page, total_after_filtering)`` — see api/services/pagination.py.

    Filtered, counted, and sliced in SQL. ``NULLS LAST`` keeps the documented
    ordering rule that a job which never started does not outrank one that
    did, in both directions.

    ``surface`` filters on ``scan_options->>'surface'`` (see
    api.services.scan_surface). ``"unknown"`` selects the rows where the key is
    absent or null — jobs started before this shipped, and scans of the
    server's default input files — so the three surfaces plus ``unknown``
    partition the list and no job is invisible under every filter.
    """
    column = JOB_SORT_COLUMNS.get(sort or "", models.Job.started_at)
    ascending = (order or "").lower() == "asc"
    direction = column.asc().nullslast() if ascending else column.desc().nullslast()

    with get_session(settings.postgres_url) as session:
        filters = []
        if tenant_id:
            filters.append(models.Job.tenant_id == tenant_id)
        if surface:
            stored = models.Job.scan_options["surface"].as_string()
            filters.append(stored.is_(None) if surface == "unknown" else stored == surface)
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
    # Outside the session, and only when the page actually has a grouped job:
    # the overwhelming majority of installations have no groups at all and must
    # not pay a second query per listing for a column they never show.
    live = _live_groups_for(settings, rows)
    return [_to_info(row, live) for row in rows], total


#: The surface buckets ``summary`` reports, in the order a console renders
#: them. ``unknown`` is the NULL bucket, exactly as in ``list_jobs``.
SUMMARY_SURFACES = (*scan_surface.SURFACES, "unknown")


def summary(settings: Settings, *, tenant_id: str | None = None) -> dict[str, Any]:
    """Queue depth by status and by surface, in one grouped query.

    The counts a scan console shows above the job list. ``tenant_id`` of
    ``None`` counts the whole fleet, which only an unscoped platform admin
    reaches — the same rule as ``list_jobs``.

    ``queued`` here is queued *plus* claimed: the question the number answers
    is "how much work is waiting to be done", and a job an agent has taken but
    not started is still waiting. Note this differs from the ``octo_jobs_*``
    gauges in docs/slo.md, which count ``claimed`` as running because they are
    measuring executor occupancy instead.
    """
    by_status = dict.fromkeys(sorted(job_states.ALL), 0)
    by_surface = {
        surface: {"running": 0, "queued": 0, "total": 0} for surface in SUMMARY_SURFACES
    }
    stored_surface = models.Job.scan_options["surface"].as_string()

    with get_session(settings.postgres_url) as session:
        filters = [models.Job.tenant_id == tenant_id] if tenant_id else []
        rows = session.execute(
            select(models.Job.status, stored_surface, func.count())
            .where(*filters)
            .group_by(models.Job.status, stored_surface)
        ).all()

    for status, surface, count in rows:
        # A status outside the lifecycle cannot be produced by job_states, but
        # a hand-edited row must not make the whole summary disappear.
        by_status[str(status)] = by_status.get(str(status), 0) + count
        bucket = by_surface[surface if surface in by_surface else "unknown"]
        bucket["total"] += count
        if status in (job_states.RUNNING, job_states.CANCELLING):
            bucket["running"] += count
        elif status in (job_states.QUEUED, job_states.CLAIMED):
            bucket["queued"] += count

    return {
        "by_status": by_status,
        # A job being stopped is still on a worker, so it is counted with the
        # running ones rather than disappearing from both tiles (#360).
        "running": by_status.get(job_states.RUNNING, 0)
        + by_status.get(job_states.CANCELLING, 0),
        "queued": by_status.get(job_states.QUEUED, 0) + by_status.get(job_states.CLAIMED, 0),
        "by_surface": by_surface,
        "generated_at": _iso(_now()),
    }


def _live_groups_for(
    settings: Settings, rows: Sequence[models.Job]
) -> set[tuple[str, str]] | None:
    """``live_groups`` for the tenants of these rows, or None if none is grouped."""
    tenants = {
        row.tenant_id or tenants_service.DEFAULT_TENANT_ID
        for row in rows
        if row.agent_group and row.status == job_states.QUEUED
    }
    if not tenants:
        return None
    return agent_groups_service.live_groups(settings, tenants)


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return None
        live = _live_groups_for(settings, [row])
        return _to_info(row, live)


def reset_for_tests(settings: Settings) -> None:
    with get_session(settings.postgres_url) as session:
        session.query(models.Job).delete()


_IngestLease = job_leases.IngestLease


def _open_ingest_lease(*args, **kwargs):
    return job_leases.open_ingest_lease(*args, **kwargs)


def _check_ingest_fence(*args, **kwargs):
    return job_leases.check_ingest_fence(*args, **kwargs)


def _update_job(*args, **kwargs) -> None:
    job_store.update_job(*args, **kwargs)


def _scan_failure_event(row: models.Job) -> dict[str, Any]:
    return job_store.scan_failure_event(row)


def force_status(
    settings: Settings, job_id: str, status: str, **fields: Any
) -> None:
    job_store.force_status(settings, job_id, status, **fields)


def _record_job_metrics(*args, **kwargs) -> None:
    job_store.record_job_metrics(*args, **kwargs)


def _refresh_job_gauges(settings: Settings) -> None:
    job_store.refresh_job_gauges(settings)


# Compatibility facade: callers historically reached these through jobs.
job_inputs_dir = job_inputs.job_inputs_dir
wordlist_file_for_job = job_inputs.wordlist_file_for_job


def _prepare_target_inputs(*args, **kwargs):
    return job_inputs.prepare_target_inputs(*args, **kwargs)


def publish_job_inputs(settings: Settings, job_id: str) -> None:
    job_inputs.publish(settings, job_id)


def ensure_job_inputs_local(settings: Settings, job_id: str) -> Path:
    return job_inputs.ensure_local(settings, job_id)


def _discard_job_inputs(settings: Settings, job_id: str) -> None:
    job_inputs.discard(settings, job_id)


def _discard_job_wordlist(settings: Settings, job_id: str) -> None:
    job_inputs.discard_wordlist(settings, job_id)


def _wordlist_overrides(*args, **kwargs):
    return job_inputs.wordlist_overrides(*args, **kwargs)


def _build_command(
    settings: Settings,
    *,
    mode: str,
    delta: bool,
    skip_nse: bool,
    notify: bool,
    export_defectdojo: bool,
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
        mode,
    ]
    if delta:
        command.append("--delta")
    if skip_nse:
        command.append("--skip-nse")
    if notify:
        command.append("--notify")
    if export_defectdojo:
        command.append("--export-defectdojo")
    if run_id:
        command.extend(["--run-id", run_id])
    command.extend(target_args)
    return command


# Compatibility facade for callers/tests that historically reached completion
# hooks through jobs. Ownership lives in run_completion.
def _upsert_assets_best_effort(*args, **kwargs):
    return run_completion.upsert_assets_best_effort(*args, **kwargs)


def _track_vulnerabilities_best_effort(*args, **kwargs):
    return run_completion.track_vulnerabilities_best_effort(*args, **kwargs)


def _publish_asset_events_best_effort(*args, **kwargs):
    return run_completion.publish_asset_events_best_effort(*args, **kwargs)


def _notify_channels_best_effort(*args, **kwargs):
    return run_completion.notify_channels_best_effort(*args, **kwargs)


def _record_scope_denials_best_effort(*args, **kwargs):
    return run_completion.record_scope_denials_best_effort(*args, **kwargs)


def _lease_deadline(settings: Settings) -> datetime:
    return job_leases.lease_deadline(settings)


def _extend_lease(row: models.Job, deadline: datetime) -> None:
    job_leases.extend_lease(row, deadline)


def renew_lease(
    settings: Settings, job_id: str, *, agent_id: str | None = None
) -> bool:
    return job_leases.renew_lease(settings, job_id, agent_id=agent_id)


def _renewing_lease(settings: Settings, job_id: str):
    return job_leases.renewing_lease(settings, job_id)


def reap_expired_leases(settings: Settings) -> dict[str, int]:
    return job_reaper.reap_expired_leases(settings)


# Compatibility aliases retained for tests and diagnostics that inspect the
# process registry through jobs. The lifecycle itself lives in
# local_scan_executor now.
_local_scan_procs = local_scan_executor.processes
_local_scan_threads = local_scan_executor.threads


def live_local_scans() -> list[str]:
    return local_scan_executor.live()


def stop_local_scans(timeout: float = 30.0) -> bool:
    return local_scan_executor.stop_all(timeout)


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
        # Cancelled between the insert and this thread getting scheduled: the
        # scan never launches, so nothing will ever read the wordlist copy or
        # the input files.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        return
    try:
        with _renewing_lease(settings, job_id):
            completed = local_scan_executor.run_scanner(job_id, command)
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
        job = get_job(settings, job_id)
        tenant_id = job.tenant_id if job else tenants_service.DEFAULT_TENANT_ID
        # Outside the success gate: a target the scanner refused was refused
        # whether or not the scan that followed it finished cleanly.
        _record_scope_denials_best_effort(
            settings,
            tenant_id=tenant_id,
            run_id=str(run_id) if run_id else None,
            requested_by=job.requested_by if job else "",
        )
        if run_id:
            # The scanner chose the run id and wrote the directory itself, so
            # this is the first moment the run can be put in the artifact
            # store (#336). Before the tagging below, and before the hooks:
            # they all read the run back through the workspace.
            try:
                artifact_workspace.adopt_local_run(
                    settings, str(run_id), settings.output_dir / "runs" / str(run_id)
                )
            except artifact_store.ArtifactStoreError:
                logging.exception(
                    "Could not publish run %s to the artifact store", run_id
                )
        if status == job_states.SUCCEEDED:
            # Tag the run before the asset upsert: an untagged run reads back as
            # the default tenant, which would leak it to every tenant's run list.
            if run_id:
                runs_service.write_run_tenant(
                    settings,
                    str(run_id),
                    tenant_id,
                    job_id=job_id,
                    surface=(job.scan_options or {}).get("surface") if job else None,
                )
            _upsert_assets_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            _track_vulnerabilities_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            _publish_asset_events_best_effort(
                settings, tenant_id=tenant_id, run_id=str(run_id) if run_id else None, job_id=job_id
            )
            # Last of the post-run hooks: the summary it sends describes the
            # tracker and the registry as they are *after* the folds above.
            _notify_channels_best_effort(
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
    finally:
        # The scanner has exited either way, so its copy of the wordlist and
        # its input files have been read for the last time.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)


#: Request fields that define *which scan* a start asks for. ``tenant_id`` is
#: decided by the route rather than the caller, and ``run_id`` only names the
#: output directory, so neither makes two calls a different request.
_IDEMPOTENCY_FIELDS = (
    "mode",
    "intent",
    "delta",
    "skip_nse",
    "notify",
    "export_defectdojo",
    "surface",
    "wordlist_id",
    # Which agents may execute the scan is part of what was asked for (#361):
    # answering a request for one group with the job of another would report a
    # scan that reached the targets from somewhere else entirely.
    "agent_group",
)

#: Target fields, compared line by line rather than character by character.
_IDEMPOTENCY_TARGET_FIELDS = ("ranges", "domains", "ports", "ports_udp")


def _normalised_target_text(text: str | None) -> str | None:
    """The same target list typed with different whitespace, spelled one way.

    Not ``split_target_lines``: that also drops comments and splits on commas,
    which are edits to the request rather than formatting of it. A retry is a
    resend of the same body, so trimming each line and dropping blank ones is
    as far as this may go without calling two different requests the same.
    """
    if text is None:
        return None
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def _idempotency_digest(request: StartScanRequest) -> str:
    """A fingerprint of the scan a start request asks for (ROADMAP P1.5).

    A key on its own only says "the client called this request X"; it cannot
    say whether the second call is the retry it claims to be. The digest is
    what lets the second call be answered with the first job only when it is
    in fact the same scan — see ``IdempotencyMismatch``.
    """
    payload: dict[str, Any] = {
        field: getattr(request, field) for field in _IDEMPOTENCY_FIELDS
    }
    payload.update(
        {
            field: _normalised_target_text(getattr(request, field))
            for field in _IDEMPOTENCY_TARGET_FIELDS
        }
    )
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IdempotencyMismatch(Exception):
    """A key an earlier request used, sent with a *different* scan request.

    Deliberately not a replay: answering with the earlier job would report a
    scan of targets this caller never asked for, and starting a second one
    would break the promise the key was given for. Neither is right, so the
    caller is told the key is taken (409) and picks another.

    Not a ``ValueError``: the body is well-formed, and the route maps
    ``ValueError`` to 422.
    """

    def __init__(self, job: JobInfo) -> None:
        super().__init__(
            "Idempotency-Key already used for a different scan request "
            f"(job {job.job_id})"
        )
        self.job = job


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


def find_by_idempotency_key(
    settings: Settings,
    *,
    tenant_id: str,
    key: str,
    request: StartScanRequest | None = None,
) -> JobInfo | None:
    """The job a previous request with this key created, if any (P1.5).

    With ``request``, the hit is also checked against what this caller is
    asking for and a key reused for a different scan raises
    ``IdempotencyMismatch`` instead of replaying. A job stored before the
    digest shipped carries none and is treated as a match: the alternative is
    to start 409-ing keys that worked yesterday.
    """
    if not key:
        return None
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.Job).where(
                models.Job.tenant_id == tenant_id,
                models.Job.idempotency_key == key,
            )
        ).scalars().first()
        if row is None:
            return None
        info = _to_info(row)
    if request is not None:
        stored = (row.scan_options or {}).get("idempotency_digest")
        if stored and stored != _idempotency_digest(request):
            raise IdempotencyMismatch(info)
    return info


# A run id names one directory under ``output_dir/runs``. This module mints
# them as ``%Y%m%dT%H%M%SZ-<6 hex>`` (:func:`_mint_run_id`), the scanner's own
# CLI as the timestamp alone; operators may supply their own for a local run.
# Either way it must stay a single path segment: it is joined onto the output
# directory unescaped, so anything with a separator or ``..`` in it would name
# a directory the caller was never given.
def _mint_run_id() -> str:
    return run_ids.mint()


def validate_run_id(value: str) -> str:
    return run_ids.validate(value)


def _confirm_run_id(expected: str | None, offered: str | None) -> str | None:
    return run_ids.confirm(expected, offered)


def start_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    idempotency_key: str | None = None,
    quota_exempt: bool = False,
    widen_with_promoted: bool = True,
) -> JobInfo:
    """``widen_with_promoted`` is whether this scan carries the related domains
    the tenant's operators promoted (org_profile M4) on top of its own targets.
    On by default — that is what promotion means — and off for a dispatch
    that is aimed at one thing, today the verification re-scan of #183. A
    separate switch from ``quota_exempt`` on purpose: billing and targeting
    are different policies that happen to coincide on that one caller.

    ``quota_exempt`` marks a scan the platform dispatched to close its own
    loop — today only the verification re-scan of #183. It is neither refused
    by the tenant's monthly quota nor counted against it, and it is a property
    of *this dispatch*: the requester's name is the analyst's on that path, so
    recognising the exemption by username would be both wrong and forgeable.
    """
    if not settings.allow_scan_start:
        raise RuntimeError("Scan start disabled by OCTO_ALLOW_SCAN_START")

    job_id = uuid.uuid4().hex[:12]
    execution = "agent" if settings.job_execution_mode == "agent" else "local"
    run_id = request.run_id
    if run_id:
        validate_run_id(run_id)
    if execution == "agent" and not run_id:
        run_id = _mint_run_id()

    # Admission is its own boundary: jobs owns queueing/execution while
    # scan_admission owns whether this request may enter the queue and where it
    # may run. New policy no longer adds another dependency and another branch
    # to this already hot service.
    admission = scan_admission.admit_scan(
        settings,
        request,
        username=username,
        job_id=job_id,
        execution=execution,
        quota_exempt=quota_exempt,
        widen_with_promoted=widen_with_promoted,
    )
    tenant_id = admission.tenant_id
    scope = admission.scope
    promoted_admitted = list(admission.promoted_admitted)
    promoted_refused = list(admission.promoted_refused)
    policy_snapshot = admission.policy_snapshot
    agent_group = admission.agent_group
    group_has_live_agent = admission.group_has_live_agent

    # Only after admission succeeds do we create job-scoped files. A refused
    # scan is now side-effect free at this boundary.
    try:
        _, target_counts, target_args = _prepare_target_inputs(
            settings,
            job_id,
            request,
            tenant_id=tenant_id,
            promoted=promoted_admitted,
            scope=scope,
            policy=policy_snapshot,
        )
        publish_job_inputs(settings, job_id)
    except scan_scopes.ScanScopeDenied as denied:
        # Defensive: admission already ran the same barrier, but target parsing
        # is intentionally allowed to be stricter. Preserve the audit contract
        # if it rejects a value admission did not.
        scan_scopes.record_denial(username=username, denied=denied)
        _discard_job_inputs(settings, job_id)
        raise

    try:
        resolved = scan_intents.resolve_scan_options(
            intent=request.intent,
            mode=request.mode,
            delta=request.delta,
            skip_nse=request.skip_nse,
        )
    except ValueError:
        raise

    # Local scans run in this container, so apply the installation config
    # overrides by merging them into a job-specific config file. Agents run
    # their own mounted config, so overrides don't reach them — they keep the
    # base config (documented limitation). Intent nuclei/top_ports overlays
    # are local-only for the same reason.
    wordlist_options: dict[str, Any] = {}
    intent_extra = resolved.config_extra
    if execution == "local":
        selected = _wordlist_overrides(settings, job_id, tenant_id, request.wordlist_id)
        wordlist_extra: dict[str, Any] | None = None
        if selected:
            wordlist_extra, wordlist_options = selected
        extra = scan_intents.merge_config_extras(intent_extra, wordlist_extra)
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
        if intent_extra:
            # Agent workers do not receive the merged effective-config file;
            # surface that so operators do not think nuclei floors applied.
            _log.warning(
                "intent=%s config overlays (nuclei/top_ports) are skipped in agent mode; "
                "CLI flags delta=%s skip_nse=%s still apply",
                resolved.intent,
                resolved.delta,
                resolved.skip_nse,
            )
        config_path = str(settings.config_path)
    # Derived from the targets as the operator entered them, not from the
    # widened set: a promoted related domain rides along with every scan and
    # would turn an internal sweep into a "mixed" one it was never asked to be.
    surface = scan_surface.resolve(request.surface, request.ranges, request.domains)
    # A fragile (OT/ICS) policy turns the service-probe stage off: nmap's NSE
    # scripts and pulse's banner grabs are the packets that put a PLC into a
    # fault state, and the port inventory a fragile run is really asked for
    # does not need them. Expressed on the command line as well as in the
    # policy document the scanner applies, so a reader of the job — and the
    # ``--skip-nse`` the scanner sees — says the same thing.
    skip_nse = resolved.skip_nse or bool((policy_snapshot or {}).get("skip_service_probe"))
    command = _build_command(
        settings,
        mode=resolved.mode,
        delta=resolved.delta,
        skip_nse=skip_nse,
        notify=request.notify,
        export_defectdojo=request.export_defectdojo,
        run_id=run_id,
        target_args=target_args,
        config_path=config_path,
    )

    row = models.Job(
        job_id=job_id,
        tenant_id=tenant_id,
        status=job_states.QUEUED,
        execution=execution,
        mode=resolved.mode,
        run_id=run_id,
        command=command,
        scan_options={
            "mode": resolved.mode,
            "intent": resolved.intent,
            "intent_summary": resolved.summary if resolved.intent else None,
            "delta": resolved.delta,
            # Visible on the job rather than only in the log: which promoted
            # domains this scan carried, and which the scope kept out.
            **({"promoted_domains": promoted_admitted} if promoted_admitted else {}),
            **({"promoted_domains_refused": promoted_refused} if promoted_refused else {}),
            "skip_nse": skip_nse,
            # The policy this scan was admitted under (#362), on the job rather
            # than only derivable from a table that has since moved on. Absent
            # for a tenant with no policy, so a job started before one was
            # written reads exactly as it did.
            **({"scan_policy": policy_snapshot} if policy_snapshot else {}),
            # External / internal / mixed, or None when the scan runs the
            # server's default input files and nothing here can tell (see
            # api.services.scan_surface).
            "surface": surface,
            # Whether that value is the operator's declaration or the server's
            # reading of the targets. Risk scoring treats only a declared
            # external scan as network-exposure evidence, and without this the
            # two are indistinguishable once stored.
            "surface_source": (
                "operator" if request.surface else ("derived" if surface else None)
            ),
            "notify": request.notify,
            "export_defectdojo": request.export_defectdojo,
            # Mirrored into the options so a schedule replaying this job's
            # settings, and the idempotency digest, both see the selector.
            **({"agent_group": agent_group} if agent_group else {}),
            # Only alongside a key: it exists to tell this request apart from
            # the next one carrying the same key, and nothing else reads it.
            **(
                {"idempotency_digest": _idempotency_digest(request)}
                if idempotency_key
                else {}
            ),
            **wordlist_options,
        },
        target_counts=target_counts,
        requested_by=username,
        agent_group=agent_group,
        assigned_agent_id=None,
        # Only local jobs are bound to this process; an agent job is claimable
        # by any worker and must not be reconciled when this replica restarts.
        owner_id=settings.instance_id if execution == "local" else None,
        idempotency_key=(idempotency_key or None),
        quota_exempt=quota_exempt,
        queued_at=_now(),
    )
    try:
        with get_session(settings.postgres_url) as session:
            if agent_group:
                # Re-asked here, holding the group row, rather than trusted
                # from the resolution above: that ran on a connection of its
                # own and this insert is another, so a concurrent
                # ``DELETE /api/agent-groups/{name}`` could count the pending
                # jobs of the group, find this one not yet inserted, and take
                # the row. What was left is a ``queued`` job addressed to a
                # group that is gone — no agent can be put into one, so it is
                # claimed by nobody, shows ``agent_group_unavailable`` in the
                # console and raises no error anywhere (#361).
                if not agent_groups_service.lock_existing_names(
                    session, tenant_id=tenant_id, names={agent_group}
                ):
                    raise ValueError(
                        f"Unknown agent_group for tenant {tenant_id}: {agent_group}"
                    )
            session.add(row)
            session.flush()
            info = _to_info(
                row,
                # What the check a few lines above found, so the answer to the
                # request that created the job is the same one the queue view
                # will show. Every later read recomputes it.
                (
                    ({(tenant_id, agent_group)} if group_has_live_agent else set())
                    if agent_group
                    else None
                ),
            )
    except ValueError:
        # The group this scan is addressed to went while the row was being
        # written. Nothing became a job, so the input files staged for it —
        # and the merged config beside them — would be read by nobody;
        # discarded here the way the idempotency loser's are.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        raise
    except IntegrityError:
        # Lost the race on (tenant_id, idempotency_key): another replica — or
        # this one, serving the client's retry concurrently — already created
        # the job. The caller wanted one scan for this key and there is one.
        # This job_id never became a row, so its materialized wordlist (and the
        # merged config beside it) and its input files would be read by nobody
        # — discarded first, so the mismatch below does not leak them either.
        _discard_job_wordlist(settings, job_id)
        _discard_job_inputs(settings, job_id)
        # ``request=`` here too: the racing pair may not be the same scan, and
        # the loser of the race must hear that rather than be handed a job for
        # targets it never asked about.
        existing = find_by_idempotency_key(
            settings, tenant_id=tenant_id, key=idempotency_key or "", request=request
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
        thread = threading.Thread(
            target=_run_job,
            args=(settings, job_id, command),
            name=f"octo-scan-{job_id}",
            daemon=True,
        )
        local_scan_executor.register_thread(thread)
        thread.start()
    elif execution == "agent" and settings.nats_url:
        _publish_job_offer(settings, job_id)

    return info


def _publish_job_offer(settings: Settings, job_id: str) -> None:
    job_dispatch.publish_offer(settings, job_id)


def _read_job_inputs(settings: Settings, job_id: str) -> dict[str, str]:
    inputs_dir = ensure_job_inputs_local(settings, job_id)
    if not inputs_dir.is_dir():
        return {}
    out: dict[str, str] = {}
    for name in _JOB_INPUT_FILES:
        path = inputs_dir / name
        if path.is_file():
            out[name] = path.read_text(encoding="utf-8")
    return out


def apply_policy_to_queued(
    settings: Settings,
    *,
    tenant_id: str,
    resolved: dict[str, Any] | None,
) -> int:
    """Hold this tenant's still-queued jobs to a policy written after they queued.

    Returns how many jobs were changed, which the PUT reports back: the number
    is what tells an operator that writing ``fragile`` at 09:00 also caught the
    scan that has been waiting for an offline agent since 02:00 — the one that
    would otherwise have started at the pace it was admitted with.

    Tightening only, through ``scan_policy.tighten``: a queued job keeps every
    ceiling it was admitted under and gains the stricter ones. A job that
    carried no policy at all gains one, which also means the claim check will
    now hold it for an agent that declares the capability (#362) — deliberately,
    because "not scanned yet" is the better outcome on the estate this profile
    describes, and the PUT's count is where the operator sees it.

    Deleting a policy does not run this: the frozen snapshots stay, and a scan
    already admitted under a ceiling is not loosened behind the operator's back.

    Best-effort against a job being claimed at the same moment — a job that
    leaves ``queued`` between the select and the write keeps the snapshot it
    was handed. The window is one transaction wide and the next scan of that
    tenant is admitted under the new policy in any case.
    """
    if resolved is None:
        return 0
    touched = 0
    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.Job).where(
                    models.Job.tenant_id == tenant_id,
                    models.Job.status == job_states.QUEUED,
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            options = dict(row.scan_options or {})
            frozen = options.get("scan_policy")
            merged = scan_policy.snapshot(scan_policy.tighten(frozen, resolved))
            if merged is None or merged == frozen:
                continue
            command = list(row.command or [])
            policy_path = _write_policy_input(job_inputs_dir(settings, row.job_id), merged)
            publish_job_inputs(settings, row.job_id)
            if "--scan-policy" not in command:
                command.extend(["--scan-policy", str(policy_path)])
            options["scan_policy"] = merged
            if merged.get("skip_service_probe"):
                options["skip_nse"] = True
                if "--skip-nse" not in command:
                    command.append("--skip-nse")
            # Reassigned rather than mutated: both columns are JSON, and an
            # in-place edit of the loaded value is not seen as a change.
            row.scan_options = options
            row.command = command
            touched += 1
    if touched:
        _log.info(
            "Scan policy for tenant %s applied to %d queued job(s)", tenant_id, touched
        )
    return touched


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

    Since #361 the tenant is not the only boundary: a job addressed to an agent
    group is claimable only by an agent an operator put in that group, and a
    job addressed to none is claimable by anybody in the tenant — which is
    every job that existed before that revision, and still the default. The
    filter is in the SQL rather than in a check after the fact so a claim that
    is not permitted never takes the row's lock, and the NATS pull path (which
    names a specific ``job_id``) is filtered by the same predicate: an agent
    handed an offer for another group's job gets nothing back.

    Since #362 there is a second thing the claim can refuse over: a job whose
    tenant has a scan policy is only handed to an agent that declares it can
    apply one. That check is after the row is selected rather than in the SQL
    on purpose — it is a property of the *agent*, and refusing it loudly is the
    point, where the group filter above is a property of the job and silently
    excluding it is correct.

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
                # An ungrouped agent takes only ungrouped jobs; a grouped one
                # takes its own group's and the ungrouped ones, so putting an
                # agent into a group narrows what it may reach without taking
                # away the queue it already served.
                models.Job.agent_group.is_(None)
                if not agent.agent_group
                else or_(
                    models.Job.agent_group.is_(None),
                    models.Job.agent_group == agent.agent_group,
                ),
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

        # A job whose tenant has a scan policy may only be handed to a worker
        # that can honour it (#362). The policy is applied by the executor —
        # the API cannot shape somebody else's packets — so an agent that does
        # not declare the ``scan_policy`` capability would run this scan at
        # whatever its local ``default.yaml`` says, which on a fragile estate
        # is the failure the policy exists to prevent.
        #
        # Refused rather than skipped over: skipping would leave the operator
        # with a queue that does not move and an agent that reports itself
        # healthy, while a 426 lands in that agent's own journal, keeps it
        # visible in the fleet view and names the upgrade — the same shape
        # #363 gives an agent below the version floor. The job stays queued
        # for a worker that can take it.
        if (row.scan_options or {}).get("scan_policy") and (
            scan_policy.AGENT_CAPABILITY not in (agent.capabilities or [])
        ):
            scan_policy.note_refusal("agent_unsupported")
            _log.warning(
                "Agent %s asked for job %s, whose tenant has a scan policy, but does not "
                "declare the %s capability; the job stays queued",
                agent_id,
                row.job_id,
                scan_policy.AGENT_CAPABILITY,
            )
            raise scan_policy.AgentPolicyUnsupported(
                f"agent {agent_id} does not support tenant scan policies "
                f"(capability {scan_policy.AGENT_CAPABILITY}); upgrade the agent — "
                "its jobs carry rate limits it cannot currently apply"
            )

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
            row.run_id = _mint_run_id()
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


def mark_running(settings: Settings, job_id: str, *, agent_id: str) -> bool:
    """Record an agent's heartbeat, and answer whether the job was cancelled.

    Three things ride on this one signal: a claimed job is promoted to running,
    an in-flight job's lease is pushed forward (P1.4) — the heartbeat is the
    only regular evidence the API gets that a remote worker is still alive —
    and, since #360, the reply carries the one instruction that travels the
    other way. The return value is ``True`` when an operator has asked for this
    job to stop and the agent holding it must put the scan down; the route puts
    it on the heartbeat response.

    Any other state is left alone: repeated heartbeats during a scan would
    otherwise attempt running → running, and a heartbeat arriving after the
    results upload must not resurrect a finished job. A heartbeat from an agent
    that does not hold the job is ignored outright — including the cancellation
    answer, which is an instruction about somebody else's work.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.assigned_agent_id != agent_id:
            return False
        if row.status == job_states.CANCELLING:
            # Repeated on every heartbeat until the agent confirms with a
            # cancelled upload: the answer to one heartbeat can be lost, and
            # the instruction has to survive that. No lease renewal — a
            # cancelling job is not in flight, and its clock is the grace
            # period in ``reap_stale_cancellations`` instead.
            return True
        if row.status not in job_states.IN_FLIGHT:
            return False
        _extend_lease(row, _lease_deadline(settings))
        if row.status != job_states.CLAIMED:
            return False
        row.status = job_states.RUNNING
        if row.started_at is None:
            row.started_at = _now()
    _refresh_job_gauges(settings)
    return False


def _stalled_ingest(settings: Settings, row: models.Job) -> bool:
    """Whether this row's open ingest has outlived the stop it is holding.

    An ingest marker is proof that an upload is being processed, and nothing
    clears it for a job that is already ``cancelling``: the lease reaper takes
    IN_FLIGHT rows only, and the process that would have cleared it is the one
    that died. Past the ingest lease the marker is no longer evidence of a
    confirmation in progress — it is the shape one left behind.

    The clock is ``job_ingest_lease_seconds``, not the cancellation grace: an
    upload is allowed to take the whole ingest lease (a branch office's uplink
    plus the extraction, which is what the sensor's own upload timeout is
    sized for), so a marker younger than that can be a live confirmation still
    inside its window. Dropping it would refuse that upload at the fence and
    take the partial archive with it. A marker left by a dead replica is older
    than the lease just as surely as it is older than the grace — the longer
    clock costs nothing but the wait.
    """
    if row.ingest_started_at is None:
        return False
    lease = timedelta(seconds=max(settings.job_ingest_lease_seconds, 1))
    return (_now() - row.ingest_started_at) > lease


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> JobInfo:
    """Stop a scan: refuse to hand it out, or ask the agent to put it down.

    Two outcomes, and which one an operator gets is a property of the job:

    - ``queued`` -> ``cancelled`` at once. Nothing has taken the job, so
      refusing to hand it out *is* the stop, and the answer is final.
    - ``claimed``/``running`` on an **agent** -> ``cancelling`` (#360). The
      instruction rides the next heartbeat, the agent signals its scanner's
      process group and uploads whatever the run produced as a cancelled
      result, and only that upload — or the grace period expiring in
      ``reap_stale_cancellations`` — writes the terminal state. The API says
      "stopping", not "stopped", because at this moment it has not been told
      the scan stopped.
    - ``cancelling`` -> itself, unchanged. The stop has been asked for and the
      clock on it is running; re-asking is not a second decision. A stale
      console, a second operator or a retried POST must not be able to
      terminalize a scan nobody has confirmed stopped. The one thing a
      deliberate second press does is drop an *abandoned* ingest hold — see
      the branch below — which returns the stop to the grace period it was
      promised instead of the ingest lease's much longer one.

    A ``running`` **local** job is still refused, and by execution rather than
    by state: its scanner is a ``subprocess`` in one replica's thread, which
    the replica handling this request may not be, so there is no signal to send
    and reporting a stop would be a lie. The message says so rather than
    reading as a generic lifecycle refusal.

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
        before = row.status
        if before == job_states.CANCELLING:
            # Idempotent, and deliberately *before* the transition table gets a
            # say: `cancelling` is not in IN_FLIGHT, so the target below would
            # be computed as `cancelled` — a legal move that would have the
            # API report a stop nobody confirmed, clear `cancel_requested`
            # before the agent has read it, and collapse the grace period to
            # nothing. Two consoles four seconds apart, or one proxy retry,
            # are enough to reach here; the answer is the job as it stands.
            #
            # With one exception, which is the only thing a second press can
            # usefully do: an ingest marker older than the grace period.
            # ``reap_stale_cancellations`` passes a stopping job over while an
            # ingest is open, and ``reap_expired_leases`` does not clear that
            # marker (it takes IN_FLIGHT rows only), so a replica killed in the
            # middle of a confirming upload holds the stop for the whole
            # ``job_ingest_lease_seconds`` — three times the grace an operator
            # was promised, with no way to say "I know, kill it". Dropping the
            # marker hands the row back to the reaper's ordinary clock.
            #
            # Bounded by the *ingest lease*, not by the grace period: an
            # upload younger than the lease is a confirmation still inside the
            # window the sensor was given, and is left alone so a slow branch
            # office does not lose the partial archive it is in the middle of
            # delivering. A marker a dead replica left behind is past the lease
            # too, so the longer clock only costs the wait.
            if _stalled_ingest(settings, row):
                _log.warning(
                    "Job %s is stopping with an ingest open since %s; %s asked again, so "
                    "the ingest hold is dropped and the stop falls back to the grace "
                    "period. An upload still in flight for it will be refused",
                    job_id,
                    row.ingest_started_at,
                    username,
                )
                row.ingest_token = None
                row.ingest_attempt = None
                row.ingest_agent_id = None
                row.ingest_started_at = None
                audit_service.record(
                    session,
                    audit,
                    action=audit_service.ACTION_SCAN_CANCEL,
                    resource_type="job",
                    resource_id=job_id,
                    tenant_id=job_tenant,
                    before={"status": before, "ingest_open": True},
                    after={"status": before, "ingest_open": False, "requested_by": username},
                )
                return _to_info(row)
            _log.info("Job %s is already stopping; %s's request is a no-op", job_id, username)
            result = _to_info(row)
            return result
        if before in job_states.IN_FLIGHT and row.execution != "agent":
            raise job_states.InvalidJobTransition(
                f"Job {job_id} is {before} in the API process itself; a local scan "
                "cannot be stopped once it has started, only an agent job can"
            )
        target = (
            job_states.CANCELLING if before in job_states.IN_FLIGHT else job_states.CANCELLED
        )
        job_states.check_transition(job_id, before, target)
        row.status = target
        if target == job_states.CANCELLING:
            row.cancel_requested_at = _now()
            # Cleared although the job is not terminal: the lease is what the
            # reaper requeues on, and a job on its way down must not be handed
            # to a second agent while the first is still stopping.
            row.claimed_until = None
            row.error = f"Cancellation requested by {username}"[:2000]
        else:
            row.finished_at = _now()
            row.claimed_until = None
            row.error = f"Cancelled by {username}"[:2000]
            metrics_service.JOB_CANCELLATIONS_TOTAL.labels(outcome="queued").inc()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCAN_CANCEL,
            resource_type="job",
            resource_id=job_id,
            tenant_id=job_tenant,
            before={"status": before, "assigned_agent_id": row.assigned_agent_id},
            after={"status": target, "requested_by": username},
        )
    _refresh_job_gauges(settings)
    result = get_job(settings, job_id)
    assert result is not None
    return result


def reap_stale_cancellations(settings: Settings) -> int:
    return job_reaper.reap_stale_cancellations(settings)


# Compatibility facade for the result-ingest API historically exposed by jobs.
ResultsConflict = job_results.ResultsConflict
ResultsInFlight = job_results.ResultsInFlight
StaleAttempt = job_results.StaleAttempt
LATE_ARCHIVE_RESERVATION = job_results.LATE_ARCHIVE_RESERVATION


def _release_results_reservation(*args, **kwargs) -> None:
    job_results._release_results_reservation(*args, **kwargs)


def _accepts_late_archive(*args, **kwargs):
    return job_results._accepts_late_archive(*args, **kwargs)


def _record_late_cancellation_archive(*args, **kwargs) -> None:
    job_results._record_late_cancellation_archive(*args, **kwargs)


def _classify_replay(*args, **kwargs):
    return job_results._classify_replay(*args, **kwargs)


def _merge_cancellation_reason(*args, **kwargs):
    return job_results._merge_cancellation_reason(*args, **kwargs)


def _release_ingest_lease(
    settings: Settings, fence: _IngestLease
) -> None:
    job_leases.release_ingest_lease(settings, fence)


def on_run_published(*args, **kwargs):
    return run_completion.on_run_published(*args, **kwargs)


def note_publication_failed(*args, **kwargs):
    return run_completion.note_publication_failed(*args, **kwargs)


def _project_ingested_run(*args, **kwargs):
    return run_completion.project_published_run(*args, **kwargs)


def _replayed(row: models.Job) -> JobInfo:
    return job_results._replayed(row)


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
    cancelled: bool = False,
) -> JobInfo:
    return job_results.complete_job(
        settings,
        job_id,
        agent_id=agent_id,
        exit_code=exit_code,
        error=error,
        run_id=run_id,
        archive_bytes=archive_bytes,
        tenant_id=tenant_id,
        idempotency_key=idempotency_key,
        attempt=attempt,
        cancelled=cancelled,
    )
