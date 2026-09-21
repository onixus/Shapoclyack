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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import agent_groups as agent_groups_service
from api.services import artifact_store
from api.services import audit as audit_service
from api.services import config_override as config_override_service
from api.services.artifact_store import workspace as artifact_workspace
from api.services import job_states
from api.services import job_control
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
    return job_control._read_job_inputs(settings, job_id)


def apply_policy_to_queued(
    settings: Settings,
    *,
    tenant_id: str,
    resolved: dict[str, Any] | None,
) -> int:
    return job_control.apply_policy_to_queued(
        settings, tenant_id=tenant_id, resolved=resolved
    )


def claim_job(
    settings: Settings,
    agent_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
) -> AgentClaimResponse | None:
    return job_control.claim_job(
        settings,
        agent_id,
        job_id=job_id,
        tenant_id=tenant_id,
    )


def mark_running(
    settings: Settings, job_id: str, *, agent_id: str
) -> bool:
    return job_control.mark_running(settings, job_id, agent_id=agent_id)


def _stalled_ingest(settings: Settings, row: models.Job) -> bool:
    return job_control._stalled_ingest(settings, row)


def cancel_job(
    settings: Settings,
    job_id: str,
    *,
    username: str,
    tenant_id: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> JobInfo:
    return job_control.cancel_job(
        settings,
        job_id,
        username=username,
        tenant_id=tenant_id,
        audit=audit,
    )


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
