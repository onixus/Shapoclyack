"""Persistence boundary for job state and API snapshots.

All lifecycle writes pass through this module so state-machine validation,
ingest fencing, terminal lease cleanup, metrics and failure events stay one
atomic policy instead of being reimplemented by every workflow.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo
from api.services import job_leases
from api.services import job_states
from api.services import metrics as metrics_service
from api.services import tenants as tenants_service
from api.services import workflow_events
from api.settings import Settings


def _iso(dt: datetime | None) -> str | None:
    return dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if dt else None


def to_info(row: models.Job, live_groups: set[tuple[str, str]] | None = None) -> JobInfo:
    """One job row as the API reports it.

    ``live_groups`` is the ``(tenant, group)`` pairs that have an agent able to
    take a job right now — see ``agent_groups.live_groups``. Passed in by the
    read paths that render a queue so one query answers a whole page; ``None``
    from the write paths, which report the job they just changed and make no
    claim about who is listening.
    """
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
        scan_options=dict(row.scan_options) if row.scan_options else None,
        surface=(row.scan_options or {}).get("surface"),
        surface_source=(row.scan_options or {}).get("surface_source"),
        agent_group=row.agent_group,
        # Answered now, not at queue time: a job addressed to a group whose
        # only agent was restarting when it was queued is claimable the moment
        # that agent is back, and a flag frozen at queue time went on saying
        # "nothing can execute this" for the rest of the job's life. Only for a
        # job still waiting — once one is claimed, who was listening an hour
        # ago is not a thing to report.
        agent_group_unavailable=(
            bool(row.agent_group)
            and row.status == job_states.QUEUED
            and live_groups is not None
            and (row.tenant_id or tenants_service.DEFAULT_TENANT_ID, row.agent_group)
            not in live_groups
        ),
    )


def scan_failure_event(row: models.Job) -> dict[str, Any]:
    """``workflow_events.emit`` keyword arguments for one failed job (#349).

    ``marker`` is the attempt count, not the job id alone: an agent job whose
    lease expired is requeued and may fail again on a later attempt, and those
    are two failures somebody has to hear about separately. The error string
    is truncated because it is a scanner's stderr and ends up in a webhook
    payload column.
    """
    return {
        "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        "subject_id": row.job_id,
        "marker": str(row.attempts or 0),
        "data": {
            "job_id": row.job_id,
            "run_id": row.run_id,
            "execution": row.execution,
            "mode": row.mode,
            # The scan's surface, not its target list: a target list can be a
            # /16 and this payload is stored per delivery.
            "surface": (row.scan_options or {}).get("surface"),
            "attempts": row.attempts,
            "assigned_agent_id": row.assigned_agent_id,
            "exit_code": row.exit_code,
            "requested_by": row.requested_by,
            "error": (row.error or "")[:1000] or None,
        },
    }


def refresh_job_gauges(settings: Settings) -> None:
    """Publish queued/running counts.

    These are now counted in the shared table rather than per-process, so two
    replicas no longer report two different queue depths for the same queue —
    one of the known gaps called out in docs/slo.md.

    ``claimed`` (P1.3) counts as running: the job is out with a worker and no
    longer waiting, so folding it into the queue depth would read as a backlog
    that nothing is working on. ``cancelling`` (#360) counts as running for the
    same reason — the agent is still busy with it until it confirms — even
    though it is deliberately outside ``IN_FLIGHT``, which is the lease set.
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
    metrics_service.JOBS_RUNNING.set(
        sum(
            counts.get(state, 0)
            for state in (*job_states.IN_FLIGHT, job_states.CANCELLING)
        )
    )


def record_job_metrics(
    settings: Settings,
    status: str,
    execution: str,
    started_at: datetime | None,
    finished_at: datetime | None,
) -> None:
    if status in {job_states.SUCCEEDED, job_states.FAILED} and started_at and finished_at:
        duration = (finished_at - started_at).total_seconds()
        if duration >= 0:
            metrics_service.JOB_DURATION_SECONDS.labels(
                status=status,
                execution=execution or "local",
            ).observe(duration)
    refresh_job_gauges(settings)


def update_job(
    settings: Settings,
    job_id: str,
    *,
    fence: job_leases.IngestLease | None = None,
    publication: models.RunPublication | None = None,
    **fields: Any,
) -> None:
    """Apply ``fields`` to a job row, validating any status change.

    Validation lives here rather than at each call site so a future writer
    cannot reintroduce a bare assignment: every path that moves a job — local
    executor, agent claim, result upload, restart reconciliation, cancel — goes
    through this function. Use ``force_status`` for the rare repair/test case
    that must ignore the lifecycle.

    ``fence`` is the ingest lease the caller has been holding while it did the
    long work outside this transaction. Given one, the write happens only if
    the row is still that lease's — checked under the same lock as the
    transition, because "is this attempt still current" and "is this move
    legal" have to be answered against one state of the row, not two.

    ``publication`` is the run this outcome accepted, and it is inserted in
    *this* transaction on purpose: an upload the fence refuses raises above
    and leaves no row, and an upload that is accepted leaves one that outlives
    the request. Making the run visible is then a retryable consequence of the
    outcome rather than something ordered around it — see
    ``api/services/run_publisher.py``.
    """
    with get_session(settings.postgres_url) as session:
        # Locked, not just read: two writers racing on one job (an operator
        # cancelling while the local executor starts it, say) would otherwise
        # both validate against the same stale status and the later commit
        # would win regardless of what the earlier one decided.
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        if fence is not None:
            job_leases.check_ingest_fence(row, fence)
            # The lease is spent by the write it authorised.
            fields.setdefault("ingest_token", None)
            fields.setdefault("ingest_attempt", None)
            fields.setdefault("ingest_agent_id", None)
            fields.setdefault("ingest_started_at", None)
        if "status" in fields:
            job_states.check_transition(job_id, row.status, str(fields["status"]))
            if fields["status"] in job_states.TERMINAL:
                # A finished job holds no lease. Cleared here rather than at
                # each terminal call site so the reaper can never see a
                # leftover deadline on a row it has no business touching.
                fields.setdefault("claimed_until", None)
        for key, value in fields.items():
            setattr(row, key, value)
        if publication is not None:
            session.add(publication)
        session.flush()
        snapshot = (
            (row.status, row.execution, row.started_at, row.finished_at)
            if "status" in fields
            else None
        )
        # Snapshotted here rather than re-read after the commit: the row is
        # loaded and locked, and a job that failed is terminal, so this is the
        # one moment it moved into ``failed``.
        failure = (
            scan_failure_event(row)
            if fields.get("status") == job_states.FAILED
            else None
        )
    if snapshot is not None:
        record_job_metrics(settings, *snapshot)
    if failure is not None:
        # After the commit: an event announcing a failure that then rolled back
        # would be a notification about something that did not happen (#349).
        workflow_events.emit(settings, "scan_failed", **failure)


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
    refresh_job_gauges(settings)
