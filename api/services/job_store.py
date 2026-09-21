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
    return (
        dt.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")
        if dt
        else None
    )


def to_info(
    row: models.Job,
    live_groups: set[tuple[str, str]] | None = None,
) -> JobInfo:
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
        agent_group_unavailable=(
            bool(row.agent_group)
            and row.status == job_states.QUEUED
            and live_groups is not None
            and (
                row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
                row.agent_group,
            )
            not in live_groups
        ),
    )


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return to_info(row) if row is not None else None


def scan_failure_event(row: models.Job) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id or tenants_service.DEFAULT_TENANT_ID,
        "subject_id": row.job_id,
        "marker": str(row.attempts or 0),
        "data": {
            "job_id": row.job_id,
            "run_id": row.run_id,
            "execution": row.execution,
            "mode": row.mode,
            "surface": (row.scan_options or {}).get("surface"),
            "attempts": row.attempts,
            "assigned_agent_id": row.assigned_agent_id,
            "exit_code": row.exit_code,
            "requested_by": row.requested_by,
            "error": (row.error or "")[:1000] or None,
        },
    }


def refresh_job_gauges(settings: Settings) -> None:
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
    """Apply a lifecycle write under row lock and optional ingest fence."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        if fence is not None:
            job_leases.check_ingest_fence(row, fence)
            fields.setdefault("ingest_token", None)
            fields.setdefault("ingest_attempt", None)
            fields.setdefault("ingest_agent_id", None)
            fields.setdefault("ingest_started_at", None)

        if "status" in fields:
            job_states.check_transition(
                job_id, row.status, str(fields["status"])
            )
            if fields["status"] in job_states.TERMINAL:
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
        failure = (
            scan_failure_event(row)
            if fields.get("status") == job_states.FAILED
            else None
        )

    if snapshot is not None:
        record_job_metrics(settings, *snapshot)
    if failure is not None:
        workflow_events.emit(settings, "scan_failed", **failure)


def force_status(
    settings: Settings, job_id: str, status: str, **fields: Any
) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        row.status = status
        for key, value in fields.items():
            setattr(row, key, value)
    refresh_job_gauges(settings)
