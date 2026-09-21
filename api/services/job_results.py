"""Agent result ingestion and completion fencing.

This module owns the upload protocol after an agent has executed a job:
idempotency, late-cancellation archives, staging, ingest fencing and creation
of the durable run-publication intent. It deliberately does not own queue
admission or claiming.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo
from api.services import agents as agents_service
from api.services import job_inputs
from api.services import job_leases
from api.services import job_states
from api.services import job_store
from api.services import metrics as metrics_service
from api.services import results_ingest
from api.services import run_ids
from api.services import run_publisher
from api.services import tenants as tenants_service
from api.services.artifact_store import workspace as artifact_workspace
from api.settings import Settings

_log = logging.getLogger(__name__)


class ResultsConflict(ValueError):
    """A second upload for a finished job that is not a replay of the first."""


class ResultsInFlight(ResultsConflict):
    """A duplicate upload arrived while the first one is still being ingested."""


StaleAttempt = job_leases.StaleAttempt

LATE_ARCHIVE_RESERVATION = "late-archive:unkeyed"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _release_results_reservation(
    settings: Settings, job_id: str, key: str, *, late: bool = False
) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is not None and (late or row.status not in job_states.TERMINAL):
            if row.results_idempotency_key == key:
                row.results_idempotency_key = None


def _accepts_late_archive(
    settings: Settings,
    row: models.Job,
    *,
    cancelled: bool,
    has_archive: bool,
) -> bool:
    """Whether bytes may still be kept after cancellation was reaped."""
    if not (cancelled and has_archive):
        return False
    if (
        row.status != job_states.CANCELLED
        or row.cancel_requested_at is None
    ):
        return False
    if row.exit_code is not None or row.results_idempotency_key is not None:
        return False
    if row.finished_at is None:
        return False
    grace = max(settings.job_cancel_grace_seconds, 1)
    return (_now() - row.finished_at) <= timedelta(seconds=grace)


def _record_late_cancellation_archive(
    settings: Settings,
    job_id: str,
    *,
    agent_id: str,
    run_id: str | None,
    fence: job_leases.IngestLease,
    publication: models.RunPublication | None = None,
) -> None:
    """Keep a late partial archive without rewriting cancellation outcome."""
    note = f"; partial results uploaded late by agent {agent_id}"
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        job_leases.check_ingest_fence(row, fence)
        row.ingest_token = None
        row.ingest_attempt = None
        row.ingest_agent_id = None
        row.ingest_started_at = None
        if run_id and not row.run_id:
            row.run_id = run_id
        if note not in (row.error or ""):
            row.error = f"{row.error or ''}{note}"[:2000]
        if publication is not None:
            session.add(publication)
    _log.info(
        "Kept a late partial archive for cancelled job %s from agent %s; "
        "the job's outcome is unchanged",
        job_id,
        agent_id,
    )


def _replayed(row: models.Job) -> JobInfo:
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(
        operation="results"
    ).inc()
    _log.info(
        "Replayed results upload for job %s; returning the stored outcome",
        row.job_id,
    )
    return job_store.to_info(row)


def _classify_replay(
    row: models.Job,
    *,
    exit_code: int,
    idempotency_key: str | None,
) -> JobInfo | None:
    if row.status == job_states.CANCELLED:
        if (
            idempotency_key
            and row.results_idempotency_key == idempotency_key
        ):
            return _replayed(row)
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


def _merge_cancellation_reason(
    requested: str | None, reported: str | None
) -> str | None:
    merged = "; ".join(part for part in (requested, reported) if part)
    return merged[:2000] or None


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
    """Record one agent result upload with idempotency and attempt fencing."""
    replay_result: JobInfo | None = None
    late_archive = False
    fence: job_leases.IngestLease | None = None

    with get_session(settings.postgres_url) as session:
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
                f"Job {job_id} is on attempt {row.attempts}; "
                f"upload is from attempt {attempt}"
            )

        status = (
            job_states.SUCCEEDED
            if exit_code == 0
            else job_states.FAILED
        )
        if cancelled:
            status = (
                job_states.CANCELLED
                if row.status
                in (job_states.CANCELLING, job_states.CANCELLED)
                else status
            )

        if row.status in job_states.TERMINAL:
            replay = _classify_replay(
                row,
                exit_code=exit_code,
                idempotency_key=idempotency_key,
            )
            if replay is not None:
                replay_result = replay
            elif _accepts_late_archive(
                settings,
                row,
                cancelled=cancelled,
                has_archive=bool(archive_bytes),
            ):
                late_archive = True
                row.results_idempotency_key = (
                    idempotency_key or LATE_ARCHIVE_RESERVATION
                )
        elif idempotency_key:
            if row.results_idempotency_key == idempotency_key:
                raise ResultsInFlight(
                    "An upload with this key is already being processed "
                    f"for job {job_id}"
                )
            row.results_idempotency_key = idempotency_key

        if replay_result is None and not late_archive:
            job_states.check_transition(job_id, row.status, status)

        requested_reason = (
            row.error if status == job_states.CANCELLED else None
        )
        resolved_run_id = run_ids.confirm(row.run_id, run_id)
        job_surface = (row.scan_options or {}).get("surface")

        if replay_result is None:
            fence = job_leases.open_ingest_lease(
                settings, row, agent_id=agent_id
            )

    if replay_result is not None:
        job_inputs.discard(settings, job_id)
        return replay_result

    assert fence is not None
    staging: Path | None = None
    publication: models.RunPublication | None = None

    try:
        if archive_bytes:
            if not resolved_run_id:
                raise ValueError("run_id required when uploading results")
            staging = artifact_workspace.staging_run_dir(
                settings, str(resolved_run_id), fence.token
            )
            try:
                results_ingest.extract_run_archive(archive_bytes, staging)
            except results_ingest.IngestError as exc:
                raise ValueError(str(exc)) from exc

            artifact_workspace.stage_upload_archive(staging, archive_bytes)
            publication = run_publisher.new_publication(
                settings,
                publication_id=fence.token,
                job_id=job_id,
                run_id=str(resolved_run_id),
                tenant_id=job_tenant,
                job_status=status,
                agent_id=agent_id,
                exit_code=exit_code,
                scan_error=error,
                surface=job_surface,
                staging=staging,
            )

        if late_archive:
            _record_late_cancellation_archive(
                settings,
                job_id,
                agent_id=agent_id,
                run_id=(
                    str(resolved_run_id)
                    if resolved_run_id
                    else None
                ),
                fence=fence,
                publication=publication,
            )
        else:
            job_store.update_job(
                settings,
                job_id,
                fence=fence,
                publication=publication,
                status=status,
                finished_at=_now(),
                exit_code=exit_code,
                run_id=(
                    str(resolved_run_id)
                    if resolved_run_id
                    else None
                ),
                error=_merge_cancellation_reason(
                    requested_reason, error
                ),
                results_idempotency_key=(idempotency_key or None),
            )
    except Exception:
        if staging is not None:
            artifact_workspace.discard_staging(staging)
        held = idempotency_key or (
            LATE_ARCHIVE_RESERVATION if late_archive else None
        )
        if held:
            _release_results_reservation(
                settings, job_id, held, late=late_archive
            )
        job_leases.release_ingest_lease(settings, fence)
        raise

    if publication is not None:
        run_publisher.publish_now(settings, fence.token)

    if status == job_states.CANCELLED:
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(
            outcome=(
                "late_results"
                if late_archive
                else "confirmed"
            )
        ).inc()

    agents_service.touch_job(agent_id, None, status="idle")
    job_inputs.discard(settings, job_id)

    result = job_store.get_job(settings, job_id)
    assert result is not None
    return result
