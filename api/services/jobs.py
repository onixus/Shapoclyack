"""Compatibility facade for scan jobs.

The job subsystem is split by invariant: admission, submission, repository,
state writes, agent control, leases/reaping, result ingestion, local execution
and post-run completion each live in their own service module. Routes and older
internal callers still import ``api.services.jobs``, so this module keeps those
names stable while delegating the implementation.

**A name here is not an interception point.** The implementation modules call
each other directly, so ``monkeypatch.setattr(jobs, "...")`` changes what *this
module's own callers* see and nothing else. Patch the owning module instead —
``run_completion.upsert_assets_best_effort``, ``job_store.update_job``,
``scan_admission.parse_target_payload`` and so on. The exceptions are
``_build_command``, ``_run_job`` and ``_publish_job_offer``: ``start_scan``
passes them into ``job_submission`` as arguments precisely so that replacing
them here still takes effect. Every other wrapper below exists because a caller
*calls* it, and wrappers nothing calls were deleted rather than left as traps —
patching a name that is gone raises, which is the outcome a test wants.

Do not add new policy or side-effect logic here. Put it in the owning service
and expose a wrapper only when an existing caller needs one.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.schemas import AgentClaimResponse, JobInfo, StartScanRequest
from api.services import audit as audit_service
from api.services import job_control
from api.services import job_dispatch
from api.services import job_inputs
from api.services import job_leases
from api.services import job_reaper
from api.services import job_repository
from api.services import job_results
from api.services import job_store
from api.services import job_submission
from api.services import local_job_runner
from api.services import local_scan_executor
from api.services import pagination
from api.services import run_completion
from api.services import run_ids
from api.settings import Settings

# Names for the scanner input contract. Layout ownership lives in job_inputs;
# aliasing here rather than restating the values keeps one copy of the list.
SCAN_SCOPE_INPUT = job_inputs.SCAN_SCOPE_INPUT
PROMOTED_DOMAINS_INPUT = job_inputs.PROMOTED_DOMAINS_INPUT
SCAN_POLICY_INPUT = job_inputs.SCAN_POLICY_INPUT

JOB_SORT_FIELDS = job_repository.JOB_SORT_FIELDS
JOB_QUERY_FIELDS = job_repository.JOB_QUERY_FIELDS
JOB_SORT_COLUMNS = job_repository.JOB_SORT_COLUMNS
SUMMARY_SURFACES = job_repository.SUMMARY_SURFACES

IdempotencyMismatch = job_submission.IdempotencyMismatch
IdempotentReplay = job_submission.IdempotentReplay
ResultsConflict = job_results.ResultsConflict
ResultsInFlight = job_results.ResultsInFlight
StaleAttempt = job_results.StaleAttempt
LATE_ARCHIVE_RESERVATION = job_results.LATE_ARCHIVE_RESERVATION

job_inputs_dir = job_inputs.job_inputs_dir
wordlist_file_for_job = job_inputs.wordlist_file_for_job

# The live registry itself, not a copy: a test that asserts the process table
# is empty after teardown is looking at local_scan_executor's own dict.
_local_scan_procs = local_scan_executor.processes


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def load_jobs(settings: Settings) -> None:
    job_repository.load_jobs(settings)


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
    return job_repository.list_jobs(
        settings,
        offset=offset,
        limit=limit,
        q=q,
        sort=sort,
        order=order,
        tenant_id=tenant_id,
        surface=surface,
    )


def summary(
    settings: Settings, *, tenant_id: str | None = None
) -> dict[str, Any]:
    return job_repository.summary(settings, tenant_id=tenant_id)


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    return job_repository.get_job(settings, job_id)


def reset_for_tests(settings: Settings) -> None:
    job_repository.reset_for_tests(settings)


def _update_job(*args, **kwargs) -> None:
    job_store.update_job(*args, **kwargs)


def force_status(
    settings: Settings, job_id: str, status: str, **fields: Any
) -> None:
    job_store.force_status(settings, job_id, status, **fields)


def publish_job_inputs(settings: Settings, job_id: str) -> None:
    job_inputs.publish(settings, job_id)


def ensure_job_inputs_local(settings: Settings, job_id: str) -> Path:
    return job_inputs.ensure_local(settings, job_id)


def _publish_asset_events_best_effort(*args, **kwargs):
    return run_completion.publish_asset_events_best_effort(*args, **kwargs)


def renew_lease(
    settings: Settings, job_id: str, *, agent_id: str | None = None
) -> bool:
    return job_leases.renew_lease(settings, job_id, agent_id=agent_id)


def reap_expired_leases(settings: Settings) -> dict[str, int]:
    return job_reaper.reap_expired_leases(settings)


def live_local_scans() -> list[str]:
    return local_scan_executor.live()


def stop_local_scans(timeout: float = 30.0) -> bool:
    return local_scan_executor.stop_all(timeout)


def _idempotency_digest(request: StartScanRequest) -> str:
    return job_submission.idempotency_digest(request)


def note_start_replay() -> None:
    job_submission.note_start_replay()


def find_by_idempotency_key(
    settings: Settings,
    *,
    tenant_id: str,
    key: str,
    request: StartScanRequest | None = None,
) -> JobInfo | None:
    return job_submission.find_by_idempotency_key(
        settings,
        tenant_id=tenant_id,
        key=key,
        request=request,
    )


def validate_run_id(value: str) -> str:
    return run_ids.validate(value)


# The three below are handed to job_submission.start_scan as arguments rather
# than called from inside it, so replacing them on this module still changes
# what a scan does. They are the only wrappers here with that property.
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
    return job_submission.build_command(
        settings,
        mode=mode,
        delta=delta,
        skip_nse=skip_nse,
        notify=notify,
        export_defectdojo=export_defectdojo,
        run_id=run_id,
        target_args=target_args,
        config_path=config_path,
    )


def _run_job(
    settings: Settings, job_id: str, command: list[str]
) -> None:
    local_job_runner.run_job(settings, job_id, command)


def _publish_job_offer(settings: Settings, job_id: str) -> None:
    job_dispatch.publish_offer(settings, job_id)


def start_scan(
    settings: Settings,
    request: StartScanRequest,
    *,
    username: str,
    idempotency_key: str | None = None,
    quota_exempt: bool = False,
    widen_with_promoted: bool = True,
) -> JobInfo:
    return job_submission.start_scan(
        settings,
        request,
        username=username,
        build_command=_build_command,
        run_local_job=_run_job,
        thread_factory=threading.Thread,
        publish_offer=_publish_job_offer,
        idempotency_key=idempotency_key,
        quota_exempt=quota_exempt,
        widen_with_promoted=widen_with_promoted,
    )


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


def on_run_published(*args, **kwargs):
    return run_completion.on_run_published(*args, **kwargs)


def note_publication_failed(*args, **kwargs):
    return run_completion.note_publication_failed(*args, **kwargs)


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
