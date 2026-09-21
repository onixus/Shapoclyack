"""Compatibility facade for scan jobs.\n\nThe job subsystem is split by invariant: admission, submission, repository,\nstate writes, agent control, leases/reaping, result ingestion, local execution\nand post-run completion each live in their own service module. Routes and older\ninternal callers still import ``api.services.jobs`` so this module keeps those\npublic and test-facing names stable while delegating the implementation.\n\nDo not add new policy or side-effect logic here. Put it in the owning service\nand expose a compatibility wrapper only when an existing caller needs one.\n"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


from api.db import models
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
    return job_repository._parse_iso(value)


JOB_SORT_FIELDS = job_repository.JOB_SORT_FIELDS
JOB_QUERY_FIELDS = job_repository.JOB_QUERY_FIELDS
JOB_SORT_COLUMNS = job_repository.JOB_SORT_COLUMNS
SUMMARY_SURFACES = job_repository.SUMMARY_SURFACES


def load_jobs(settings: Settings) -> None:
    job_repository.load_jobs(settings)


def _import_legacy_jobs(settings: Settings, path: Path) -> None:
    job_repository._import_legacy_jobs(settings, path)


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


def _live_groups_for(
    settings: Settings, rows: Sequence[models.Job]
) -> set[tuple[str, str]] | None:
    return job_repository._live_groups_for(settings, rows)


def get_job(settings: Settings, job_id: str) -> JobInfo | None:
    return job_repository.get_job(settings, job_id)


def reset_for_tests(settings: Settings) -> None:
    job_repository.reset_for_tests(settings)


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


def _run_job(
    settings: Settings, job_id: str, command: list[str]
) -> None:
    local_job_runner.run_job(settings, job_id, command)


_IDEMPOTENCY_FIELDS = job_submission._IDEMPOTENCY_FIELDS
_IDEMPOTENCY_TARGET_FIELDS = job_submission._IDEMPOTENCY_TARGET_FIELDS
IdempotencyMismatch = job_submission.IdempotencyMismatch
IdempotentReplay = job_submission.IdempotentReplay


def _normalised_target_text(text: str | None) -> str | None:
    return job_submission._normalised_target_text(text)


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


def _mint_run_id() -> str:
    return run_ids.mint()


def validate_run_id(value: str) -> str:
    return run_ids.validate(value)


def _confirm_run_id(
    expected: str | None, offered: str | None
) -> str | None:
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
