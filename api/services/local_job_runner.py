"""Execution wrapper for scans run inside the API process.

The process mechanics live in local_scan_executor. This module owns the job
state transitions and post-run bookkeeping around that process.
"""

from __future__ import annotations

import json
import logging

from api.services import artifact_store
from api.services import job_inputs
from api.services import job_leases
from api.services import job_repository
from api.services import job_states
from api.services import job_store
from api.services import local_scan_executor
from api.services import run_completion
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services.artifact_store import workspace as artifact_workspace
from api.settings import Settings

_log = logging.getLogger(__name__)


def run_job(
    settings: Settings, job_id: str, command: list[str]
) -> None:
    """Execute one local scan and account for its terminal outcome."""
    try:
        job_store.update_job(
            settings,
            job_id,
            status=job_states.RUNNING,
            started_at=job_repository._now(),
            claimed_until=job_leases.lease_deadline(settings),
            attempts=1,
        )
    except job_states.InvalidJobTransition as exc:
        _log.info("Not starting job %s: %s", job_id, exc)
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
        return

    try:
        with job_leases.renewing_lease(settings, job_id):
            completed = local_scan_executor.run_scanner(
                job_id, command
            )

        run_id = None
        pointer = settings.state_dir / "latest_run.json"
        if pointer.exists():
            try:
                run_id = json.loads(
                    pointer.read_text(encoding="utf-8")
                ).get("run_id")
            except json.JSONDecodeError:
                run_id = None

        status = (
            job_states.SUCCEEDED
            if completed.returncode == 0
            else job_states.FAILED
        )
        error = None
        if completed.returncode != 0:
            error = (
                completed.stderr
                or completed.stdout
                or f"exit {completed.returncode}"
            )[:2000]

        job_store.update_job(
            settings,
            job_id,
            status=status,
            finished_at=job_repository._now(),
            exit_code=completed.returncode,
            run_id=str(run_id) if run_id else None,
            error=error,
        )

        job = job_repository.get_job(settings, job_id)
        tenant_id = (
            job.tenant_id
            if job
            else tenants_service.DEFAULT_TENANT_ID
        )
        run_completion.record_scope_denials_best_effort(
            settings,
            tenant_id=tenant_id,
            run_id=str(run_id) if run_id else None,
            requested_by=job.requested_by if job else "",
        )

        if run_id:
            try:
                artifact_workspace.adopt_local_run(
                    settings,
                    str(run_id),
                    settings.output_dir / "runs" / str(run_id),
                )
            except artifact_store.ArtifactStoreError:
                _log.exception(
                    "Could not publish run %s to the artifact store",
                    run_id,
                )

        if status == job_states.SUCCEEDED:
            if run_id:
                runs_service.write_run_tenant(
                    settings,
                    str(run_id),
                    tenant_id,
                    job_id=job_id,
                    surface=(
                        (job.scan_options or {}).get("surface")
                        if job
                        else None
                    ),
                )

            run_completion.upsert_assets_best_effort(
                settings,
                tenant_id=tenant_id,
                run_id=str(run_id) if run_id else None,
                job_id=job_id,
            )
            run_completion.track_vulnerabilities_best_effort(
                settings,
                tenant_id=tenant_id,
                run_id=str(run_id) if run_id else None,
                job_id=job_id,
            )
            run_completion.publish_asset_events_best_effort(
                settings,
                tenant_id=tenant_id,
                run_id=str(run_id) if run_id else None,
                job_id=job_id,
            )
            run_completion.notify_channels_best_effort(
                settings,
                tenant_id=tenant_id,
                run_id=str(run_id) if run_id else None,
                job_id=job_id,
            )

    except Exception as exc:  # noqa: BLE001
        _log.exception("Scan job %s failed", job_id)
        try:
            job_store.update_job(
                settings,
                job_id,
                status=job_states.FAILED,
                finished_at=job_repository._now(),
                error=str(exc)[:2000],
            )
        except job_states.InvalidJobTransition:
            job_store.update_job(
                settings, job_id, error=str(exc)[:2000]
            )
    finally:
        job_inputs.discard_wordlist(settings, job_id)
        job_inputs.discard(settings, job_id)
