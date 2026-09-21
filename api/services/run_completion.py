"""Post-run projections and completion side effects.

A job becoming terminal and a run becoming published are separate concerns.
This module owns the latter: derived inventory, vulnerability state, events,
notifications and scope-denial audit. Queue state remains in jobs.
"""

from __future__ import annotations

import json
import logging

from api.db import models
from api.db.engine import get_session
from api.services import asset_events
from api.services import assets as assets_service
from api.services import auth_audit
from api.services import job_states
from api.services import vulnerabilities as vulns_service
from api.services.artifact_store import workspace as artifact_workspace
from api.services.integrations import channels as channels_service
from api.settings import Settings
from scanner.pipeline import scan_scope

_log = logging.getLogger(__name__)


def _append_job_error(settings: Settings, job_id: str, note: str) -> None:
    """Append diagnostic text without changing a job's terminal outcome."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:
            return
        if note not in (row.error or ""):
            row.error = f"{row.error or ''}{note}"[:2000]


def _set_asset_upsert_error(settings: Settings, job_id: str, message: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is not None:
            row.asset_upsert_error = message[:2000]


def _requested_by(settings: Settings, job_id: str) -> str:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return (row.requested_by or "") if row is not None else ""


def upsert_assets_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    if not run_id:
        return
    try:
        assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id=run_id)
    except Exception as exc:  # noqa: BLE001
        _log.exception("Asset upsert failed for run %s (tenant=%s)", run_id, tenant_id)
        if job_id:
            _set_asset_upsert_error(
                settings, job_id, f"{type(exc).__name__}: {exc}"
            )


def track_vulnerabilities_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    if not run_id:
        return
    try:
        vulns_service.register_findings_from_run(
            settings, tenant_id=tenant_id, run_id=run_id
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "Vulnerability tracking failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def publish_asset_events_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    if not run_id or not settings.asset_events_enabled or not settings.nats_url:
        return
    try:
        asset_events.publish_run_events(
            nats_url=settings.nats_url,
            run_dir=artifact_workspace.run_dir(settings, run_id, refresh=False),
            tenant_id=tenant_id,
            run_id=run_id,
            job_id=job_id,
            max_events=settings.asset_events_max_per_run,
            settings=settings,
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "Asset event publish failed for run %s (tenant=%s)", run_id, tenant_id
        )


def notify_channels_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    if not run_id or not settings.notification_channels_enabled:
        return
    try:
        channels_service.notify_run_complete_async(
            tenant_id=tenant_id,
            run_id=run_id,
            run_dir=artifact_workspace.run_dir(settings, run_id, refresh=False),
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "Notification fan-out failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def record_scope_denials_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, requested_by: str
) -> None:
    """Journal targets the scanner itself rejected from the approved scope."""
    if not run_id:
        return
    artifact = (
        artifact_workspace.run_dir(settings, run_id, refresh=False)
        / scan_scope.DENIED_ARTIFACT
    )
    try:
        report = json.loads(artifact.read_text(encoding="utf-8"))
        denied = [str(item) for item in (report.get("denied") or [])]
        if not denied:
            return
        auth_audit.record_denied(
            username=requested_by or "scanner",
            reason=auth_audit.REASON_SCAN_SCOPE,
            detail=f"tenant={tenant_id} run={run_id} dropped by the scanner: "
            f"{', '.join(denied[:8])}"[:1000],
        )
    except FileNotFoundError:
        return
    except Exception:  # noqa: BLE001
        _log.exception(
            "Failed to record scanner scan-scope denials for run %s (tenant=%s)",
            run_id,
            tenant_id,
        )


def project_published_run(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    status: str,
) -> None:
    """Project one published run into the control-plane read models."""
    upsert_assets_best_effort(
        settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
    )
    record_scope_denials_best_effort(
        settings,
        tenant_id=tenant_id,
        run_id=run_id,
        requested_by=_requested_by(settings, job_id),
    )
    if status == job_states.SUCCEEDED:
        track_vulnerabilities_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        )
        publish_asset_events_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        )


def on_run_published(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    status: str,
) -> None:
    """Feed a published run to all derived projections. Never escapes."""
    try:
        project_published_run(
            settings,
            job_id,
            run_id=run_id,
            tenant_id=tenant_id,
            status=status,
        )
    except Exception as exc:  # pragma: no cover - helpers guard themselves
        _log.error(
            "Job %s published run %s but it could not be projected",
            job_id,
            run_id,
            exc_info=True,
        )
        _append_job_error(
            settings, job_id, f"; run projections did not complete: {exc}"
        )
    if status == job_states.SUCCEEDED:
        notify_channels_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        )


def note_publication_failed(
    settings: Settings, job_id: str, *, publication_id: str, reason: str
) -> None:
    """Surface a permanently failed publication on the job drawer."""
    _append_job_error(
        settings,
        job_id,
        f"; run not published (publication {publication_id}): {reason}",
    )
