"""Post-run projections and completion side effects.

A job becoming terminal and a run becoming published are separate concerns.
This module owns the latter: derived inventory, vulnerability state, events,
notifications and scope-denial audit. Queue state remains in jobs.
"""

from __future__ import annotations

import json
import logging
import re

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
    """Add one line to a job's ``error``, without touching how it ended."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:  # pragma: no cover - the row was written moments ago
            return
        if note not in (row.error or ""):
            row.error = f"{row.error or ''}{note}"[:2000]


def _set_asset_upsert_error(settings: Settings, job_id: str, message: str) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is not None:
            row.asset_upsert_error = message[:2000]


def _requested_by(settings: Settings, job_id: str) -> str:
    """Who asked for this scan, or "" when the row is gone."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return (row.requested_by or "") if row is not None else ""


def upsert_assets_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort asset-registry upsert (Phase 7) — never fails the scan/upload.

    Covers both execution paths: local-mode scans land here from local_job_runner.run_job,
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
        _log.exception("Asset upsert failed for run %s (tenant=%s)", run_id, tenant_id)
        if job_id:
            _set_asset_upsert_error(
                settings, job_id, f"{type(exc).__name__}: {exc}"
            )


def track_vulnerabilities_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort fold of the run's findings into the tracker (#145).

    Runs after the asset upsert in both completion paths, and only for a
    *succeeded* run: a finding is attached to an asset, so the registry has to
    be current first, and a failed run's ``vulnerabilities.json`` may be a
    partial write from a scan that stopped mid-stage. Findings the tracker
    misses are not lost — the next successful scan observes them again.

    Quiet on failure, like the event publish and unlike the asset upsert: an
    un-tracked finding is still in the run's artifacts and in ClickHouse, so
    nothing is unrecoverable, whereas an empty asset list means the run
    produced no inventory at all.
    """
    if not run_id:
        return
    try:
        vulns_service.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)
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
    """Best-effort publish of the run's Phase 10.1 events (Phase 10.2).

    Called from the same two places as ``upsert_assets_best_effort`` and for
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
            run_dir=artifact_workspace.run_dir(settings, run_id, refresh=False),
            tenant_id=tenant_id,
            run_id=run_id,
            job_id=job_id,
            max_events=settings.asset_events_max_per_run,
            # Passed so an event the broker refuses is written to nats_outbox
            # rather than counted and forgotten: these events are the only
            # source of the webhook fan-out, and since NATS stopped deciding
            # readiness the upload is accepted during an outage that would
            # otherwise swallow them.
            settings=settings,
        )
    except Exception:  # noqa: BLE001
        _log.exception("Asset event publish failed for run %s (tenant=%s)", run_id, tenant_id)


def notify_channels_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Announce a finished run to the tenant's notification channels (#351).

    Called from the same two points as the asset-event publish above, and that
    is the fix: those are the only places where a finished run's artifacts are
    on disk *under a known tenant*. The alert used to be a scanner stage, which
    ran with installation-wide credentials and no tenant id at all, so on an
    MSSP installation every tenant's scan announced itself in one Slack channel.

    Quiet on failure like the event publish, and for a stronger reason: an
    unreachable Slack must not turn a successful scan into a failed job. The
    per-channel outcome is recorded on the channel row (``last_status``), which
    is where an operator looks when a channel goes silent.

    Asynchronous, unlike the hooks above it, because it is the only one that
    dials a third party. ``complete_job`` runs inside ``async def
    upload_results``, so a blocking send there stalls the API's event loop for
    the timeout budget of every channel in turn — see the note in
    ``channels.notify_run_complete_async``. The hooks above touch Postgres and
    the local NATS and are left alone.
    """
    if not run_id or not settings.notification_channels_enabled:
        return
    try:
        channels_service.notify_run_complete_async(
            tenant_id=tenant_id,
            run_id=run_id,
            run_dir=artifact_workspace.run_dir(settings, run_id, refresh=False),
        )
    except Exception:  # noqa: BLE001 - a thread that would not start
        _log.exception(
            "Notification fan-out failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def record_scope_denials_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, requested_by: str
) -> None:
    """Fold the scanner's own scope refusals into the access-decision journal (#244).

    The scanner drops a target that the tenant's approved scope refuses, but it
    runs on the agent's host with no database, no ``auth_events`` and no route
    to either — so it writes what it refused into ``scan_scope_denied.json`` and
    the decision is journalled here, where the run's artifacts land. Without
    this the refusals the *scanner* makes would be the only access decisions in
    the platform that leave no trail, and "who was stopped from scanning what"
    would have two answers depending on which barrier stopped them.

    Attributed to the job's requester, not to the agent: the agent executed a
    scan somebody else asked for, and it is the asker whose request was cut
    down. Called for a failed run too — a refusal happened whether or not the
    scan that followed it succeeded.

    Best-effort, like ``record_denial``: the scan is long over by the time this
    runs, and a lost journal write must not turn a completed upload into a 500.
    """
    if not run_id:
        return
    artifact = (
        artifact_workspace.run_dir(settings, run_id, refresh=False) / scan_scope.DENIED_ARTIFACT
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
        # An older agent, or a run the pipeline never got far enough to filter.
        return
    except Exception:  # noqa: BLE001 - see docstring
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
    """The projections themselves, each already guarded by its own helper."""
    upsert_assets_best_effort(settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id)
    # Ungated, matching the local path: this is where the agent's copy of the
    # run reaches disk, and a refusal the scanner made is a decision to journal
    # regardless of how the scan ended (#244).
    record_scope_denials_best_effort(
        settings,
        tenant_id=tenant_id,
        run_id=run_id,
        requested_by=_requested_by(settings, job_id),
    )
    # Gated on the outcome, matching the local path. An agent may attach
    # diagnostics to a *failed* run, and a partial diff read as a change set
    # would alert on hosts and ports that a broken scan simply failed to
    # observe — a disappearance is not a discovery.
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
    """Feed a *published* run to everything derived from it. Best-effort.

    Called by ``run_publisher`` the moment a run becomes visible — in the
    request that accepted the upload when the publication lands there, and
    from the reconciler when it lands later. Not by ``complete_job``: these
    read the run directory, so before the publication there is nothing to
    read, and a straggler refused at the terminal write never gets here at all
    because it never produced a publication.

    Nothing here may escape. The outcome is committed and the agent's retry is
    answered as a replay, so an exception would report a failure for a run the
    API has kept — and, on the reconciler's side, would fail a publication
    that has in fact landed and have it published a second time.
    """
    try:
        project_published_run(settings, job_id, run_id=run_id, tenant_id=tenant_id, status=status)
    except Exception as exc:  # pragma: no cover - each projection guards itself
        _log.error(
            "Job %s published run %s but it could not be projected",
            job_id,
            run_id,
            exc_info=True,
        )
        _append_job_error(settings, job_id, f"; run projections did not complete: {exc}")
    if status == job_states.SUCCEEDED:
        # Last, and only for a scan that finished: a partial or failed run
        # announced as a completed one is a notification about a scan that did
        # not happen. The send itself is on a thread, so this costs one
        # ``Thread.start``.
        notify_channels_best_effort(settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id)


def note_publication_failed(
    settings: Settings, job_id: str, *, publication_id: str, reason: str
) -> None:
    """Put a publication nobody is going to retry on the job itself.

    ``run_publications`` is where an operator finds the details, but the job
    is where they look first: a scan that reads ``succeeded`` with no
    artifacts behind it must say why on the row that claims it succeeded.
    """
    _append_job_error(
        settings,
        job_id,
        f"; run not published (publication {publication_id}): {reason}",
    )


def clear_publication_note(settings: Settings, job_id: str, *, publication_id: str) -> None:
    """Take a publication's "not published" note back off the job.

    Called when a publication that was once ``dead`` lands after all — the
    operator requeued it (#425). The note was true when it was written and is
    false now, and it sits on the one field the console paints red on a job
    that says ``succeeded``. Only this publication's note goes; anything else
    appended to ``error`` stays where it was.
    """
    pattern = re.compile(
        rf"; run not published \(publication {re.escape(publication_id)}\): .*?"
        r"(?=; run (?:not published \(publication |projections did not complete: )|$)",
        re.DOTALL,
    )
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None or not row.error:
            return
        cleaned = pattern.sub("", row.error)
        if cleaned != row.error:
            row.error = cleaned or None
