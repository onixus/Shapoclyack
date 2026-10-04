"""Post-run projections and completion side effects.

A job becoming terminal and a run becoming published are separate concerns.
This module owns the latter: derived inventory, vulnerability state, events,
notifications and scope-denial audit. Queue state remains in jobs.

Which of those a run feeds is decided here once, by outcome, for both
execution paths (:data:`POST_PUBLICATION`, #454); the local executor and the
sensor upload are only two ways of producing a ``run_publications`` row.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services import asset_services
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


def _written_run_dir(settings: Settings, run_id: str, tenant_id: str) -> Path | None:
    """This job's run on this pod, wherever it landed (``workspace.locate_written``).

    ``None`` when the only run under this id is another tenant's. Not
    refreshed: every caller runs straight after the run was written here.
    """
    try:
        ref = artifact_workspace.locate_written(settings, run_id, tenant_id)
    except (ValueError, artifact_store.ArtifactStoreError):
        # Fail-soft like every hook here: an id that is not a run id, or a
        # store that cannot answer, costs the hooks their input, not the job.
        _log.warning("Could not locate run %s for tenant %s", run_id, tenant_id, exc_info=True)
        return None
    if ref is None:
        return None
    return artifact_workspace.run_dir(settings, ref, refresh=False)


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


def _job_finished_at(settings: Settings, job_id: str | None) -> datetime | None:
    """When the job that produced a run finished, or ``None`` when unknown."""
    if not job_id:
        return None
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return row.finished_at if row is not None else None


def _requested_by(settings: Settings, job_id: str) -> str:
    """Who asked for this scan, or "" when the row is gone."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        return (row.requested_by or "") if row is not None else ""


def upsert_assets_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort asset-registry upsert (Phase 7) — never fails the scan/upload.

    Covers both execution paths: a local scan and a sensor's upload both reach
    it through :func:`on_run_published` once their publication has landed, and
    only for a succeeded run (:data:`POST_PUBLICATION`).

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


def record_services_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort record of the run's service fingerprints (retro matching).

    After the vulnerability fold and only for a *succeeded* run, for the same
    two reasons: a fingerprint hangs off an asset, which the upsert above has
    just written, and a failed run may have stopped halfway through the probe
    stage and would record an older version of a listener as its newest.

    Quiet on failure like the fold: a listener this misses is still in the run
    directory, the next scan records it, and the backfill script can re-read
    any run still on disk (docs/retro-cve-matching.md).
    """
    if not run_id:
        return
    try:
        asset_services.record_run(
            settings,
            tenant_id=tenant_id,
            run_id=run_id,
            # When the scan finished, not when its publication landed: the
            # reconciler can publish a run hours late, and "now" would let that
            # run's fingerprints overwrite a newer scan's.
            observed_at=_job_finished_at(settings, job_id),
        )
    except Exception:  # noqa: BLE001
        _log.exception(
            "Service fingerprint recording failed for run %s (tenant=%s, job=%s)",
            run_id,
            tenant_id,
            job_id,
        )


def publish_asset_events_best_effort(
    settings: Settings, *, tenant_id: str, run_id: str | None, job_id: str | None = None
) -> None:
    """Best-effort publish of the run's Phase 10.1 events (Phase 10.2).

    Called from :func:`on_run_published`, like ``upsert_assets_best_effort``
    and for the same reason — a published run is the only point where a
    finished run's artifacts are on disk under a known tenant, whether the scan
    ran locally or came up from an agent.

    Deliberately quieter than the asset upsert on failure: an empty asset list
    is a broken installation worth recording on the job, while an unpublished
    event is a missed notification whose payload is still in ``diff.json``.
    """
    if not run_id or not settings.asset_events_enabled or not settings.nats_url:
        return
    run_dir = _written_run_dir(settings, run_id, tenant_id)
    if run_dir is None:
        return
    try:
        asset_events.publish_run_events(
            nats_url=settings.nats_url,
            run_dir=run_dir,
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

    Called from the same point as the asset-event publish above, and that is
    the fix: a published run is the only place where a finished run's
    artifacts are on disk *under a known tenant*. The alert used to be a scanner stage, which
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
    run_dir = _written_run_dir(settings, run_id, tenant_id)
    if run_dir is None:
        return
    try:
        channels_service.notify_run_complete_async(
            tenant_id=tenant_id,
            run_id=run_id,
            run_dir=run_dir,
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
    try:
        run_dir = _written_run_dir(settings, run_id, tenant_id)
        if run_dir is None:
            return
        artifact = run_dir / scan_scope.DENIED_ARTIFACT
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


#: The derived updates a published run can feed, in the order they run. The
#: order is load-bearing: a finding and a service fingerprint attach to an
#: asset, so the registry is current first; the events read the tracker the
#: fold has just updated (retro announcements); the notification describes the
#: registry and the tracker as they are *after* everything above it.
SCOPE_DENIALS = "scope_denials"
ASSETS = "assets"
FINDINGS = "findings"
SERVICES = "services"
EVENTS = "events"
NOTIFY = "notify"

#: What a published run feeds, by the outcome committed beside it (#454).
#: One table for both execution paths: a local run and a sensor's upload
#: reach :func:`on_run_published` through the same ``run_publications`` row,
#: and nothing else in the codebase decides which of these run.
#:
#: Only a *succeeded* run is evidence of absence and of coverage. A failed or
#: cancelled scan — and a partial archive, which is one of those two — may
#: have stopped anywhere: its ``diff.json`` would announce as gone what it
#: never reached, its ``vulnerabilities.json`` may be a partial write, and its
#: host list would stamp ``last_scanned_at``/``last_vuln_scan_at`` on hosts it
#: did not finish with and feed identity merges from half a certificate sweep.
#: So it feeds nothing derived — not even the asset registry, which the sensor
#: path used to upsert from such a run while the local path did not; the run
#: itself stays published and readable, and the next complete scan observes
#: the same hosts. The scanner's scope refusals are journalled whatever the
#: outcome: a target refused was refused whether or not the scan after it
#: finished (#244).
POST_PUBLICATION: dict[str, tuple[str, ...]] = {
    job_states.SUCCEEDED: (SCOPE_DENIALS, ASSETS, FINDINGS, SERVICES, EVENTS, NOTIFY),
    job_states.FAILED: (SCOPE_DENIALS,),
    job_states.CANCELLED: (SCOPE_DENIALS,),
}


def actions_for(status: str) -> tuple[str, ...]:
    """The derived updates owed to a run published with ``status``.

    An outcome the table does not name gets the journal only: a status added
    later must opt into feeding derived state, not inherit it by accident.
    """
    return POST_PUBLICATION.get(status, (SCOPE_DENIALS,))


def project_published_run(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    status: str,
) -> None:
    """The Postgres and broker projections of :data:`POST_PUBLICATION`.

    Everything but the notification, which :func:`on_run_published` sends
    last. Each step guards itself, so one that fails costs only itself.
    """
    steps = {
        SCOPE_DENIALS: lambda: record_scope_denials_best_effort(
            settings,
            tenant_id=tenant_id,
            run_id=run_id,
            requested_by=_requested_by(settings, job_id),
        ),
        ASSETS: lambda: upsert_assets_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        ),
        FINDINGS: lambda: track_vulnerabilities_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        ),
        SERVICES: lambda: record_services_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        ),
        EVENTS: lambda: publish_asset_events_best_effort(
            settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id
        ),
    }
    for action in actions_for(status):
        if action in steps:
            steps[action]()


def on_run_published(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    status: str,
) -> None:
    """Feed a *published* run to everything derived from it. Best-effort.

    The one owner of the post-publication sequence, for both execution paths
    (#454): ``run_publisher`` calls it once a run's publication has landed —
    the sensor's upload and, since #454, a local scan's directory alike — and
    nothing else does. Not ``complete_job`` and not the local executor: these
    read the run directory, so before the publication there is nothing to
    read, and a straggler refused at the terminal write never gets here at all
    because it never produced a publication.

    **At least once, made safe by idempotency.** The publisher runs this
    *before* it closes the publication's row, so a replica killed in between
    leaves a row that is published again and fed again — rather than a run
    whose derived state was simply never written. Each step therefore treats
    a second pass over the same run as the same facts: the asset upsert and
    the service fingerprints converge, the vulnerability fold does not count
    an observation it has already counted for this run, and asset events carry
    a content-derived ``Msg-Id`` the broker deduplicates. The notification and
    the scope-denial journal are the two that can repeat on that path; neither
    is promised exactly-once (docs/architecture.md).

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
    if NOTIFY in actions_for(status):
        # Last, and only for a scan that finished: a partial or failed run
        # announced as a completed one is a notification about a scan that did
        # not happen. The send itself is on a thread, so this costs one
        # ``Thread.start``.
        notify_channels_best_effort(settings, tenant_id=tenant_id, run_id=run_id, job_id=job_id)


#: Every prefix a note appended to ``jobs.error`` starts with — what ends the
#: note before it. A new ``_append_job_error``-style writer adds its prefix
#: here, or a cleared publication note swallows it.
_NOTE_PREFIXES = (
    "; run not published (publication ",
    "; run projections did not complete: ",
    "; partial results uploaded late by agent ",
    "; run not filed under its tenant: ",
)

_ADOPTION_NOTE_PREFIX = "; run not filed under its tenant: "


def note_adoption_failed(settings: Settings, job_id: str, detail: str) -> None:
    """Say on the job that its local scan did not reach its tenant's run (#427).

    The run is on disk, but not (all) where readers look for it; the pod log
    alone would leave the job reading as a clean success.
    """
    _append_job_error(settings, job_id, f"{_ADOPTION_NOTE_PREFIX}{detail}")


def _publication_note_prefix(publication_id: str) -> str:
    return f"; run not published (publication {publication_id}): "


def note_publication_failed(session, job_id: str, *, publication_id: str, reason: str) -> None:
    """Put a publication nobody is going to retry on the job itself.

    ``run_publications`` is where an operator finds the details, but the job
    is where they look first: a scan that reads ``succeeded`` with no
    artifacts behind it must say why on the row that claims it succeeded.

    Written in the caller's session — the transaction that ends the row
    ``dead``, which holds the row's lock — so the note and the death are one
    fact. Written after it, in a session of its own, the note could land after
    a peer that was still publishing had succeeded, found no error on the row
    and left nothing to clear: a published run whose job said it was not
    (:func:`clear_publication_notes`).

    ``;`` in the reason becomes ``,``. Every note on ``error`` starts with
    ``; `` and the named reasons carry ``;`` of their own, so without this the
    note had no end a later clear could find, and took whatever was appended
    after it along with it.
    """
    row = session.get(models.Job, job_id, with_for_update=True)
    if row is None:  # pragma: no cover - the row was written with the publication
        return
    note = f"{_publication_note_prefix(publication_id)}{reason.replace(';', ',')}"
    if note not in (row.error or ""):
        row.error = f"{row.error or ''}{note}"[:2000]


def clear_publication_notes(
    session, job_id: str, *, publication_id: str, reasons: list[str]
) -> None:
    """Take a publication's "not published" notes back off the job.

    Called, in the transaction that closes the publication out, when a row
    that had failed before lands after all — typically the operator requeued
    it (#425). The note was true when it was written and is false now, and it
    sits on the one field the console paints red on a job that says
    ``succeeded``.

    Only this publication's notes go, and nothing around them: first the exact
    notes for ``reasons`` (the row's own ``last_error``, as written by this
    release or, with its ``;`` intact, by the one before), then any other note
    of this publication up to where the next note begins.

    "Where the next note begins" is the next of the prefixes something in this
    codebase appends to ``error`` with (:data:`_NOTE_PREFIXES`), not the next
    ``;``. A note written before this release — or by a replica still on it
    during a rollout — carries its reason's ``;`` intact, and cutting there
    left ``; this run needs a re-scan or a manual load`` on a job whose run
    had since been published.
    """
    row = session.get(models.Job, job_id, with_for_update=True)
    if row is None or not row.error:
        return
    prefix = _publication_note_prefix(publication_id)
    cleaned = row.error
    for reason in reasons:
        for text in (reason.replace(";", ","), reason):
            cleaned = cleaned.replace(f"{prefix}{text}", "")
    ends = "|".join(re.escape(note) for note in _NOTE_PREFIXES)
    cleaned = re.sub(rf"{re.escape(prefix)}.*?(?={ends}|$)", "", cleaned, flags=re.DOTALL)
    if cleaned != row.error:
        row.error = cleaned or None
