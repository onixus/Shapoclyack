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
from api.services import job_repository
from api.services import job_states
from api.services import job_store
from api.services import metrics as metrics_service
from api.services import results_ingest
from api.services import run_ids
from api.services import run_publisher
from api.services import tenants as tenants_service
from api.services.artifact_store import keys as artifact_keys
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
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def _release_results_reservation(
    settings: Settings, job_id: str, key: str, *, late: bool = False
) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        # Only clear our own reservation, and only while the job is still
        # unfinished: once it is terminal the key is the record of what
        # produced that outcome, not a reservation.
        #
        # ``late`` is the one exception, and it is not really one: a key
        # reserved on the :func:`_accepts_late_archive` path sits on a row the
        # *reaper* terminalized, so it records nothing about that outcome — it
        # is a reservation like any other, and an ingest that failed under it
        # must give it back or the agent's retry is replayed an upload that
        # never landed.
        if row is not None and (late or row.status not in job_states.TERMINAL):
            if row.results_idempotency_key == key:
                row.results_idempotency_key = None


def _accepts_late_archive(
    settings: Settings, row: models.Job, *, cancelled: bool, has_archive: bool
) -> bool:
    """Whether this upload's *archive* may be kept on a job the reaper closed.

    The case, from #360's own debt list: the agent obeyed. It signalled the
    scanner, packed the partial ``runs/<run_id>`` and started uploading it on a
    link that was never going to finish inside ``job_cancel_grace_seconds`` —
    and ``reap_stale_cancellations`` wrote the row ``cancelled`` while the bytes
    were still on the wire. The upload then met a terminal job, was refused 422,
    and an archive nobody can produce again went in the bin, under a docs line
    that promises partial results are kept.

    **What is accepted is the bytes, not the verdict.** The row keeps the
    outcome the reaper gave it — ``cancelled``, ``finished_at`` where the reaper
    put it, ``exit_code`` still NULL, and "agent X did not confirm within Ns"
    still in ``error``. Nothing here claims the agent confirmed, because nothing
    here proves it did: a confirmation is a statement about *when* the scan
    stopped, and this upload arrived after the API had already given up waiting
    for one. That is why an upload carrying **no archive** is still refused — it
    has nothing to keep and would be asking the API to accept exactly the
    verdict it may not accept, which is the invariant #360's fixer left in place
    and this does not touch.

    Narrow on purpose, and every clause is load-bearing:

    * ``cancelled`` — the agent says it stopped because it was asked to. An
      ordinary late result is still a straggler, and still refused;
    * ``cancel_requested_at`` — an operator did ask. A job cancelled out of the
      queue never had an agent to obey;
    * ``exit_code IS NULL`` and no results key — nothing has ever been ingested
      for this job, so this cannot overwrite a run that was already reported.
      An ingest on this path writes one even when the agent sent none
      (:data:`LATE_ARCHIVE_RESERVATION`), which is what keeps the clause from
      being permanently true for an agent old enough not to have a key;
    * inside one further ``job_cancel_grace_seconds`` of ``finished_at``. The
      agent that missed the first grace period gets one more to deliver what it
      packed; past that "late" would mean "whenever", and an archive for a scan
      closed last week is not a partial result but a surprise. Derived from the
      knob #360 already has rather than from a second one of its own.
    """
    if not (cancelled and has_archive):
        return False
    if row.status != job_states.CANCELLED or row.cancel_requested_at is None:
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
    """Note that the archive landed, without rewriting how the job ended.

    Deliberately not :func:`job_store.update_job`: ``status``, ``finished_at`` and
    ``exit_code`` are the reaper's answer and stay its answer. What changes is
    the two things that are about the *data* — which run directory now holds it,
    and a line in ``error``, so an operator reading the drawer is not left
    wondering why a job that "did not confirm" has results.

    Fenced like the ordinary terminal write, and for the same reason: this one
    also runs after an ingest that took as long as it took, and a second upload
    accepted meanwhile is the upload whose archive is now in the run directory.

    ``publication`` rides in the same transaction for the same reason it does
    in :func:`job_store.update_job`: the archive is kept, so the installation owes it a
    publication, and the two facts are one write.
    """
    note = f"; partial results uploaded late by agent {agent_id}"
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id, with_for_update=True)
        if row is None:  # pragma: no cover - the row was locked moments ago
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
        "Kept a late partial archive for cancelled job %s from agent %s; the job's "
        "outcome is unchanged",
        job_id,
        agent_id,
    )


def _replayed(row: models.Job) -> JobInfo:
    metrics_service.JOB_IDEMPOTENT_REPLAYS_TOTAL.labels(operation="results").inc()
    _log.info("Replayed results upload for job %s; returning the stored outcome", row.job_id)
    return job_store.to_info(row)


def _classify_replay(
    row: models.Job, *, exit_code: int, idempotency_key: str | None
) -> JobInfo | None:
    """Decide whether an upload for an already-finished job is a replay.

    Returns the stored outcome for a replay, raises ``ResultsConflict`` for an
    upload that contradicts it, and returns ``None`` when this is not a replay
    question at all, so the caller's normal transition check produces the
    error.

    A ``cancelled`` job is the narrow case (#360). Since a confirmed
    cancellation *is* an upload, its retry is a replay like any other — but
    only an exact key proves that. Without one, this is a late result for a
    stop the row never recorded a confirmation of (the reaper's row carries no
    key), and that still meets the transition check rather than being answered
    with an outcome it did not produce.

    With a key, the comparison is exact. Without one — older agents, and the
    legacy shared-token path — the fallback is the natural key: the same agent
    reporting the same exit code for a job it still owns is the retry we are
    trying to survive, and it cannot be confused with a different result,
    because a different result carries a different exit code.
    """
    if row.status == job_states.CANCELLED:
        if idempotency_key and row.results_idempotency_key == idempotency_key:
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


def _merge_cancellation_reason(requested: str | None, reported: str | None) -> str | None:
    """Keep "Cancellation requested by X" when the agent confirms the stop (#360).

    ``requested`` is what ``cancel_job`` wrote and is ``None`` for every
    outcome that is not a confirmed cancellation, which makes this the plain
    truncation the other paths always did. For a cancellation it is the only
    place the actor survives after the job is finished: without it the agent's
    string — or, when it sends none, ``NULL`` — is all a drawer shows for a
    scan somebody deliberately stopped, and "who killed my scan at 3am" is a
    hop away in the audit trail instead of being on the job.
    """
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
    """Record an agent's result upload. Replays return the original outcome.

    P1.3 made a second upload an error, which is right for a *different*
    result but wrong for the case that actually happens: the upload succeeded
    and the response never made it back, so the agent sends the same bytes
    again. Under P1.5 that replay is answered with the job as it already
    stands — no re-extraction, no second NATS publish, no error for the agent
    to interpret. Two uploads that genuinely disagree still conflict.

    ``attempt`` is the fencing token from the claim response. A lease that
    expired and was reissued bumped it, so an upload carrying an older value is
    a straggler from an attempt that has already been replaced — and since a
    restarted worker keeps its ``agent_id``, that is the only way to tell the
    two apart. Omitted by pre-P1.5 agents, which are then unfenced.

    ``attempt`` is checked twice, and the second check is the one that matters.
    Between the two, this function extracts an archive and writes artifacts
    over the network, and the lease can lapse inside that window: the reaper
    then requeues the job, a second attempt claims it, and the first one's
    terminal write used to finish *that* attempt, because ``claimed → succeeded``
    is legal whoever asks for it. So the first transaction takes an ingest
    lease, everything the upload produces is extracted into staging named after
    that lease, and the terminal write happens only if the row is still on the
    same (attempt, owner, token). A result that is no longer current is refused
    as :class:`StaleAttempt` — the agent is told its result was rejected, which
    is not the same thing as its upload having failed.

    Nothing is published on either side of that check. The upload is
    extracted into a staging tree named after the lease, which no listing, no
    store key and no bus subject can see, and the terminal write carries one
    ``run_publications`` row with it. So a refused straggler leaves nothing
    anywhere, and an accepted upload leaves a record that the installation
    owes this run its store keys, its run directory, ``latest_run.json`` and
    its ``ingest.results.{tenant}`` message — published in this thread right
    below, and by ``run_publisher``'s reconciler if that does not succeed.
    Ordering the publication *around* the write, in either direction, is what
    two previous attempts did; see the module docstring there for why neither
    side of that choice is correct.

    ``cancelled`` is the agent confirming it put the scan down because the API
    asked it to (#360), and it decides the outcome on its own: the scanner was
    signalled, so it exits non-zero, and without this flag every stop would be
    filed as a scan that failed. The archive is still ingested — whatever the
    run had written before the signal is real data an operator asked to keep —
    but, like a failed run, it does not feed the vulnerability tracker, the
    asset event stream or the notification channels: a partial sweep read as a
    complete one would report hosts and ports as *gone* that the scan simply
    never reached.
    """
    replay_result: JobInfo | None = None
    late_archive = False
    fence: job_leases.IngestLease | None = None

    with get_session(settings.postgres_url) as session:
        # Locked for the whole check: concurrent uploads for the same job must
        # be decided one at a time, or both would read a non-terminal row and
        # both go on to extract the archive.
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
        # Only from a job the API actually asked to stop. An agent that
        # reported a cancellation nobody requested would otherwise be able to
        # retire any job it holds as "cancelled" — and the honest reading of a
        # scan that stopped for the agent's own reasons is a failure, which is
        # what the exit code already says.
        #
        # A row already ``cancelled`` is included so that an upload this
        # function is about to refuse is refused for what it reported: a retry
        # whose key does not match is a second cancellation result, and telling
        # its agent the job "cannot move from cancelled to failed" would name
        # an outcome nobody claimed.
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
                # Answered below, once the row lock is released: the cleanup
                # this replay triggers is filesystem work, and holding the lock
                # across it would make a second agent's retry wait on the disk
                # rather than on the decision.
                replay_result = replay
            elif _accepts_late_archive(
                settings,
                row,
                cancelled=cancelled,
                has_archive=bool(archive_bytes),
            ):
                # The obedient-but-slow agent: its bytes are kept, the outcome
                # the reaper wrote is not touched. See the predicate.
                late_archive = True
                # Reserved inside the lock like any other, so a second copy of
                # this upload is recognised rather than extracted twice. Given
                # back by the failure path below, which is told this is a
                # reservation and not the record of an outcome. An agent that
                # sent no key gets the server's own marker rather than
                # nothing: see :data:`LATE_ARCHIVE_RESERVATION`.
                row.results_idempotency_key = (
                    idempotency_key or LATE_ARCHIVE_RESERVATION
                )
        elif idempotency_key:
            if row.results_idempotency_key == idempotency_key:
                # Same key, job not finished: the first request holding this key
                # is still ingesting. Answering 409 tells the client to retry
                # rather than letting two handlers extract into one run
                # directory and race to terminalize the job.
                raise ResultsInFlight(
                    "An upload with this key is already being processed "
                    f"for job {job_id}"
                )
            # Reserve the key inside the locked transaction, so the duplicate
            # above can recognise it. Cleared again if this upload fails.
            row.results_idempotency_key = idempotency_key

        # Checked before the archive is ingested, not after: a duplicate upload
        # for a job that already finished — or one an operator cancelled while
        # the agent was still working — must not overwrite the run directory
        # and re-publish to NATS before being rejected.
        if replay_result is None and not late_archive:
            job_states.check_transition(job_id, row.status, status)

        # Read under the lock, for the same reason the surface below is: the
        # confirming upload is the only writer that would otherwise erase who
        # asked for the stop, and ``error`` is where docs/api-and-rbac.md says
        # that reason lives for the life of the job (#360).
        requested_reason = (
            row.error if status == job_states.CANCELLED else None
        )
        resolved_run_id = run_ids.confirm(row.run_id, run_id)
        # Read here rather than re-fetched at the write below: the row is
        # already loaded and locked, and the surface was decided at start_scan.
        job_surface = (row.scan_options or {}).get("surface")

        # Taken last, on the row this transaction has just approved, and only
        # for an upload that is going to be ingested: a replay is answered
        # from the row as it stands and produces no write to fence.
        if replay_result is None:
            fence = job_leases.open_ingest_lease(
                settings, row, agent_id=agent_id
            )

    if replay_result is not None:
        # Reached only for a job that is already terminal, so the agent is not
        # still reading these — a replay arrives after the run has finished,
        # not while it is executing. A first upload whose response was lost may
        # already have swept the directory, which is why this is idempotent
        # (#258).
        job_inputs.discard(settings, job_id)
        return replay_result

    assert fence is not None
    staging: Path | None = None
    publication: models.RunPublication | None = None

    try:
        if archive_bytes:
            if not resolved_run_id:
                raise ValueError("run_id required when uploading results")
            # Into staging named after this ingest lease, never straight into
            # the run directory: a job keeps its run id across attempts, so
            # extracting there would publish a straggler's archive over the
            # run the current attempt is producing — before anything had
            # checked whether this upload is still the current one.
            staging = artifact_workspace.staging_run_dir(
                settings,
                artifact_keys.run_ref(str(resolved_run_id), job_tenant),
                fence.token,
            )
            try:
                results_ingest.extract_run_archive(archive_bytes, staging)
            except results_ingest.IngestError as exc:
                raise ValueError(str(exc)) from exc

            # Kept beside the tree, not inside it: the bus message for this run
            # is built from these exact bytes, and a publication that has to be
            # retried after the process is gone has no other way to send the
            # same ``Msg-Id``.
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

        # The fence, and the only thing that crosses it. Everything above this
        # line is work on a copy nobody can see; this write decides whether the
        # installation has a scan at all, and it carries the publication with
        # it so that deciding and owing become true together.
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
                # Recorded with the outcome, so a later upload can be told apart
                # from the one that produced it.
                results_idempotency_key=(idempotency_key or None),
            )
    except Exception:
        if staging is not None:
            # Nothing was published — the write above is what would have made
            # this tree the installation's copy of the run, and it did not
            # happen. So the tree is a refused upload's rubbish rather than a
            # scan somebody might miss, and the sensor still holds the archive.
            artifact_workspace.discard_staging(staging)
        # The reservation above is only meaningful while this upload is in
        # flight. Releasing it lets the agent retry with the same key — or, on
        # the late path, with no key at all — instead of meeting its own
        # abandoned reservation forever.
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
        # In this thread, so the ordinary upload is answered with the run
        # already in the store and on the bus. A failure here is not the
        # agent's problem and does not raise: the outcome is committed, and
        # what is left undone is a row the reconciler owns.
        run_publisher.publish_now(settings, fence.token)

    if status == job_states.CANCELLED:
        # Counted apart from a confirmation, because it is not one: the scan was
        # written off unconfirmed and only its archive arrived afterwards. A
        # rising share here is an agent that cannot upload inside the grace
        # period — a bandwidth or grace-period problem, not a stuck agent.
        metrics_service.JOB_CANCELLATIONS_TOTAL.labels(
            outcome=(
                "late_results"
                if late_archive
                else "confirmed"
            )
        ).inc()

    agents_service.touch_job(agent_id, None, status="idle")
    # The job is terminal now: no further claim will serve these files (#258).
    # After the job_store.update_job above, so a raise in ingestion leaves them
    # for the agent's retry rather than deleting what the retry needs.
    job_inputs.discard(settings, job_id)

    # The channel fan-out is not here any more: it announces a run an operator
    # can open, so it belongs to the *publication* and moved to
    # ``run_completion.on_run_published``. It keeps the property that made it
    # move once before — it is after the terminal write, on a thread, so a
    # fan-out that hangs cannot hold the outcome hostage and send the agent's
    # retry into its own in-flight reservation.
    result = job_repository.get_job(settings, job_id)
    assert result is not None
    return result
