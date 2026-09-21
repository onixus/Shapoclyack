"""Making an accepted run visible, once, after the decision to accept it.

**The question this answers.** An agent's upload becomes four visible things:
the object store, the run directory other requests read, ``latest_run.json``,
and one message on ``ingest.results.{tenant}`` that feeds ClickHouse. The
outcome of the job is a fifth, and it is a row. Ordering the publication
against that row has no right answer:

* publish *before* the terminal write and a straggler — an upload whose lease
  the reaper has already handed to a second attempt — puts its archive in the
  store, merges its files into the run directory and lands on the bus under a
  run id it no longer owns. The write that would have refused it comes after
  the damage, and rolling four publications back is not something a process
  that may die halfway can promise.
* publish *after* it and a store outage leaves a job reported ``succeeded``
  with no scan behind it; the agent's retry is then answered as a replay of
  that outcome, so nothing ever fetches the run again.

Both were shipped in turn, and the second was worse than the first. The way
out is to stop treating it as an ordering problem. The publication is work
that must happen **exactly once, after a decision, and survive the process
that made it** — which is a durable intent, not a call order.

**The shape.** ``complete_job`` extracts the upload into a staging tree named
after its ingest lease, which nothing can see. Then one transaction writes the
job's terminal state *and* one ``run_publications`` row, under the same fence:
either both happen or neither does, so an upload the fence refuses leaves no
row, no directory, no key and no message — and an upload that is accepted can
no longer be forgotten. Everything visible is done from that row afterwards,
in the accepting request first (so the common case is published before the
sensor's response returns) and by the reconciler here if that does not
succeed.

Each step is idempotent and each is resumable from what is on disk, so a
replica killed anywhere in the middle is a retry rather than a repair:
``upload_tree`` writes the same keys, ``promote_staging`` moves the same tree,
the pointer is a file, and the bus message carries a ``Msg-Id`` derived from
the archive digest — which is why the archive is kept beside the staging tree
rather than re-derived (:func:`artifact_store.workspace.staged_archive_path`).
A republish of the same run is the same message, so JetStream drops it; two
*different* attempts could never both get here, because only one of them was
ever accepted.

**The bound.** Retries stop at ``run_publication_max_attempts`` and the row
stays ``dead``. That is the honest end: an installation whose store has been
refusing for ten minutes needs an operator, not a slower timer. A dead row is
visible three ways — ``/api/health``, ``octo_run_publication_backlog`` and a
note on the job's ``error`` — and its tree is kept on disk for a day (see the
sweep in ``workspace``), so the decision is "publish it by hand or re-scan",
never "the scan is gone and nothing said so".

Safe in every replica without leader election, like the job reaper: due-ness
is a property of the row and rows are claimed with ``FOR UPDATE SKIP LOCKED``.
The paths in a row are on one replica's disk, though, so a peer that claims a
row it cannot see gives it back instead of declaring the run lost — see
:func:`_claim_due`. Bounded as well: a pod's ``emptyDir`` cache takes its
staging trees with it, so a row offered around for
``run_publication_orphan_deadline_seconds`` with nobody able to see the tree
ends ``dead`` like any other publication that cannot be finished, rather than
circulating silently forever (:func:`_give_back`).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.services import results_ingest
from api.services import runs as runs_service
from api.services.artifact_store import workspace as artifact_workspace
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.run-publisher")

#: Rows one reconciler tick takes. Small on purpose: each is a whole run's
#: worth of store writes, and the tick that claims them holds them for the
#: length of the batch (:func:`_claim_due`).
_BATCH_SIZE = 10

STATUS_PENDING = "pending"
STATUS_DEAD = "dead"

#: Why a publication is dead without having been tried again: the tree it
#: would publish is not on any disk this installation can reach. Named so the
#: operations runbook and the tests can both point at one string.
_TREE_IS_GONE = (
    "the extracted upload is no longer on disk; this run needs a re-scan or a manual load"
)

#: Why a publication is dead without this replica having tried it: the row was
#: accepted by a replica that is gone and the only copy of the tree went with
#: it. Distinct from ``_TREE_IS_GONE``, which is this replica's own tree.
_REPLICA_IS_GONE = (
    "the replica that accepted this upload is gone and no peer can see the extracted "
    "tree; this run needs a re-scan"
)


def _now() -> datetime:
    """Naive UTC, matching ``jobs`` and every timestamp column in this schema."""
    return datetime.now(UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class _Publication:
    """One row, snapshotted before any I/O.

    Plain values rather than ORM state: publishing a run is minutes of file
    and network work, and an attached instance held across it is a session
    open across it.
    """

    publication_id: str
    tenant_id: str
    job_id: str
    run_id: str
    agent_id: str | None
    job_status: str
    exit_code: int | None
    scan_error: str | None
    surface: str | None
    staging_path: str
    archive_path: str | None
    replica: str | None
    created_at: datetime | None
    attempts: int


def _snapshot(row: models.RunPublication) -> _Publication:
    return _Publication(
        publication_id=row.publication_id,
        tenant_id=row.tenant_id,
        job_id=row.job_id,
        run_id=row.run_id,
        agent_id=row.agent_id,
        job_status=row.job_status,
        exit_code=row.exit_code,
        scan_error=row.scan_error,
        surface=row.surface,
        staging_path=row.staging_path or "",
        archive_path=row.archive_path,
        replica=row.replica,
        created_at=row.created_at,
        attempts=row.attempts or 0,
    )


def new_publication(
    settings: Settings,
    *,
    publication_id: str,
    job_id: str,
    run_id: str,
    tenant_id: str,
    job_status: str,
    agent_id: str,
    exit_code: int,
    scan_error: str | None,
    surface: str | None,
    staging: Path,
) -> models.RunPublication:
    """The row ``complete_job`` inserts *with* the job's terminal write.

    Built here rather than in ``jobs`` so the two callers there (an ordinary
    result and a late cancellation archive) cannot drift apart, and returned
    unattached: it is added to the caller's session, inside the caller's
    transaction, because "this run was accepted" and "this run is owed a
    publication" have to become true together or not at all.

    ``publication_id`` is the caller's ingest lease token — one publication
    per accepted upload, and none for an upload the fence refuses.
    """
    now = _now()
    return models.RunPublication(
        publication_id=publication_id,
        tenant_id=tenant_id,
        job_id=job_id,
        run_id=run_id,
        agent_id=agent_id,
        job_status=job_status,
        exit_code=exit_code,
        scan_error=scan_error,
        surface=surface,
        staging_path=str(staging),
        archive_path=str(artifact_workspace.staged_archive_path(staging)),
        replica=settings.instance_id,
        status=STATUS_PENDING,
        attempts=0,
        # Due immediately: the accepting request publishes it inline, and a
        # row that outlives that request is one the reconciler should pick up
        # on its next tick rather than after a backoff nothing has earned yet.
        next_attempt_at=now,
        created_at=now,
        updated_at=now,
    )


def publish_now(settings: Settings, publication_id: str) -> bool:
    """Publish one owed run in the caller's thread. Answers whether it landed.

    Called by ``complete_job`` straight after the transaction that accepted
    the upload, which is what keeps the ordinary case synchronous: by the time
    the sensor is answered, the run is in the store and on the bus.

    The row is *claimed* here exactly as a reconciler tick claims it: the row
    is inserted due immediately and publishing it is minutes of store and
    broker work, so a tick — in this replica or any other — would otherwise
    find it due and publish it a second time alongside this call. That costs
    the operator a duplicate notification, the projections a second pass, and
    the tree a ``rmtree`` racing an ``upload_tree``. A row a peer is already
    holding is left to it: ``False`` here is "not published by me".

    Never raises for a failed publication. The outcome is committed, the
    agent's retry is answered as a replay, and raising here would report a
    failure for a scan the API has kept — while the work itself is not lost,
    it is a row.
    """
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.RunPublication)
            .where(models.RunPublication.publication_id == publication_id)
            .with_for_update(skip_locked=True)
        ).scalars().first()
        if row is None:  # pragma: no cover - inserted moments ago, or held by a tick
            return False
        _hold(row, now=_now(), rows=1, settings=settings)
        publication = _snapshot(row)
    return _attempt(settings, publication)


class _TreeIsGone(RuntimeError):
    """Neither the staging tree nor the run directory is on this disk."""


def _attempt(settings: Settings, publication: _Publication) -> bool:
    """One publication attempt, with its outcome written back."""
    try:
        _publish(settings, publication)
    except _TreeIsGone:
        _record_failure(settings, publication, _TREE_IS_GONE, final=True)
        return False
    except Exception as exc:  # noqa: BLE001 - every failure here is a retry
        _record_failure(settings, publication, f"{type(exc).__name__}: {exc}")
        return False
    _record_success(settings, publication)
    return True


def _publish(settings: Settings, publication: _Publication) -> None:
    """Do the four visible things, in the order that keeps each one resumable.

    The tenant marker is written into the *staging* tree rather than after the
    run is published: a run directory with no ``tenant.json`` reads back as
    the default tenant everywhere (``runs.read_run_tenant``), which puts one
    tenant's scan in every tenant's run list until somebody notices. Into
    staging, it travels into both copies at the moment either becomes
    readable.

    A retry may find the tree already promoted — the replica died between the
    move and the bus publish — and that is not an error but the first three
    steps' way of saying they are done.
    """
    staging = Path(publication.staging_path) if publication.staging_path else None
    run_id = publication.run_id
    if staging is not None and staging.is_dir():
        runs_service.stage_run_tenant(
            staging,
            publication.tenant_id,
            job_id=publication.job_id,
            surface=publication.surface,
        )
        # Into the store from staging: the copy the other replicas read is
        # complete and marked the first time they can see it.
        try:
            artifact_workspace.publish_run(settings, run_id, source=staging)
        except Exception:
            # A remote backend uploads the tree file by file, and a store that
            # starts refusing halfway leaves keys under ``runs/<run_id>/``. A
            # run listing is the children of ``runs/``, so those keys are a
            # scan every replica can see and open, with whatever did not make
            # it simply missing. The half is taken back off before the failure
            # is recorded, so a retry starts from nothing and a row that ends
            # ``dead`` costs the run its visibility rather than leaving a
            # partial one that reads as complete.
            artifact_workspace.unpublish_run(settings, run_id)
            raise
        # The marker cache on a remote backend may hold a "no marker" answer
        # from a listing that asked about this run before it existed, and
        # reading that back is the default-tenant leak the marker prevents.
        artifact_workspace.forget_run_marker(run_id)
        artifact_workspace.promote_staging(settings, run_id, staging)
    elif not artifact_workspace.run_exists(settings, run_id):
        raise _TreeIsGone(_TREE_IS_GONE)
    results_ingest.update_latest_run_pointer(settings.state_dir, run_id)
    _publish_to_bus(settings, publication)


def _publish_to_bus(settings: Settings, publication: _Publication) -> None:
    """Put the run's archive on ``ingest.results.{tenant}``. Raises to retry.

    The bytes come from the file kept beside the staging tree, so a republish
    after a broker outage sends the archive this upload actually carried and
    JetStream's ``Msg-Id`` dedup recognises it — re-tarring the run directory
    would produce a different digest, i.e. a second message for one run.

    An archive that is gone is not a retry: the rest of the publication has
    landed and no future attempt can produce these bytes, so the row is ended
    as ``dead`` with the reason on it rather than counting down attempts that
    cannot work.
    """
    if not settings.nats_url:
        return
    archive = Path(publication.archive_path) if publication.archive_path else None
    if archive is None or not archive.is_file():
        raise _TreeIsGone(
            "the uploaded archive is no longer on disk, so the analytical projection "
            "cannot be fed for this run; the run itself is published"
        )
    result = results_ingest.publish_raw_results(
        nats_url=settings.nats_url,
        job_id=publication.job_id,
        run_id=publication.run_id,
        agent_id=publication.agent_id or "",
        exit_code=publication.exit_code if publication.exit_code is not None else 0,
        archive_bytes=archive.read_bytes(),
        error=publication.scan_error,
        tenant_id=publication.tenant_id,
    )
    if not result.get("published"):
        raise RuntimeError("the broker refused the ingest publish")


def _record_success(settings: Settings, publication: _Publication) -> None:
    """Close the row out, drop the archive, and feed what reads the run.

    The projections run here, not in ``complete_job``: they read the run
    directory, so before the publication there is nothing for them to read,
    and after a deferred publication they are owed exactly as much as the run
    is. Each one guards itself; a failure among them is a note on the job, not
    a reason to publish the run twice.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is not None:
            session.delete(row)
    if publication.archive_path:
        Path(publication.archive_path).unlink(missing_ok=True)
    metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="published").inc()
    if publication.attempts:
        LOG.info(
            "Published run %s of job %s after %d attempt(s)",
            publication.run_id,
            publication.job_id,
            publication.attempts + 1,
        )
    # Imported here rather than at module scope: ``jobs`` owns the projections
    # and calls this module for every upload it accepts, so the two would be a
    # cycle at import time.
    from api.services import jobs as jobs_service

    jobs_service.on_run_published(
        settings,
        publication.job_id,
        run_id=publication.run_id,
        tenant_id=publication.tenant_id,
        status=publication.job_status,
    )


def _record_failure(
    settings: Settings, publication: _Publication, reason: str, *, final: bool = False
) -> None:
    """Write one failed attempt back, and end the row when it is out of them.

    ``final`` is for a failure no retry can fix. Everything else counts down
    ``run_publication_max_attempts`` on an exponential backoff, the same shape
    as ``webhooks.backoff_seconds``. The attempt itself is counted here rather
    than where the row was claimed, so an attempt is something that was tried
    and refused — see :func:`_hold`.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is None:  # pragma: no cover - deleted by a peer mid-flight
            return
        row.attempts += 1
        row.updated_at = now
        row.last_error = reason[:2000]
        spent = final or row.attempts >= settings.run_publication_max_attempts
        if spent:
            row.status = STATUS_DEAD
            row.next_attempt_at = None
        else:
            row.next_attempt_at = now + timedelta(
                seconds=_retry_delay_seconds(row.attempts, settings)
            )
        attempts = row.attempts
    if not spent:
        metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="deferred").inc()
        LOG.warning(
            "Run %s of job %s is accepted but not published yet (attempt %d/%d): %s",
            publication.run_id,
            publication.job_id,
            attempts,
            settings.run_publication_max_attempts,
            reason,
        )
        return
    metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="dead").inc()
    LOG.error(
        "Run %s of job %s is accepted and will not be published without an operator "
        "(after %d attempt(s)): %s. The extracted upload is at %s",
        publication.run_id,
        publication.job_id,
        attempts,
        reason,
        publication.staging_path,
    )
    # On the job as well as in the table: the operator looking at a scan that
    # says ``succeeded`` with no artifacts behind it is looking at the job,
    # and the row is the thing they have not been told about yet.
    from api.services import jobs as jobs_service

    jobs_service.note_publication_failed(
        settings, publication.job_id, publication_id=publication.publication_id, reason=reason
    )


def _retry_delay_seconds(attempts: int, settings: Settings) -> int:
    """Delay before the next attempt, exponential and capped.

    The exponent is clamped because ``attempts`` is read back from a row and
    is not a value to trust into ``2**large``.
    """
    exponent = min(max(0, attempts - 1), 20)
    return min(
        settings.run_publication_retry_base_seconds * (2**exponent),
        settings.run_publication_retry_max_seconds,
    )


def _adoption_seconds(settings: Settings) -> int:
    """How long a peer's row waits before another replica may try it.

    A row's paths are on the replica that accepted the upload, so its own
    reconciler is the one that can finish it, and giving a peer first refusal
    would mean marking runs dead because they are on somebody else's disk.
    After this long the accepting replica is not coming back — it was killed
    — and a peer that *can* see the tree (a shared volume, a local backend on
    an RWX mount) is the run's only chance. One that cannot see it gives the
    row back untouched.
    """
    return max(300, 10 * settings.run_publication_interval_seconds)


def _hold(row: models.RunPublication, *, now: datetime, rows: int, settings: Settings) -> None:
    """Push one claimed row out of the due window for the length of the work.

    The window covers the whole batch rather than one row, because the rows
    are published after the claiming transaction commits and a batch of runs
    is minutes of work: a peer must not claim the tail of a batch that is
    still being published.

    Attempts are *not* counted here. A claim is not an attempt: a replica the
    OOM killer takes down while publishing a large run would otherwise write
    off one attempt per restart for every row it was holding, and five
    restarts would leave a batch ``dead`` without the store having refused
    once. They are counted where a failure is recorded instead.
    """
    per_row = max(60, settings.run_publication_interval_seconds)
    row.next_attempt_at = now + timedelta(seconds=per_row * max(1, rows))
    row.updated_at = now


def _claim_due(session, *, now: datetime, limit: int, settings: Settings) -> list[Any]:
    """Take up to ``limit`` due rows, pushing them out of the due window.

    ``FOR UPDATE SKIP LOCKED`` plus a bumped ``next_attempt_at`` is what makes
    the reconciler safe in every replica — and what the accepting request does
    too, see :func:`publish_now`.
    """
    instance = settings.instance_id
    adoption_cutoff = now - timedelta(seconds=_adoption_seconds(settings))
    rows = list(
        session.execute(
            select(models.RunPublication)
            .where(
                models.RunPublication.status == STATUS_PENDING,
                models.RunPublication.next_attempt_at <= now,
                or_(
                    models.RunPublication.replica == instance,
                    models.RunPublication.replica.is_(None),
                    models.RunPublication.created_at < adoption_cutoff,
                ),
            )
            .order_by(models.RunPublication.next_attempt_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars().all()
    )
    for row in rows:
        _hold(row, now=now, rows=len(rows), settings=settings)
    session.flush()
    return rows


def _is_foreign_and_absent(settings: Settings, publication: _Publication) -> bool:
    """Whether this row belongs to a replica that still has the only copy.

    Adopted rows are published by whoever can see the tree. One that cannot —
    the ordinary case for a cache directory that is an ``emptyDir`` — must not
    spend the row's attempts or declare the run lost on the strength of its
    own disk.
    """
    if publication.replica in (None, settings.instance_id):
        return False
    staging = Path(publication.staging_path) if publication.staging_path else None
    if staging is not None and staging.is_dir():
        return False
    return not artifact_workspace.run_exists(settings, publication.run_id)


def _give_back(settings: Settings, publication: _Publication) -> bool:
    """Hand a peer's row back — or end it, when nobody is coming for it.

    Answers whether the row is still owed. Giving it back has to be bounded:
    the peer that could publish it may not exist. The default HA overlay keeps
    the artifact cache in an ``emptyDir``, so a staging tree dies with its pod,
    and a row from a pod the autoscaler took away is one *no* replica can ever
    see. Without a deadline it is claimed, given back and claimed again every
    adoption window, forever, while ``is_backlogged`` counts only ``dead`` and
    the job goes on saying it succeeded with nothing behind it — which is the
    failure this whole module exists to end.

    Past ``run_publication_orphan_deadline_seconds`` the row is therefore
    ``dead`` with the reason on it, which is the same three-way visibility a
    store outage gets: ``/api/health``, the backlog gauge, and a note on the
    job. An operator can still find the tree if the disk outlived the pod;
    what they cannot do any more is not be told.
    """
    now = _now()
    if _is_orphaned(settings, publication, now=now):
        _record_failure(settings, publication, _REPLICA_IS_GONE, final=True)
        return False
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is None:  # pragma: no cover - finished by its own replica
            return True
        row.next_attempt_at = now + timedelta(seconds=_adoption_seconds(settings))
        row.updated_at = now
    return True


def _is_orphaned(settings: Settings, publication: _Publication, *, now: datetime) -> bool:
    """Whether a row this replica cannot see has waited past its deadline."""
    created = publication.created_at
    if created is None:  # pragma: no cover - the column is written with the row
        return False
    return (now - created) > timedelta(seconds=_orphan_deadline_seconds(settings))


def _orphan_deadline_seconds(settings: Settings) -> int:
    """How long an unreachable row is offered around before it is declared dead.

    Floored at two adoption windows so the deadline can never land before a
    peer has had a chance to adopt the row at all.
    """
    return max(
        settings.run_publication_orphan_deadline_seconds, 2 * _adoption_seconds(settings)
    )


def reconcile_once(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """One pass over the owed publications. Returns what the pass did.

    Called by the worker below on a timer, and directly by the tests and by an
    operator who would rather not wait for a tick.
    """
    outcome = {"published": 0, "failed": 0, "skipped": 0}
    moment = now or _now()
    with get_session(settings.postgres_url) as session:
        claimed = [_snapshot(row) for row in _claim_due(
            session, now=moment, limit=_BATCH_SIZE, settings=settings
        )]
    for publication in claimed:
        if _is_foreign_and_absent(settings, publication):
            if _give_back(settings, publication):
                outcome["skipped"] += 1
            else:
                outcome["failed"] += 1
            continue
        if publication.replica != settings.instance_id:
            metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="adopted").inc()
        if _attempt(settings, publication):
            outcome["published"] += 1
        else:
            outcome["failed"] += 1
    _refresh_backlog_gauge(settings)
    return outcome


def backlog(settings: Settings) -> dict[str, int]:
    """What is owed, by status. Read by ``/api/health`` and the gauge."""
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.RunPublication.status, func.count()).group_by(
                models.RunPublication.status
            )
        ).all()
    counts = {STATUS_PENDING: 0, STATUS_DEAD: 0}
    for status, count in rows:
        counts[str(status)] = int(count)
    return {"pending": counts[STATUS_PENDING], "dead": counts[STATUS_DEAD]}


def is_backlogged(settings: Settings) -> bool:
    """Whether an accepted run is not visible and is not going to become so.

    Only ``dead`` counts. A pending row is the publication in flight — the
    ordinary state for the length of one upload's ingest — and calling the
    installation degraded for it would mean a health check that flickers on
    every scan.

    Fail-soft: a database that cannot answer is the blocking Postgres check's
    business, and a probe that raises tells the kubelet the API is broken
    rather than that a query failed.
    """
    try:
        return bool(backlog(settings)["dead"])
    except Exception:  # noqa: BLE001
        LOG.warning("Could not read the run publication backlog", exc_info=True)
        return False


def pending_publications(settings: Settings, job_id: str) -> list[models.RunPublication]:
    """Publications still owed for one job, newest first. For the API and tests."""
    with get_session(settings.postgres_url) as session:
        return list(
            session.execute(
                select(models.RunPublication)
                .where(models.RunPublication.job_id == job_id)
                .order_by(models.RunPublication.created_at.desc())
            ).scalars().all()
        )


def discard_publication(settings: Settings, publication_id: str) -> bool:
    """Forget one owed publication. Answers whether there was one to forget.

    The way out of a ``dead`` row, for the operator who has either loaded the
    run by hand or decided to re-scan (see the runbook in
    ``docs/operations.md``). Deliberately not a route: it is the last word on a
    run the installation has already told its user it accepted, it is reached
    perhaps twice a year, and the alternative on offer until now was raw SQL
    against the table in a runbook that did not say so.

    Only the row goes. The extracted tree and the archive beside it stay where
    they are until the ordinary sweep takes them, so a decision made in haste
    is still recoverable for a day.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication_id)
        if row is None:
            return False
        session.delete(row)
    LOG.warning(
        "Publication %s was discarded by an operator; the run it owed is not published",
        publication_id,
    )
    return True


def reset_for_tests(settings: Settings) -> None:
    """Empty the table. Test-only, and named like ``jobs.reset_for_tests``."""
    with get_session(settings.postgres_url) as session:
        session.query(models.RunPublication).delete()


def _refresh_backlog_gauge(settings: Settings) -> None:
    try:
        counts = backlog(settings)
    except Exception:  # noqa: BLE001
        LOG.debug("Could not refresh the run publication gauge", exc_info=True)
        return
    for status, value in counts.items():
        metrics_service.RUN_PUBLICATION_BACKLOG.labels(status=status).set(value)


class PublicationReconciler:
    """Timer that finishes the publications the requests did not.

    Structured like ``job_reaper``/``webhook_worker``: a daemon thread with a
    crash-restart loop, started and stopped from the FastAPI lifespan, and
    safe in every replica for the reason in :func:`_claim_due`.
    """

    def __init__(self, *, settings: Settings, poll_interval_seconds: float | None = None) -> None:
        self._settings = settings
        # Floored here as well as in Settings: a caller constructing this
        # directly (tests, an embedder) must not be able to spin the loop.
        self._poll_interval = max(
            1.0, poll_interval_seconds or float(settings.run_publication_interval_seconds)
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"ticks": 0, "published": 0, "failed": 0, "skipped": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-run-publisher", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Run publication reconciler started (poll_interval=%.0fs max_attempts=%d)",
            self._poll_interval,
            self._settings.run_publication_max_attempts,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Run publication reconciler stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Run publication reconciler tick failed")
            self._stop.wait(self._poll_interval)

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        outcome = reconcile_once(self._settings)
        for key in ("published", "failed", "skipped"):
            self._stats[key] += outcome[key]


_RECONCILER: PublicationReconciler | None = None


def start_worker(settings: Settings) -> PublicationReconciler | None:
    global _RECONCILER
    if not settings.run_publication_worker_enabled:
        return None
    if _RECONCILER is not None:
        return _RECONCILER
    worker = PublicationReconciler(settings=settings)
    worker.start()
    _RECONCILER = worker
    return worker


def stop_worker() -> None:
    global _RECONCILER
    if _RECONCILER is not None:
        _RECONCILER.stop()
        _RECONCILER = None


def reconciler_stats() -> dict[str, int] | None:
    if _RECONCILER is None:
        return None
    return _RECONCILER.stats


__all__ = [
    "PublicationReconciler",
    "reset_for_tests",
    "backlog",
    "is_backlogged",
    "new_publication",
    "pending_publications",
    "publish_now",
    "reconcile_once",
    "reconciler_stats",
    "start_worker",
    "stop_worker",
]
