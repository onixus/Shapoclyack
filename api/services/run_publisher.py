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
A republish of the same run is therefore the same message, which JetStream
drops: the ``INGEST`` stream is declared with a ``duplicate_window``
(``OCTO_NATS_INGEST_DEDUPE_SECONDS``, 24h) wide enough to cover both this
module's backoff and the outbox's, rather than the two-minute default that was
shorter than either. Two *different* attempts could never both get here,
because only one of them was ever accepted.

**The bound.** Retries stop at ``run_publication_max_attempts`` and the row
stays ``dead``. That is the honest end: an installation whose store has been
refusing for ten minutes needs an operator, not a slower timer. A dead row is
visible three ways — ``/api/health``, ``octo_run_publication_backlog`` and a
note on the job's ``error`` — and its tree is kept on disk for a day from the
upload's acceptance (see the sweep in ``workspace``), so the decision is "publish it by hand or re-scan",
never "the scan is gone and nothing said so".

A claimed row is held out of the due window, and the hold is *renewed* while
the work runs (:class:`_Lease`): a publication is minutes of store and broker
work and a horizon is a guess, so the guess only has to cover the gap between
two renewals rather than the whole transfer. A replica that dies stops renewing
and the row falls due one horizon later. That renewal is also the row's proof
of life for a peer that cannot see its tree.

Safe in every replica without leader election, like the job reaper: due-ness
is a property of the row and rows are claimed with ``FOR UPDATE SKIP LOCKED``.
The paths in a row are on one replica's disk, though, so a peer that claims a
row it cannot see gives it back instead of declaring the run lost — see
:func:`_claim_due`. Bounded as well: a pod's ``emptyDir`` cache takes its
staging trees with it, so a row offered around for
``run_publication_orphan_deadline_seconds`` with nobody able to see the tree
ends ``dead`` like any other publication that cannot be finished, rather than
circulating silently forever (:func:`_give_back`). The symmetric end is bounded
too: a row claimed over and over by a replica that dies before it can record
anything — the large tree and the OOM killer, which is the example the attempt
counter was moved out of the claim for — ends ``dead`` on its claims rather
than crash-looping in silence (:func:`_claims_spent`).
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import func, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import metrics as metrics_service
from api.services import nats_outbox
from api.services import results_ingest
from api.services import run_completion
from api.services import runs as runs_service
from api.services.artifact_store import keys as artifact_keys
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

#: Why a publication is dead with no attempt behind it: every replica that took
#: it died before it could record anything. See :func:`_claims_spent`.
_NEVER_ATTEMPTED = (
    "this publication has been claimed far more often than it may be attempted, without "
    "one attempt reaching an outcome, so whichever replica takes it is dying "
    "mid-publication; this run needs a re-scan or a manual load"
)

#: Why a publication is dead although the run itself is readable: every step
#: but the bus hop has landed, and the archive that hop needs is gone. Named
#: because the operator's answer differs — there is nothing to requeue or
#: re-scan for, only the analytical projection to give up on.
_ARCHIVE_IS_GONE = (
    "the uploaded archive is no longer on disk, so the analytical projection "
    "cannot be fed for this run; the run itself is published"
)

#: Ceiling on how often a running publication pushes its row's hold forward.
#: The period is the smaller of this and a third of the horizon, so one missed
#: renewal still leaves two more before the row falls due.
_LEASE_RENEW_SECONDS = 15.0


def _now() -> datetime:
    """Naive UTC, matching ``jobs`` and every timestamp column in this schema."""
    return datetime.now(UTC).replace(tzinfo=None)


def _db_now(session) -> datetime:
    """The database's clock, naive UTC like :func:`_now`.

    For the one timestamp two pods compare: ``leased_until`` is written by the
    pod running an attempt and read by whichever pod serves an operator's
    button. ``clock_timestamp()`` rather than ``now()``, which is the start of
    a transaction that may have waited on the row lock.

    Postgres only. The SQLite dev fallback has neither function — asking it
    raised on every job card, on both buttons and on every lease renewal, so
    the hold was never pushed forward — and it is one process with one clock,
    which is what :func:`_now` already is (as in ``leader_lock`` and
    ``auth_audit``).
    """
    if session.get_bind().dialect.name != "postgresql":
        return _now()
    return session.execute(select(func.timezone("UTC", func.clock_timestamp()))).scalar_one()


#: An absolute path of two components or more. Not preceded by ``:`` or
#: ``/``, so the path of a URL (``s3://bucket/key``) is not one.
_ABSOLUTE_PATH = re.compile(r"(?<![\w:/.~-])/(?:[^\s/'\"]+/)+([^\s/'\"]+)")


def redact_paths(text: str | None) -> str | None:
    """Cut every absolute path in ``text`` down to its last component.

    For a reason a tenant reads — on the job, in ``/publications`` and in the
    audit trail. A failure is recorded as ``f"{type}: {exc}"``, and an
    ``OSError`` names the staging tree on the pod's disk, which the route
    withholds from everyone but the platform admin. The last component stays
    because it is what says what went wrong (``tenant.json``, ``.upload``).
    """
    if not text:
        return text
    return _ABSOLUTE_PATH.sub(lambda match: f"…/{match.group(1)}", text)


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
    updated_at: datetime | None
    attempts: int
    claims: int
    claims_base: int
    stored_at: datetime | None
    fence: int
    last_error: str | None


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
        updated_at=row.updated_at,
        attempts=row.attempts or 0,
        claims=row.claims or 0,
        claims_base=row.claims_base or 0,
        stored_at=row.stored_at,
        fence=row.fence or 0,
        last_error=row.last_error,
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
        claims=0,
        claims_base=0,
        fence=0,
        lease_lapses=0,
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
    the tree a ``rmtree`` racing an ``upload_tree``. The claim is a floor and
    the work renews it as it goes (:class:`_Lease`), so "minutes" is what the
    hold actually covers rather than what it was rounded to. A row a peer is
    already holding is left to it: ``False`` here is "not published by me".

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


class _HalfPublished(RuntimeError):
    """The upload failed and the keys it wrote could not be taken back.

    Carries its own message rather than a type name, because this one is read
    by an operator on the job: the run may be listed by every replica with
    files missing from it until an attempt succeeds, and that is worth saying
    where they are looking.
    """


def _attempt(settings: Settings, publication: _Publication) -> bool:
    """One publication attempt, with its outcome written back.

    Under a renewing lease: the claim held the row for one horizon, and this
    is the work that horizon was a guess at. See :class:`_Lease`.
    """
    try:
        with _Lease(settings, publication):
            _publish(settings, publication)
    except _TreeIsGone as exc:
        _record_failure(settings, publication, str(exc) or _TREE_IS_GONE, final=True)
        return False
    except _HalfPublished as exc:
        _record_failure(settings, publication, str(exc))
        return False
    except Exception as exc:  # noqa: BLE001 - every failure here is a retry
        _record_failure(settings, publication, f"{type(exc).__name__}: {exc}")
        return False
    _record_success(settings, publication)
    return True


class _Lease:
    """Keeps a claimed row out of the due window for as long as the work runs.

    A claim pushes ``next_attempt_at`` out by one horizon, and the horizon is a
    constant — while the docstrings around it, correctly, call a publication
    "minutes of store and broker work". A tree that outlived the constant was
    found due by the next tick in any replica and published a second time
    alongside the first: two messages on the bus, two notifications, two
    projections, and an ``upload_tree`` racing the ``rmtree`` that promotes the
    same staging tree.

    So the hold is renewed from a thread of its own while the work runs, and
    the constant only has to cover the gap between two renewals. A replica that
    dies stops renewing and the row falls due one horizon later, which is what
    the claim was reaching for to begin with.

    The renewal stamps ``updated_at`` as well, and that is the second thing it
    is for: to a peer holding a row whose tree it cannot see, that stamp is the
    difference between "the replica that accepted this upload is gone" and "it
    is still working on it" (:func:`_is_orphaned`).

    The third is ``leased_until``, which an operator's requeue and discard read
    (#425). It is stamped from the moment the attempt starts and on every
    renewal *whatever the row's status*: a row goes ``dead`` when one attempt
    records its last failure, and another attempt that took the row while the
    first one's hold had lapsed is still running then. Stopping at ``dead``, as
    this class used to, made that attempt invisible to exactly the button that
    would start a third one beside it. The stamp only moves forward, so two
    attempts renewing one row cannot shorten each other's proof of life.

    A renewal that fails or lands after the previous hold had already lapsed is
    the precondition of that second attempt, and until #426 it was a log line.
    It is counted now (``octo_run_publication_lease_renewal_total``) and marked
    on the row (``lease_lapses``); a failed renewal is marked by the next one
    that reaches the database, because the one that failed could not.
    """

    def __init__(self, settings: Settings, publication: _Publication) -> None:
        self._settings = settings
        self._publication_id = publication.publication_id
        self._fence = publication.fence
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # This attempt's own hold as it last stamped it, and the lapses it has
        # not been able to write down yet.
        self._held_until: datetime | None = None
        self._unrecorded_lapses = 0
        self._superseded = False

    def __enter__(self) -> "_Lease":
        # Stamped before the work starts, not one period into it: an operator
        # reading the row in between would otherwise see no attempt at all.
        self._renew()
        period = min(_LEASE_RENEW_SECONDS, _lease_horizon_seconds(self._settings) / 3)
        self._thread = threading.Thread(
            target=self._run, args=(period,), name="octo-publication-lease", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        return False

    def _run(self, period: float) -> None:
        while not self._stop.wait(period):
            self._renew()

    def _renew(self) -> None:
        now = _now()
        until = now + timedelta(seconds=_lease_horizon_seconds(self._settings))
        late = self._held_until is not None and now > self._held_until
        try:
            with get_session(self._settings.postgres_url) as session:
                row = session.get(models.RunPublication, self._publication_id)
                if row is None:
                    # Finished, or discarded. Nothing to hold.
                    self._stop.set()
                    return
                superseded = (row.fence or 0) != self._fence
                lapses = self._unrecorded_lapses
                if superseded and not self._superseded:
                    lapses += 1
                elif late and not superseded:
                    lapses += 1
                if lapses:
                    row.lease_lapses = (row.lease_lapses or 0) + lapses
                # On the database's clock, which is the one the operator's
                # button reads it by (:func:`_is_leased`). ``next_attempt_at``
                # stays on this pod's: the reconciler compares it with its own.
                held = _db_now(session) + timedelta(
                    seconds=_lease_horizon_seconds(self._settings)
                )
                if row.leased_until is None or row.leased_until < held:
                    row.leased_until = held
                if row.status == STATUS_PENDING:
                    row.next_attempt_at = until
                    row.updated_at = now
        except Exception:  # noqa: BLE001 - a lost renewal is not a failed publication
            # The work goes on. Losing a renewal costs at worst the duplicate
            # publication this class exists to prevent, which is what the code
            # did before it existed; failing the publication over a database
            # hiccup would cost the run instead.
            self._unrecorded_lapses += 1
            metrics_service.RUN_PUBLICATION_LEASE_RENEWALS_TOTAL.labels(outcome="failed").inc()
            LOG.warning(
                "Could not renew the publication lease for %s", self._publication_id,
                exc_info=True,
            )
            return
        self._unrecorded_lapses = 0
        self._held_until = until
        if superseded:
            outcome = "superseded"
            if not self._superseded:
                LOG.warning(
                    "Publication %s was claimed by another attempt (or requeued) while "
                    "this one was still running; both are publishing it now",
                    self._publication_id,
                )
            self._superseded = True
        elif late:
            outcome = "late"
            LOG.warning(
                "Publication %s renewed its hold after the hold had lapsed; a peer "
                "may have claimed it meanwhile",
                self._publication_id,
            )
        else:
            outcome = "renewed"
        metrics_service.RUN_PUBLICATION_LEASE_RENEWALS_TOTAL.labels(outcome=outcome).inc()


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
    steps' way of saying they are done (:func:`_tree_is_stored`).
    """
    staging = Path(publication.staging_path) if publication.staging_path else None
    run_id = publication.run_id
    run = _run_ref(publication)
    if staging is not None and staging.is_dir():
        runs_service.stage_run_tenant(
            staging,
            publication.tenant_id,
            job_id=publication.job_id,
            surface=publication.surface,
        )
        # Into the store from staging: the copy the other replicas read is
        # complete and marked the first time they can see it.
        written: list[str] = []
        try:
            artifact_workspace.publish_run(settings, run, source=staging, written=written)
        except Exception as exc:
            # A remote backend uploads the tree file by file, and a store that
            # starts refusing halfway leaves keys under ``runs/<run_id>/``. A
            # run listing is the children of ``runs/``, so those keys are a
            # scan every replica can see and open, with whatever did not make
            # it simply missing. The half is taken back off before the failure
            # is recorded, so a retry starts from nothing and a row that ends
            # ``dead`` costs the run its visibility rather than leaving a
            # partial one that reads as complete.
            if _roll_back_upload(settings, publication, written):
                raise
            raise _HalfPublished(
                f"{type(exc).__name__}: {exc} — and the {len(written)} key(s) this "
                "attempt had already written could not be taken back, so the run may "
                "be listed by every replica with files missing from it"
            ) from exc
        # The whole tree is in the store now, and ``_record_success`` will not
        # say so for another archive upload. Stamped before the promotion
        # rather than after it, because the promotion is what a second attempt
        # trips over — it takes the staging tree both are reading — and the
        # stamp is what stops that attempt taking these keys back off again
        # (:func:`_may_take_back`).
        _mark_stored(settings, publication)
        # The marker cache on a remote backend may hold a "no marker" answer
        # from a listing that asked about this run before it existed, and
        # reading that back is the default-tenant leak the marker prevents.
        artifact_workspace.forget_run_marker(run)
        artifact_workspace.promote_staging(settings, run, staging)
    elif not _tree_is_stored(settings, publication):
        raise _TreeIsGone(_TREE_IS_GONE)
    results_ingest.update_latest_run_pointer(settings.state_dir, run_id)
    _publish_to_bus(settings, publication)


def _tree_is_stored(settings: Settings, publication: _Publication) -> bool:
    """Whether a *finished* attempt put this run's tree where replicas read it.

    Two questions, because either alone answers yes too early:

    * the store's own answer is "is there a key under ``runs/<run_id>/``",
      which is true from the **first** key of an upload that is still running.
      A peer that adopted a row whose owner had merely stopped renewing read
      that as "already published", skipped the upload of a half-written tree
      and closed the row out — a run every replica lists with most of it
      missing, and nothing owing it any more.
    * ``stored_at`` alone is an attempt saying it finished uploading, which on
      the local backend is not yet a readable run: the stamp goes on before
      ``promote_staging``, deliberately (:func:`_roll_back_upload`), and that
      move is what makes the tree readable there. A row whose promotion failed
      would otherwise be "published" on the strength of a tree nobody has.

    Together they mean what the caller needs: some attempt carried the whole
    tree up, and the store has the result.
    """
    if publication.stored_at is None:
        return False
    if artifact_workspace.run_exists(settings, _run_ref(publication)):
        return True
    # Stored by a replica that predates #427, at the flat ``runs/<run_id>``:
    # the tree is there and readable (``runs.resolve_run`` falls back to it),
    # so it is not gone. Only if it is this tenant's, which its marker says.
    flat = artifact_keys.run_ref(publication.run_id)
    return (
        artifact_workspace.run_exists(settings, flat)
        and runs_service.run_tenant_of(settings, flat) == publication.tenant_id
    )


def _run_ref(publication: _Publication) -> artifact_keys.RunRef:
    """Where this publication's run lives: under its tenant, since #427."""
    return artifact_keys.run_ref(publication.run_id, publication.tenant_id)


def _mark_stored(settings: Settings, publication: _Publication) -> None:
    """Record that this run's tree is in the store, whatever else is left.

    Not best-effort: a database that refuses this write is one that cannot
    record the outcome either, and the retry it buys re-publishes a run that
    is already readable — which every step here is built to survive — while
    swallowing it would leave the fence down for the attempt that needs it.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is None:  # pragma: no cover - finished by a peer mid-flight
            return
        row.stored_at = now
        row.updated_at = now


def _roll_back_upload(
    settings: Settings, publication: _Publication, written: list[str]
) -> bool:
    """Undo what this attempt put in the store. Answers whether the store is clean.

    Two things it must not do, both of them silent loss of a published scan:

    * **remove the run's prefix.** ``delete_prefix("runs/<run_id>")`` is a run
      deleter wearing a rollback's name. The prefix can hold keys this attempt
      never wrote — an attempt in another replica that succeeded, or, while run
      ids are minted from a one-second clock, a different job's run — and a
      failed publication then deleted a scan that was complete, across tenants.
      So the keys this transfer actually wrote are collected as they land and
      those are what goes.
    * **run at all after another attempt has published this run.** The keys
      are the *same* keys then, so removing "only what this attempt wrote"
      would still take the published run apart file by file. ``stored_at`` is
      the fence, and the row is not: the winner stamps the tree as stored
      before it promotes it, then spends an archive upload on the bus before
      ``_record_success`` deletes the row — and a loser that read the row
      would spend that whole upload believing nothing had been published yet,
      having been woken by the very promotion the stamp precedes. The lease
      above is what makes the race rare; this is what makes it harmless.
    """
    if not written:
        return True
    if not _may_take_back(settings, publication):
        LOG.warning(
            "Run %s was published by another attempt while this one was uploading; "
            "leaving the %d key(s) this attempt wrote where they are",
            publication.run_id,
            len(written),
        )
        return True
    run = _run_ref(publication)
    artifact_workspace.unpublish_run(settings, run, only=written)
    artifact_workspace.forget_run_marker(run)
    try:
        return not artifact_workspace.run_exists(settings, run)
    except Exception:  # noqa: BLE001 - the outage that refused the upload, again
        # Asked rather than assumed, because the answer is what the operator is
        # told: a store too broken to list is too broken to have been cleaned.
        return False


def _may_take_back(settings: Settings, publication: _Publication) -> bool:
    """Whether this attempt's keys are still its own to remove.

    ``False`` once any attempt has put the run's tree in the store — because
    the row is gone (``_record_success``) or because it carries ``stored_at``
    and the winner is still on the bus. Either way the keys under this run are
    a published scan and the caller's job is to leave them alone.

    ``stored_at`` alone left the widest window of the three open: it is
    stamped after the winner's *whole* tree is up, so while the winner is
    still inside ``upload_tree`` it is honestly NULL — and the keys it has
    already written carry the same names this attempt wrote, which is what
    makes ``only=written`` no defence at all. A loser whose own store refused
    it halfway (the failure this rollback exists for, and one made more likely
    by two attempts hammering one bucket) then deleted files out of the run the
    winner was in the middle of publishing.

    So the claim counter is the second condition: every attempt claims the row
    before it touches the store (``_hold``, and ``publish_now`` claims exactly
    as a tick does), so a claim taken since this one means somebody else has
    been working this row — and it is visible from the first key the other
    attempt writes rather than from its last.

    And ``fence`` is the third, because ``claims`` used not to be monotonic:
    it started over whenever an attempt recorded an outcome. An attempt that
    took the row as its first claim, lost its lease, and woke after a peer had
    failed and a third attempt had claimed read ``claims == 1`` again — its own
    number — and took the third attempt's keys for its own. ``claims`` only
    grows now (the budget counts from ``claims_base``), but a replica on the
    previous release still resets it, so ``fence`` — which only this release
    moves, on every claim and on an operator's requeue (#425) — stays the
    condition that cannot come back round.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id)
        if row is None or row.stored_at is not None:
            return False
        return (row.claims or 0) == publication.claims and (
            row.fence or 0
        ) == publication.fence


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

    **A refused publish is handed to the outbox, not retried here.** This is
    the last step of the publication, and the three before it — the store, the
    run directory, the pointer — are done by the time it runs, as are the
    Postgres projections waiting on :func:`_record_success`. Failing the whole
    row on a broker that is down therefore held *those* hostage too: a ten
    minute outage spent this row's five attempts, ended it ``dead``, and left
    every run of that window without its assets, its findings and its
    notification, over a message for ClickHouse. So the message is published or
    written down (``nats_outbox``), and either outcome closes the publication.
    The two mechanisms own disjoint work — this module up to and including the
    hand-off, the outbox reconciler the hop itself — so neither retries what
    the other is retrying.

    Refusing without recording is still a failure of the publication: with
    ``OCTO_NATS_OUTBOX_ENABLED=false`` nothing durable is left behind, and an
    upload whose message is neither delivered nor written down must not read as
    published.
    """
    if not settings.nats_url:
        return
    archive = Path(publication.archive_path) if publication.archive_path else None
    if archive is None or not archive.is_file():
        raise _TreeIsGone(_ARCHIVE_IS_GONE)
    result = nats_outbox.publish_ingest_or_record(
        settings,
        job_id=publication.job_id,
        run_id=publication.run_id,
        agent_id=publication.agent_id or "",
        exit_code=publication.exit_code if publication.exit_code is not None else 0,
        archive_bytes=archive.read_bytes(),
        error=publication.scan_error,
        tenant_id=publication.tenant_id,
    )
    if not result.get("published") and not result.get("outbox_id"):
        raise RuntimeError("the broker refused the ingest publish and the outbox is disabled")


def _record_success(settings: Settings, publication: _Publication) -> None:
    """Close the row out, drop the archive, and feed what reads the run.

    The projections run here, not in ``complete_job``: they read the run
    directory, so before the publication there is nothing for them to read,
    and after a deferred publication they are owed exactly as much as the run
    is. Each one guards itself; a failure among them is a note on the job, not
    a reason to publish the run twice.

    The "run not published" note is decided from the row as it is *now*,
    locked, and not from this attempt's snapshot. The snapshot was taken at
    the claim, and the row may have died since: a peer that took it while this
    attempt's hold lapsed gave up, ended it ``dead`` and put the note on the
    job — and this attempt then published the run and deleted the row, looking
    at a snapshot with no error on it. A published run whose job said it was
    not, with no row and no button left to explain it. The peer writes the
    note in the transaction that ends the row (``_record_failure``) under the
    same lock, so the two cannot interleave.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RunPublication, publication.publication_id, with_for_update=True)
        if row is not None:
            failed_before = row.last_error is not None or row.status == STATUS_DEAD
            reasons = [row.last_error] if row.last_error else []
            session.delete(row)
            if failed_before:
                _clear_notes(session, publication, reasons)
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
    run_completion.on_run_published(
        settings,
        publication.job_id,
        run_id=publication.run_id,
        tenant_id=publication.tenant_id,
        status=publication.job_status,
    )


def _clear_notes(session, publication: _Publication, reasons: list[str]) -> None:
    """Take this publication's notes off the job, in a savepoint of their own.

    Fail-soft, because the delete beside it is not optional: a failure here
    rolling the whole transaction back would keep the row and publish the run
    again on the next tick — harmless, but forever, if what fails is the job
    row itself. Only the note is lost then, and the log says so.
    """
    try:
        with session.begin_nested():
            run_completion.clear_publication_notes(
                session,
                publication.job_id,
                publication_id=publication.publication_id,
                reasons=[redact_paths(reason) for reason in reasons] + reasons,
            )
    except Exception:  # noqa: BLE001 - a stale note must not cost the publication
        # Counted and logged with the job, because the job is then the one
        # place that says the run was not published while it was: this is
        # how an operator finds it.
        metrics_service.RUN_PUBLICATION_STALE_NOTES_TOTAL.inc()
        LOG.warning(
            "Run %s of job %s is published, but the note saying it was not could not "
            "be taken off the job's error",
            publication.run_id,
            publication.job_id,
            exc_info=True,
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
        # Locked: the note below is written in this transaction, and a peer
        # closing the row out as published reads it under the same lock.
        row = session.get(
            models.RunPublication, publication.publication_id, with_for_update=True
        )
        if row is None:  # pragma: no cover - deleted by a peer mid-flight
            return
        row.attempts += 1
        row.updated_at = now
        # An attempt that reached an outcome is what the claim budget was
        # counting the absence of, so it starts over — from here, not from 0:
        # ``claims`` itself is a fence a previous release reads, and setting
        # it back hands a stale attempt its own number again.
        row.claims_base = row.claims or 0
        row.last_error = reason[:2000]
        spent = final or row.attempts >= settings.run_publication_max_attempts
        if spent:
            row.status = STATUS_DEAD
            row.next_attempt_at = None
            # On the job as well as in the table: the operator looking at a
            # scan that says ``succeeded`` with no artifacts behind it is
            # looking at the job, and the row is the thing they have not been
            # told about yet. Everyone who can read the job reads this, so
            # the pod's paths are taken out of it.
            run_completion.note_publication_failed(
                session,
                publication.job_id,
                publication_id=publication.publication_id,
                reason=redact_paths(reason),
            )
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


def _lease_horizon_seconds(settings: Settings) -> int:
    """How far one hold pushes a row, and how far each renewal pushes it again.

    Not the length of the work — that is unbounded by anything this process
    controls — but the gap a renewal has to cover, plus the margin a replica
    that died gets before a peer may take its row (:class:`_Lease`).
    """
    return max(60, settings.run_publication_interval_seconds)


def _hold(row: models.RunPublication, *, now: datetime, rows: int, settings: Settings) -> None:
    """Push one claimed row out of the due window, and count the claim.

    The window covers the whole batch rather than one row, because the rows
    are published after the claiming transaction commits and a batch of runs
    is minutes of work: a peer must not claim the tail of a batch that is
    still being published. It is a floor, not the whole horizon — the work
    renews it as it runs.

    Attempts are *not* counted here. A claim is not an attempt: a replica the
    OOM killer takes down while publishing a large run would otherwise write
    off one attempt per restart for every row it was holding, and five
    restarts would leave a batch ``dead`` without the store having refused
    once. They are counted where a failure is recorded instead. Claims are
    counted here, because the same replica dying every time is the one thing
    an attempt counter cannot see (:func:`_claims_spent`).

    ``updated_at`` is deliberately left alone. It means "some replica was
    demonstrably working on this row at that moment", which a claim is not yet
    and a claim a peer hands straight back never was; a peer's orphan deadline
    reads it, and a claim that stamped it would keep pushing that deadline out
    of reach every adoption window.
    """
    per_row = _lease_horizon_seconds(settings)
    row.next_attempt_at = now + timedelta(seconds=per_row * max(1, rows))
    if (row.claims or 0) < (row.claims_base or 0):
        # A replica on the release before 0062 recorded an outcome: it writes
        # ``claims = 0`` and knows nothing of the base, which would read as a
        # negative count and stretch the budget by as much.
        row.claims_base = 0
    row.claims = (row.claims or 0) + 1
    # The generation the rollback fence compares, and the one ``claims``
    # cannot be: that counter starts over whenever an attempt records an
    # outcome, so it can come back to the very value a stale attempt holds.
    row.fence = (row.fence or 0) + 1


def _claim_budget(settings: Settings) -> int:
    """How often a row may be claimed before it is written off unattempted."""
    return max(2 * settings.run_publication_max_attempts, 4)


def _claims_spent(settings: Settings, publication: _Publication) -> bool:
    """Whether this row has been taken far more often than it has been tried.

    The other bound here counts *attempts*, and an attempt is something that
    was tried and refused — deliberately, so a replica the OOM killer takes
    down mid-batch does not write one off per restart. That left the symmetric
    end open: a publication whose tree is large enough to kill the replica
    every time is claimed, dies before it can record anything, and is claimed
    again one horizon later, forever. ``_is_orphaned`` never looks at it (the
    row is not foreign), ``is_backlogged`` counts only ``dead``, the job says
    ``succeeded`` with an empty ``error`` — the exact silence this module was
    written to end, on the very example the attempt counter was moved for.

    Twice the permitted attempts is the margin: an ordinary retry spends one
    claim per attempt, so nothing that reaches an outcome can come near it.
    Counted from ``claims_base``, which reaching an outcome, a requeue and a
    claim handed straight back to its owner all move up to ``claims``
    (:func:`_give_back`) — ``claims`` itself never goes back down.
    """
    return publication.claims - publication.claims_base > _claim_budget(settings)


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

    "In the store" is :func:`_tree_is_stored` and not a bare listing: a
    listing says yes to the first key of an upload that is still running, so a
    peer that adopted the row of an owner which had only stopped renewing took
    it for a published run, skipped the upload and closed the row out.
    """
    if publication.replica in (None, settings.instance_id):
        return False
    staging = Path(publication.staging_path) if publication.staging_path else None
    if staging is not None and staging.is_dir():
        return False
    return not _tree_is_stored(settings, publication)


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
        # Neither this claim nor this hand-back was work on the row: the claim
        # is taken off the budget so a row offered around every adoption
        # window cannot exhaust it — by moving the base, since ``claims`` is a
        # fence and must not come back round — and ``updated_at`` is left
        # alone so the orphan deadline keeps running from the last time
        # somebody really published.
        row.claims_base = (row.claims_base or 0) + 1
    return True


def _is_orphaned(settings: Settings, publication: _Publication, *, now: datetime) -> bool:
    """Whether a row this replica cannot see has gone untouched past its deadline.

    Measured from ``updated_at``: the last moment some replica was
    demonstrably working on this row — a running publication renews it every
    few seconds (:class:`_Lease`) and a recorded failure writes it. Measured
    from ``created_at``, as it was, the clock ran from the *acceptance of the
    upload*, so a replica that is alive and has been retrying a slow store for
    an hour had its row condemned by a peer that cannot see its tree, four
    milliseconds after the owner last touched it — and the run was then
    reported as needing a re-scan while its tree sat on a running pod's disk.
    """
    touched = publication.updated_at or publication.created_at
    if touched is None:  # pragma: no cover - both columns are written with the row
        return False
    return (now - touched) > timedelta(seconds=_orphan_deadline_seconds(settings))


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
        if _claims_spent(settings, publication):
            # Before the attempt, not after: the attempt is what has been
            # killing the replica that takes this row.
            _record_failure(settings, publication, _NEVER_ATTEMPTED, final=True)
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


class PublicationInFlight(ValueError):
    """An operator action on a row some attempt is still proving it works on.

    Carries the moment that proof of life runs out, so the caller can say when
    to ask again rather than only "not now".
    """

    def __init__(self, message: str, *, leased_until: datetime, now: datetime) -> None:
        super().__init__(message)
        self.leased_until = leased_until
        self.retry_after_seconds = max(1, int((leased_until - now).total_seconds()) + 1)


def _iso(value: datetime | None) -> str | None:
    return value.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z") if value else None


def _is_leased(row: models.RunPublication, *, db_now: datetime) -> bool:
    """Whether a running attempt still holds this row, on the database's clock.

    ``leased_until`` is written by the pod running the attempt and read by
    whichever pod serves the button, so both sides use the database's clock
    (:func:`_db_now`): each pod's own, and a skew between two of them past one
    horizon, read a live attempt as a lease that had long expired.
    """
    return row.leased_until is not None and row.leased_until > db_now


def _tree_kept_until(row: models.RunPublication) -> datetime | None:
    """Until when the accepting pod may still have the extracted tree.

    A day from the *acceptance*, not from the last attempt: the sweep
    (``workspace._sweep_abandoned``) reads the staging directory's
    ``st_mtime``, which only the first ``tenant.json`` moves.
    """
    if row.created_at is None:  # pragma: no cover - written with the row
        return None
    return row.created_at + timedelta(seconds=artifact_workspace.INGEST_KEPT_SECONDS)


def _resolution(row: models.RunPublication, *, now: datetime) -> str:
    """What an operator can usefully do about one row, as the console shows it.

    ``wait`` while it is owed and somebody is on it; ``rescan`` when the tree
    it would publish is on no disk this installation can reach — a requeue
    would only walk it back to ``dead``; ``discard`` when the run itself is
    readable and only the analytical projection is lost; ``requeue`` for every
    other ``dead`` row, once whatever refused it (the store, the broker, the
    pod's memory limit) has been fixed.

    Past :func:`_tree_kept_until` a row the store never took whole is a
    ``rescan`` whatever it died of: the sweep has had the tree, so a requeue
    would only walk it to ``_TreeIsGone`` and put a second note on the job.
    """
    if row.status != STATUS_DEAD:
        return "wait"
    reason = row.last_error or ""
    if reason == _ARCHIVE_IS_GONE:
        return "discard"
    if reason in (_REPLICA_IS_GONE, _TREE_IS_GONE):
        # Both are written only when no reachable copy of the tree was found
        # — not in staging, and not whole in the store (``_tree_is_stored``).
        return "rescan"
    kept_until = _tree_kept_until(row)
    if row.stored_at is None and kept_until is not None and now > kept_until:
        return "rescan"
    return "requeue"


def _view(
    settings: Settings,
    row: models.RunPublication,
    *,
    now: datetime,
    db_now: datetime,
    show_paths: bool,
) -> dict[str, Any]:
    """One row as ``GET /api/jobs/{id}/publications`` reports it.

    ``staging_path``, ``archive_path`` and ``replica`` name a pod and a path on
    its disk: what the runbook's manual load needs, and nothing a tenant can
    act on — that step takes a shell on the pod. So they are the platform
    admin's only.

    ``silent`` is the HA overlay's orphan told apart from a slow store: a
    pending row nobody holds, which neither its own replica's next retry nor a
    peer's adoption has touched in the time both should have. On an
    ``emptyDir`` cache that is a pod the autoscaler took away with the only
    copy of the tree; it ends ``dead`` at ``orphan_deadline_at`` needing a
    re-scan, and the console says so now rather than an hour later.

    ``last_error`` is ``f"{type}: {exc}"`` and an ``OSError`` carries the full
    path of the staging tree, so for everyone but the platform admin its paths
    are cut to their last component (:func:`redact_paths`).
    """
    leased = _is_leased(row, db_now=db_now)
    touched = row.updated_at or row.created_at
    silent = False
    orphan_deadline_at = None
    if row.status == STATUS_PENDING and touched is not None:
        orphan_deadline_at = touched + timedelta(seconds=_orphan_deadline_seconds(settings))
        quiet_for = timedelta(
            seconds=_retry_delay_seconds(row.attempts or 0, settings)
            + _adoption_seconds(settings)
        )
        silent = not leased and (now - touched) > quiet_for
    dead = row.status == STATUS_DEAD
    return {
        "publication_id": row.publication_id,
        "job_id": row.job_id,
        "run_id": row.run_id,
        "tenant_id": row.tenant_id,
        "status": row.status,
        "state": "dead" if dead else "publishing" if leased else "retrying",
        "resolution": _resolution(row, now=now),
        "attempts": row.attempts or 0,
        "max_attempts": settings.run_publication_max_attempts,
        # Claims since the last outcome: what the budget counts.
        # Floored: a replica on the previous release resets ``claims`` and
        # not the base, until the next claim here starts the base over.
        "claims": max(0, (row.claims or 0) - (row.claims_base or 0)),
        "lease_lapses": row.lease_lapses or 0,
        "last_error": row.last_error if show_paths else redact_paths(row.last_error),
        "stored_at": _iso(row.stored_at),
        "tree_kept_until": _iso(_tree_kept_until(row)),
        "next_attempt_at": _iso(row.next_attempt_at),
        "leased_until": _iso(row.leased_until),
        "silent": silent,
        "orphan_deadline_at": _iso(orphan_deadline_at),
        "actionable": dead and not leased,
        "actionable_at": _iso(row.leased_until) if dead and leased else None,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "replica": row.replica if show_paths else None,
        "staging_path": (row.staging_path or None) if show_paths else None,
        "archive_path": row.archive_path if show_paths else None,
    }


def publications_for_job(
    settings: Settings, job_id: str, *, tenant_id: str | None, show_paths: bool = False
) -> list[dict[str, Any]]:
    """What one job still owes, newest first, for the console (#425).

    ``tenant_id`` is the caller's scope — ``None`` for a platform admin — and a
    row in another tenant is not there, like a job in another tenant.
    """
    now = _now()
    query = (
        select(models.RunPublication)
        .where(models.RunPublication.job_id == job_id)
        .order_by(models.RunPublication.created_at.desc())
    )
    if tenant_id is not None:
        query = query.where(models.RunPublication.tenant_id == tenant_id)
    with get_session(settings.postgres_url) as session:
        db_now = _db_now(session)
        return [
            _view(settings, row, now=now, db_now=db_now, show_paths=show_paths)
            for row in session.execute(query).scalars().all()
        ]


def _operator_row(
    session, publication_id: str, *, job_id: str | None, tenant_id: str | None
) -> models.RunPublication | None:
    """The row an operator named, locked, or ``None`` when it is not theirs.

    A plain ``FOR UPDATE``: the reconciler's claim is ``SKIP LOCKED``, so while
    this transaction holds the row no tick can take it, and whatever is decided
    here is what the next claim sees.
    """
    row = session.get(models.RunPublication, publication_id, with_for_update=True)
    if row is None:
        return None
    if job_id is not None and row.job_id != job_id:
        return None
    if tenant_id is not None and row.tenant_id != tenant_id:
        return None
    return row


def _refuse_while_leased(
    row: models.RunPublication, *, db_now: datetime, action: str
) -> None:
    """The operator's half of the fence: no decision beside a running attempt.

    ``dead`` is one attempt giving up, not every attempt having stopped (see
    :class:`_Lease`), and both actions go wrong beside one that is still
    running. A requeue starts a second publication of the same keys — two
    uploads of one tree, and a rollback in either that removes names the other
    has just written. A discard deletes the row the running attempt reads its
    rollback fence from, and ``_may_take_back`` reads a missing row as
    "published by somebody else": a store that refuses that attempt halfway
    then leaves half a run listed by every replica, with nothing owing it.
    """
    if row.status != STATUS_DEAD:
        raise ValueError(
            f"publication {row.publication_id} is {row.status}; only a dead publication "
            "can be requeued or discarded — a pending one is still being retried"
        )
    if _is_leased(row, db_now=db_now):
        assert row.leased_until is not None
        raise PublicationInFlight(
            f"publication {row.publication_id} is dead, but an attempt at it is still "
            f"running (its hold lasts until {_iso(row.leased_until)}); {action} it "
            "once that attempt has stopped",
            leased_until=row.leased_until,
            now=db_now,
        )


def _decision_record(row: models.RunPublication) -> dict[str, Any]:
    return {
        "job_id": row.job_id,
        "run_id": row.run_id,
        "status": row.status,
        "attempts": row.attempts or 0,
        # Read by the tenant's own auditors: no pod paths.
        "last_error": redact_paths(row.last_error),
        "stored_at": _iso(row.stored_at),
    }


def requeue_publication(
    settings: Settings,
    publication_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
    audit: audit_service.AuditContext | None = None,
    show_paths: bool = False,
) -> dict[str, Any] | None:
    """Give a ``dead`` publication a full set of attempts again (#425).

    The runbook's first way out, for the operator who has fixed what refused
    it — the store, the broker, the pod's memory limit. ``None`` for a row that
    is not there, or not in ``tenant_id``/``job_id``. A row that is already
    ``pending`` comes back unchanged, so a double click is not a second
    decision; one an attempt is still running on is refused
    (:class:`PublicationInFlight`).

    The requeue bumps ``fence``, as a claim does. Whatever was running before
    it — an attempt that lost its lease and has not noticed — then reads the
    row as somebody else's and leaves its own keys where they are, rather than
    taking back what the requeued attempt uploads (:func:`_may_take_back`).
    ``attempts`` and the claim budget start over: the budgets they enforce are
    for the world as it is now, not as it was when the row died. ``claims``
    itself does not — the budget counts from ``claims_base`` — because a
    replica on the release before 0062 fences its rollback on ``claims`` alone,
    and a requeue that set it back to 0 made the requeued attempt's first
    claim the number such an attempt was holding. ``last_error``
    stays, so the console still says what went wrong until something else does.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = _operator_row(session, publication_id, job_id=job_id, tenant_id=tenant_id)
        if row is None:
            return None
        db_now = _db_now(session)
        if row.status == STATUS_PENDING:
            return _view(settings, row, now=now, db_now=db_now, show_paths=show_paths)
        _refuse_while_leased(row, db_now=db_now, action="requeue")
        before = _decision_record(row)
        row.status = STATUS_PENDING
        row.attempts = 0
        # The budget starts over; ``claims`` does not (see ``_may_take_back``).
        row.claims_base = row.claims or 0
        row.fence = (row.fence or 0) + 1
        row.next_attempt_at = now
        # The orphan deadline runs from here: the operator is saying somebody
        # should try this again, and a row condemned on the old clock by the
        # first peer to look at it would not have been tried at all.
        row.updated_at = now
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_RUN_PUBLICATION_REQUEUE,
            resource_type="run_publication",
            resource_id=row.publication_id,
            tenant_id=row.tenant_id,
            before=before,
            after=_decision_record(row),
        )
        session.flush()
        view = _view(settings, row, now=now, db_now=db_now, show_paths=show_paths)
    metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="requeued").inc()
    LOG.warning(
        "Publication %s of job %s was requeued by an operator after %d attempt(s): %s",
        publication_id,
        view["job_id"],
        before["attempts"],
        before["last_error"],
    )
    _refresh_backlog_gauge(settings)
    return view


def discard_publication(
    settings: Settings,
    publication_id: str,
    *,
    job_id: str | None = None,
    tenant_id: str | None = None,
    audit: audit_service.AuditContext | None = None,
) -> bool:
    """Forget one owed publication. Answers whether there was one to forget.

    The way out of a ``dead`` row, for the operator who has either loaded the
    run by hand or decided to re-scan (see the runbook in
    ``docs/operations.md``). Reached from ``DELETE
    /api/jobs/{id}/publications/{publication_id}`` since #425 and still from
    the runbook's ``python -c``, with the same checks either way: only a
    ``dead`` row, and not while an attempt at it is still running
    (:func:`_refuse_while_leased`). ``False`` for a row that is not there, or
    not in ``tenant_id``/``job_id``.

    Only the row goes. The extracted tree and the archive beside it stay where
    they are until the ordinary sweep takes them — up to a day from the
    upload's acceptance, not from this call (:func:`_tree_kept_until`) — so a
    decision made in haste may still be recoverable. So does the note on the
    job: the run was not published, and that is still true.
    """
    with get_session(settings.postgres_url) as session:
        row = _operator_row(session, publication_id, job_id=job_id, tenant_id=tenant_id)
        if row is None:
            return False
        _refuse_while_leased(row, db_now=_db_now(session), action="discard")
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_RUN_PUBLICATION_DISCARD,
            resource_type="run_publication",
            resource_id=row.publication_id,
            tenant_id=row.tenant_id,
            before=_decision_record(row),
            after=None,
        )
        session.delete(row)
    metrics_service.RUN_PUBLICATIONS_TOTAL.labels(outcome="discarded").inc()
    LOG.warning(
        "Publication %s was discarded by an operator; the run it owed is not published",
        publication_id,
    )
    _refresh_backlog_gauge(settings)
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
    "PublicationInFlight",
    "PublicationReconciler",
    "discard_publication",
    "publications_for_job",
    "requeue_publication",
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
