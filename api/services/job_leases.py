"""Job lease and ingest-fencing primitives.

This module contains only ownership/lease invariants. It does not decide job
outcomes, publish offers, or project runs, which keeps the concurrency rules
usable by both queue and result-ingest code without importing the jobs monolith.
"""

from __future__ import annotations

import logging
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from collections.abc import Iterator

from api.db import models
from api.db.engine import get_session
from api.services import job_states
from api.settings import Settings

_log = logging.getLogger(__name__)


class StaleAttempt(ValueError):
    """An upload from a lease that has already expired and been reissued."""


@dataclass(frozen=True)
class IngestLease:
    """Who is allowed to write this job's outcome when the ingest finishes.

    Taken in ``complete_job``'s first transaction, on the row it has just
    checked, and carried through the ingest — which runs outside any
    transaction and lasts as long as an archive takes to extract and store.
    The terminal write is conditional on it, so a lease that lapsed meanwhile
    and an attempt the reaper handed to somebody else cost this upload its
    result rather than costing the *new* attempt its own.
    """

    job_id: str
    token: str
    attempt: int
    agent_id: str


def _now() -> datetime:
    """Naive UTC, matching the other Postgres-backed services."""
    return datetime.now(UTC).replace(tzinfo=None)


def lease_deadline(settings: Settings) -> datetime:
    return _now() + timedelta(seconds=max(settings.job_lease_seconds, 1))


def extend_lease(row: models.Job, deadline: datetime) -> None:
    """Push a lease deadline out, never pull it in.

    A heartbeat is worth one ``job_lease_seconds``, but a result being ingested
    is worth the longer ``job_ingest_lease_seconds`` (see
    :func:`open_ingest_lease`), and the agent goes on beating while its upload
    is processed. Assigning would let those beats shorten the window the
    ingest reserved, which is exactly the window the reaper must stay out of.
    """
    if row.claimed_until is None or row.claimed_until < deadline:
        row.claimed_until = deadline


def open_ingest_lease(settings: Settings, row: models.Job, *, agent_id: str) -> IngestLease:
    """Reserve the right to finish this job, on a row already locked.

    Also pushes the job's lease out by ``job_ingest_lease_seconds``: an upload
    being processed is proof of life, and without it an ingest longer than the
    remaining lease would have the reaper requeue a job whose result is at that
    moment being written. The fence below is what makes a stale result
    *refused*; this is what keeps that refusal rare.
    """
    token = uuid.uuid4().hex
    row.ingest_token = token
    row.ingest_attempt = row.attempts or 0
    row.ingest_agent_id = agent_id
    row.ingest_started_at = _now()
    if row.status in job_states.IN_FLIGHT:
        extend_lease(
            row, _now() + timedelta(seconds=max(settings.job_ingest_lease_seconds, 1))
        )
    return IngestLease(
        job_id=row.job_id, token=token, attempt=row.ingest_attempt, agent_id=agent_id
    )


def check_ingest_fence(row: models.Job, fence: IngestLease) -> None:
    """Raise unless this row is still the one ``fence`` was taken on.

    All three parts are load-bearing. The token says no other upload has been
    accepted for ingest since; the attempt says the lease was not expired and
    reissued (a restarted worker keeps its ``agent_id``, so the attempt is the
    only thing that tells two of its uploads apart); the owner says the job was
    not handed to a different agent altogether.
    """
    if (
        row.ingest_token == fence.token
        and (row.attempts or 0) == fence.attempt
        and row.assigned_agent_id == fence.agent_id
    ):
        return
    raise StaleAttempt(
        f"Job {fence.job_id} is no longer on the attempt this result was produced by "
        f"(uploaded for attempt {fence.attempt} by agent {fence.agent_id}; the job is "
        f"now on attempt {row.attempts} with agent {row.assigned_agent_id}); "
        "the result was rejected and nothing was published"
    )


def renew_lease(settings: Settings, job_id: str, *, agent_id: str | None = None) -> bool:
    """Push a job's lease deadline forward. Returns whether it applied.

    The proof of life for an in-flight job: agents renew from their heartbeat,
    local jobs from a thread beside the scan (``renewing_lease``). Only jobs
    that are actually in flight are touched, and when ``agent_id`` is given it
    must be the agent holding the job — a stray heartbeat naming someone else's
    job must not keep that job alive.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None or row.status not in job_states.IN_FLIGHT:
            return False
        if agent_id is not None and row.assigned_agent_id != agent_id:
            return False
        extend_lease(row, lease_deadline(settings))
        return True


@contextmanager
def renewing_lease(settings: Settings, job_id: str) -> Iterator[None]:
    """Keep a local job's lease alive for as long as this process runs it.

    A local scan has no heartbeat to ride on — it is a ``subprocess`` in a
    thread — so without this its lease would lapse mid-scan and the reaper
    would fail a job that is running perfectly well. Renewing from beside the
    scan is also what finally closes the P1.2 residual: if this replica dies,
    the renewals stop with it and the job stops looking attended.

    Failures are logged, not raised: a database blip during a two-hour scan
    should cost a renewal, not the scan.
    """
    stop = threading.Event()
    # Renew several times per lease so a single missed tick is not fatal.
    interval = max(settings.job_lease_seconds / 3.0, 1.0)

    def _loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_lease(settings, job_id):
                    return  # Terminal already — nothing left to hold.
            except Exception:  # noqa: BLE001
                _log.warning("Lease renewal failed for job %s", job_id, exc_info=True)

    thread = threading.Thread(target=_loop, name=f"octo-lease-{job_id}", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)


def release_ingest_lease(settings: Settings, fence: IngestLease) -> None:
    """Give back an ingest lease whose upload produced nothing.

    Only our own, and only while it is still ours: a lease the reaper has
    already cleared, or one a later upload has taken, is not this caller's to
    tidy up.

    ``claimed_until`` goes back to the ordinary ``job_lease_seconds`` it would
    have had without this ingest. :func:`open_ingest_lease` pushed it out by
    the much longer ``job_ingest_lease_seconds`` to keep the reaper out of an
    ingest in progress; once the ingest has failed there is no ingest to
    protect, and leaving the long deadline in place would hold the job
    ``claimed`` for the whole of it — the agent does not resend a refused
    upload (``local_job_runner.run_job`` gives up on it), so the only thing that moves the job
    on is the reaper, and this is what lets it. Pulled in by assignment rather
    than through :func:`extend_lease`, which only ever pushes out.

    A job on its way down (``cancelling``) keeps its cleared deadline: it is
    not the reaper's to requeue, and giving it one back would hand a stopping
    scan to a second agent.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, fence.job_id, with_for_update=True)
        if row is None or row.ingest_token != fence.token:
            return
        row.ingest_token = None
        row.ingest_attempt = None
        row.ingest_agent_id = None
        row.ingest_started_at = None
        if row.status in job_states.IN_FLIGHT:
            row.claimed_until = lease_deadline(settings)
