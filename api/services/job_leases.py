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
    """An upload from a lease that expired and was reissued."""


@dataclass(frozen=True)
class IngestLease:
    """The attempt allowed to write a job outcome after long-running ingest."""

    job_id: str
    token: str
    attempt: int
    agent_id: str


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def lease_deadline(settings: Settings) -> datetime:
    return _now() + timedelta(seconds=max(settings.job_lease_seconds, 1))


def extend_lease(row: models.Job, deadline: datetime) -> None:
    """Push a lease deadline out, never pull it in."""
    if row.claimed_until is None or row.claimed_until < deadline:
        row.claimed_until = deadline


def open_ingest_lease(
    settings: Settings, row: models.Job, *, agent_id: str
) -> IngestLease:
    """Reserve the right to finish a locked job row after ingest I/O."""
    token = uuid.uuid4().hex
    row.ingest_token = token
    row.ingest_attempt = row.attempts or 0
    row.ingest_agent_id = agent_id
    row.ingest_started_at = _now()
    if row.status in job_states.IN_FLIGHT:
        extend_lease(
            row,
            _now() + timedelta(seconds=max(settings.job_ingest_lease_seconds, 1)),
        )
    return IngestLease(
        job_id=row.job_id,
        token=token,
        attempt=row.ingest_attempt,
        agent_id=agent_id,
    )


def check_ingest_fence(row: models.Job, fence: IngestLease) -> None:
    """Raise unless the row still belongs to the reserved attempt."""
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


def renew_lease(
    settings: Settings, job_id: str, *, agent_id: str | None = None
) -> bool:
    """Push an in-flight job lease forward if the caller still owns it."""
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
    """Keep a local executor's lease alive for the duration of its scan."""
    stop = threading.Event()
    interval = max(settings.job_lease_seconds / 3.0, 1.0)

    def _loop() -> None:
        while not stop.wait(interval):
            try:
                if not renew_lease(settings, job_id):
                    return
            except Exception:  # noqa: BLE001
                _log.warning("Lease renewal failed for job %s", job_id, exc_info=True)

    thread = threading.Thread(
        target=_loop, name=f"octo-lease-{job_id}", daemon=True
    )
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=1.0)


def release_ingest_lease(settings: Settings, fence: IngestLease) -> None:
    """Release a failed ingest reservation without disturbing a newer owner."""
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
