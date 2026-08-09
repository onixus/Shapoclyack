"""The scan job lifecycle, as data (ROADMAP P1.3).

Until this module, a job's status was whatever the last writer assigned. Every
call site wrote a bare string, and nothing stopped a late result upload from
moving a job that had already failed back to ``succeeded``, or a restart from
overwriting a status set by another replica half a second earlier. With the
queue in Postgres (P1.1/P1.2) those writers are genuinely concurrent, so the
legal moves need to be stated once and enforced on every write.

Two states are new here:

``claimed``
    An agent has taken the job but has not reported working on it yet. It used
    to be indistinguishable from ``running``, which hid the one window where a
    job is owned by a worker that may never come back — exactly the window the
    P1.4 lease reaper has to sweep.

``cancelled``
    A terminal state the API never had. An operator could only wait for a
    queued scan to be picked up.

``claimed | running → queued`` is the P1.4 reaper putting a job back after its
executor stopped renewing the lease. It is the one backwards move in the table,
and it is bounded: each hand-out increments ``attempts``, and past the cap the
reaper fails the job instead of requeueing it.

Transitions deliberately *not* here:

- ``running → cancelled``. There is no channel to stop an in-flight scan: a
  local job is a ``subprocess`` owned by one replica's thread, and an agent job
  runs in another process entirely. Marking such a row cancelled would report a
  stop that never happened. Cancellation is offered before execution starts;
  what the reaper does to an abandoned running job is fail it, which is a
  statement about the executor, not a claim to have stopped the scan.
- Same-state moves (``succeeded → succeeded``). A second terminal write is a
  duplicate delivery, and rejecting it is what makes the retry safe until the
  idempotency keys in P1.5 land.
"""

from __future__ import annotations

QUEUED = "queued"
CLAIMED = "claimed"
RUNNING = "running"
SUCCEEDED = "succeeded"
FAILED = "failed"
CANCELLED = "cancelled"

#: Terminal states — nothing may follow them.
TERMINAL = frozenset({SUCCEEDED, FAILED, CANCELLED})

#: States that occupy the queue. Both gauges in docs/slo.md are counted over
#: these: ``claimed`` is in flight, not finished, so it is reported as running.
ACTIVE = frozenset({QUEUED, CLAIMED, RUNNING})

#: In-flight on a worker, i.e. reported by ``octo_jobs_running``.
IN_FLIGHT = frozenset({CLAIMED, RUNNING})

TRANSITIONS: dict[str, frozenset[str]] = {
    # queued → running is the local path (no claim step: the API process is the
    # worker); queued → failed is startup reconciliation of an orphan.
    QUEUED: frozenset({CLAIMED, RUNNING, FAILED, CANCELLED}),
    # An agent that finishes fast can upload results before its first
    # heartbeat, so claimed → terminal has to be legal without passing through
    # running. Back to queued is the P1.4 reaper returning a job whose executor
    # stopped renewing its lease.
    CLAIMED: frozenset({RUNNING, SUCCEEDED, FAILED, CANCELLED, QUEUED}),
    RUNNING: frozenset({SUCCEEDED, FAILED, QUEUED}),
    SUCCEEDED: frozenset(),
    FAILED: frozenset(),
    CANCELLED: frozenset(),
}

ALL = frozenset(TRANSITIONS)


class InvalidJobTransition(ValueError):
    """An illegal status move was attempted.

    Subclasses ``ValueError`` so the existing route handlers that map
    ``ValueError`` to 422 keep working; ``POST /jobs/{id}/cancel`` catches it
    specifically and answers 409.
    """


def can_transition(current: str, new: str) -> bool:
    return new in TRANSITIONS.get(current, frozenset())


def check_transition(job_id: str, current: str, new: str) -> None:
    """Raise unless ``current → new`` is a legal move for ``job_id``."""
    if new not in ALL:
        raise InvalidJobTransition(f"Job {job_id}: unknown status {new!r}")
    if not can_transition(current, new):
        raise InvalidJobTransition(
            f"Job {job_id} cannot move from {current} to {new}"
            + (f" (already {current})" if current in TERMINAL else "")
        )
