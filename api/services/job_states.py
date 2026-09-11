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

``cancelling``
    An operator has asked for a *running* scan to stop and the API is waiting
    for the agent to confirm it did (#360). Not terminal and not in flight: the
    job is out with an executor that has been told to put it down, so it must
    not be requeued by the reaper and must not count as work anybody is still
    doing. The stop itself travels on the heartbeat response, which is the only
    channel that reaches a working agent, and ``jobs.reap_stale_cancellations``
    bounds the wait — an agent too old to understand the request, or one that
    died with the signal in flight, leaves the job ``cancelled`` after
    ``job_cancel_grace_seconds`` rather than parked here forever.

``claimed | running → queued`` is the P1.4 reaper putting a job back after its
executor stopped renewing the lease. It is the one backwards move in the table,
and it is bounded: each hand-out increments ``attempts``, and past the cap the
reaper fails the job instead of requeueing it.

``claimed | running → cancelling`` is #360 closing the gap this table used to
document as unclosable: an agent now asks the API on every heartbeat whether
the job it holds has been cancelled, so there *is* a channel, and the state in
between says plainly that the API has asked and has not yet been told the scan
stopped. ``cancelling → succeeded | failed`` is legal for the same reason the
claim path is: the scan may have finished on its own microseconds before the
request reached the agent, and a real result must not be thrown away to make
the console's wording come true.

Transitions deliberately *not* here:

- ``running → cancelled`` **for a local job**. A local scan is a ``subprocess``
  owned by one replica's thread; the row can be read by every replica but the
  process can only be signalled by the one that spawned it, so an API that
  answered "cancelled" would be reporting a stop that never happened while the
  scan went on hitting the targets. ``jobs.cancel_job`` refuses it by
  execution rather than by state, and says so.
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
#: Stop requested, not yet confirmed by the executor (#360).
CANCELLING = "cancelling"

#: Terminal states — nothing may follow them.
TERMINAL = frozenset({SUCCEEDED, FAILED, CANCELLED})

#: States that occupy the queue. Both gauges in docs/slo.md are counted over
#: these: ``claimed`` is in flight, not finished, so it is reported as running.
ACTIVE = frozenset({QUEUED, CLAIMED, RUNNING, CANCELLING})

#: In-flight on a worker, i.e. reported by ``octo_jobs_running``. Deliberately
#: without ``cancelling``: the lease machinery is keyed on this set, and a job
#: whose stop has been requested must neither have its lease renewed nor be
#: handed to a second agent by the reaper. Its deadline is the cancellation
#: grace period instead (``jobs.reap_stale_cancellations``).
IN_FLIGHT = frozenset({CLAIMED, RUNNING})

TRANSITIONS: dict[str, frozenset[str]] = {
    # queued → running is the local path (no claim step: the API process is the
    # worker); queued → failed is startup reconciliation of an orphan.
    QUEUED: frozenset({CLAIMED, RUNNING, FAILED, CANCELLED}),
    # An agent that finishes fast can upload results before its first
    # heartbeat, so claimed → terminal has to be legal without passing through
    # running. Back to queued is the P1.4 reaper returning a job whose executor
    # stopped renewing its lease.
    CLAIMED: frozenset({RUNNING, SUCCEEDED, FAILED, QUEUED, CANCELLING}),
    RUNNING: frozenset({SUCCEEDED, FAILED, QUEUED, CANCELLING}),
    # The agent confirms with a ``cancelled`` result upload; the two other
    # moves are the scan having finished before the stop reached it, and the
    # grace period running out is CANCELLED written by the reaper.
    CANCELLING: frozenset({CANCELLED, SUCCEEDED, FAILED}),
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
