"""The job lifecycle table itself (ROADMAP P1.3) — no database needed.

These assert the *rules*; tests/test_jobs.py asserts that the services obey
them.
"""

from __future__ import annotations

import pytest

from api.services import job_states


def test_the_happy_paths_are_legal():
    # Agent: an agent takes the job, reports starting, then finishes.
    assert job_states.can_transition(job_states.QUEUED, job_states.CLAIMED)
    assert job_states.can_transition(job_states.CLAIMED, job_states.RUNNING)
    assert job_states.can_transition(job_states.RUNNING, job_states.SUCCEEDED)
    # Local: no claim step, the API process is the worker.
    assert job_states.can_transition(job_states.QUEUED, job_states.RUNNING)
    # A fast agent can upload results before its first heartbeat lands.
    assert job_states.can_transition(job_states.CLAIMED, job_states.SUCCEEDED)


@pytest.mark.parametrize("terminal", sorted(job_states.TERMINAL))
def test_terminal_states_never_move_again(terminal):
    """The rule that makes a duplicate result upload safe: a job that already
    finished cannot be rewritten by a retry arriving after a network timeout."""
    for target in job_states.ALL:
        assert not job_states.can_transition(terminal, target)


def test_a_started_job_stops_through_cancelling_and_never_straight_to_cancelled():
    """Only a queued job is stopped by a single write: nothing has taken it.

    A job an executor holds goes through `cancelling` (#360) — the API has
    asked and has not been told the scan stopped — and writing `cancelled`
    directly from `claimed`/`running` would report a stop that had not been
    confirmed by anybody."""
    assert job_states.can_transition(job_states.QUEUED, job_states.CANCELLED)
    assert not job_states.can_transition(job_states.CLAIMED, job_states.CANCELLED)
    assert not job_states.can_transition(job_states.RUNNING, job_states.CANCELLED)
    assert job_states.can_transition(job_states.CLAIMED, job_states.CANCELLING)
    assert job_states.can_transition(job_states.RUNNING, job_states.CANCELLING)
    assert job_states.can_transition(job_states.CANCELLING, job_states.CANCELLED)


def test_a_cancelling_job_may_still_report_the_result_it_produced():
    """The scan can finish on its own between the request and the signal, and a
    real result must not be discarded to make the console's wording come true."""
    assert job_states.can_transition(job_states.CANCELLING, job_states.SUCCEEDED)
    assert job_states.can_transition(job_states.CANCELLING, job_states.FAILED)
    # ...but it must not go back on the queue: the reaper requeues on the lease,
    # and a second agent must never be handed a job that is being stopped.
    assert not job_states.can_transition(job_states.CANCELLING, job_states.QUEUED)
    assert job_states.CANCELLING not in job_states.IN_FLIGHT


def test_check_transition_names_the_job_and_the_move():
    with pytest.raises(job_states.InvalidJobTransition) as exc:
        job_states.check_transition("job-1", job_states.SUCCEEDED, job_states.RUNNING)
    assert "job-1" in str(exc.value)
    assert "already succeeded" in str(exc.value)

    with pytest.raises(job_states.InvalidJobTransition):
        job_states.check_transition("job-1", job_states.QUEUED, "sideways")


def test_the_gauge_sets_partition_every_state():
    """docs/slo.md reads queue depth off these; a state in neither set would be
    silently invisible to monitoring."""
    assert job_states.ACTIVE | job_states.TERMINAL == job_states.ALL
    assert not (job_states.ACTIVE & job_states.TERMINAL)
    assert job_states.IN_FLIGHT < job_states.ACTIVE
