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


def test_a_running_job_cannot_be_cancelled():
    """There is no channel to stop an in-flight scan (see job_states' module
    docstring), so cancelling one would report a stop that never happened."""
    assert not job_states.can_transition(job_states.RUNNING, job_states.CANCELLED)
    assert job_states.can_transition(job_states.QUEUED, job_states.CANCELLED)
    assert job_states.can_transition(job_states.CLAIMED, job_states.CANCELLED)


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
