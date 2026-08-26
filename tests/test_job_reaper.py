"""Lease expiry and the reaper (ROADMAP P1.4).

The rule under test: an in-flight job whose executor stopped renewing its lease
is provably unattended, and what happens next depends on whether anyone else
could ever pick it up.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import job_reaper
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.services.jobs import get_job
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="agent",
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    # Scans need an approved scan scope since #226; see tests/conftest.py.
    approve_scan_scope(base)
    agents_service.configure(base)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return base


def _expire_lease(settings, job_id: str) -> None:
    """Move the lease into the past instead of waiting one out."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        row.claimed_until = jobs_service._now() - timedelta(seconds=1)  # noqa: SLF001


def _start_and_claim(settings):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    return job


def test_claim_takes_a_lease_and_the_heartbeat_extends_it(settings):
    job = _start_and_claim(settings)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job.job_id)
        assert row.attempts == 1
        first_deadline = row.claimed_until
        assert first_deadline is not None

    _expire_lease(settings, job.job_id)
    # The heartbeat is the agent's proof of life; it must push the deadline back
    # into the future, or a live scan would be reaped mid-run.
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Job, job.job_id).claimed_until > jobs_service._now()  # noqa: SLF001

    assert jobs_service.reap_expired_leases(settings) == {"requeued": 0, "failed": 0}
    assert get_job(settings, job.job_id).status == "running"


def test_a_stray_heartbeat_cannot_hold_someone_elses_lease(settings):
    job = _start_and_claim(settings)
    agents_service.register_agent(agent_id="agent-2", tenant_id="default")
    _expire_lease(settings, job.job_id)

    assert jobs_service.renew_lease(settings, job.job_id, agent_id="agent-2") is False
    assert jobs_service.reap_expired_leases(settings)["requeued"] == 1


def test_an_abandoned_agent_job_goes_back_on_the_queue(settings):
    """The agent died between claiming and finishing. Another worker gets it."""
    job = _start_and_claim(settings)
    _expire_lease(settings, job.job_id)

    assert jobs_service.reap_expired_leases(settings) == {"requeued": 1, "failed": 0}
    requeued = get_job(settings, job.job_id)
    assert requeued.status == "queued"
    assert requeued.assigned_agent_id is None
    # The attempt never produced a run, so it must not read as a started job.
    assert requeued.started_at is None
    assert requeued.attempts == 1

    assert jobs_service.claim_job(settings, "agent-1").job_id == job.job_id
    assert get_job(settings, job.job_id).attempts == 2


def test_requeueing_stops_at_the_attempt_cap(settings):
    """A target that kills whatever picks it up must not cycle the fleet."""
    settings.job_max_attempts = 2
    job = _start_and_claim(settings)

    _expire_lease(settings, job.job_id)
    assert jobs_service.reap_expired_leases(settings)["requeued"] == 1
    jobs_service.claim_job(settings, "agent-1")  # attempt 2 of 2
    _expire_lease(settings, job.job_id)
    assert jobs_service.reap_expired_leases(settings) == {"requeued": 0, "failed": 1}

    dead = get_job(settings, job.job_id)
    assert dead.status == "failed"
    assert "Lease expired after 2 attempt" in dead.error
    assert dead.finished_at is not None


def test_an_abandoned_local_job_is_failed_not_requeued(settings):
    """This is the P1.2 residual: a local job's only executor was the thread in
    the replica that died, so no other replica will ever pick the row up.
    Requeueing it would park it in the queue for good."""
    settings.job_execution_mode = "local"
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    # Stand in for "the replica running this died": in flight, lease lapsed.
    jobs_service.force_status(
        settings,
        job.job_id,
        "running",
        claimed_until=jobs_service._now() - timedelta(seconds=1),  # noqa: SLF001
        attempts=1,
    )

    assert jobs_service.reap_expired_leases(settings) == {"requeued": 0, "failed": 1}
    dead = get_job(settings, job.job_id)
    assert dead.status == "failed"
    assert "local" in dead.error


def test_jobs_without_a_lease_are_left_alone(settings):
    """Queued jobs hold no lease, and a finished job's lease is cleared — the
    sweep must not touch either, however long they sit there."""
    done = _start_and_claim(settings)
    jobs_service.complete_job(settings, done.job_id, agent_id="agent-1", exit_code=0)
    # Queued after the claim, so it is not the row the claim above took.
    queued = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )

    with get_session(settings.postgres_url) as session:
        assert session.get(models.Job, done.job_id).claimed_until is None

    assert jobs_service.reap_expired_leases(settings) == {"requeued": 0, "failed": 0}
    assert get_job(settings, queued.job_id).status == "queued"
    assert get_job(settings, done.job_id).status == "succeeded"


def test_reaper_worker_ticks_and_reports_what_it_did(settings):
    job = _start_and_claim(settings)
    _expire_lease(settings, job.job_id)

    worker = job_reaper.JobReaper(settings=settings, poll_interval_seconds=3600)
    worker._tick()  # noqa: SLF001

    assert worker.stats == {"ticks": 1, "requeued": 1, "failed": 0, "errors": 0}
    assert get_job(settings, job.job_id).status == "queued"


def test_the_reaper_can_be_disabled(settings):
    settings.job_reaper_enabled = False
    assert job_reaper.start_worker(settings) is None


def test_giving_up_on_a_job_is_visible_to_the_completion_slo(settings):
    """docs/slo.md says lease-exhausted jobs land on the failure side of the
    job-completion ratio; if the reaper wrote the row without observing it, the
    success ratio would look best exactly when executors are dying."""
    from api.services import metrics as metrics_service

    settings.job_max_attempts = 1
    job = _start_and_claim(settings)
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
    _expire_lease(settings, job.job_id)

    def _observations() -> float:
        for metric in metrics_service.REGISTRY.collect():
            if metric.name != "octo_job_duration_seconds":
                continue
            for sample in metric.samples:
                if sample.name.endswith("_count") and sample.labels == {
                    "status": "failed",
                    "execution": "agent",
                }:
                    return sample.value
        return 0.0

    before = _observations()
    assert jobs_service.reap_expired_leases(settings)["failed"] == 1
    assert _observations() == before + 1


def test_the_poll_interval_cannot_be_zero(settings):
    """A mistyped 0 would turn the sweep into a busy loop holding row locks."""
    settings.job_reaper_interval_seconds = 0
    assert job_reaper.JobReaper(settings=settings)._poll_interval >= 1.0  # noqa: SLF001
