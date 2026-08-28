"""Per-job input directories are removed when the job finishes (#258).

``_prepare_target_inputs`` writes ``state_dir/job_inputs/<job_id>/``. Before
#244 that happened only for a job carrying target overrides; since #244 it
holds ``scan_scope.json`` for *every* scan, so a tree nothing ever cleaned grew
once per run on a persistent volume. The property under test is one sentence:
after a job reaches a terminal state, by any of the three paths that can take
it there, its input directory is gone — and not one moment before, because the
scanner and the agent read those files while the run is in flight.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from tests.conftest import (
    approve_scan_scope,
    make_settings,
    requires_postgres,
)

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
    approve_scan_scope(base)
    agents_service.configure(base)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return base


def _inputs(settings, job_id: str) -> Path:
    return jobs_service.job_inputs_dir(settings, job_id)


def test_inputs_survive_until_the_agent_reports(settings):
    """The guard on the other three: a claimed job is still reading these."""
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", ranges="10.1.0.0/28"), username="admin"
    )
    assert _inputs(settings, job.job_id).is_dir()

    jobs_service.claim_job(settings, "agent-1")

    assert _inputs(settings, job.job_id).is_dir()
    assert (_inputs(settings, job.job_id) / jobs_service.SCAN_SCOPE_INPUT).is_file()


def test_agent_upload_removes_the_inputs(settings):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")

    jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=0)

    assert not _inputs(settings, job.job_id).exists()


def test_a_failed_agent_job_removes_the_inputs_too(settings):
    """A run that failed is as finished as one that succeeded."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")

    jobs_service.complete_job(
        settings, job.job_id, agent_id="agent-1", exit_code=2, error="scanner died"
    )

    assert not _inputs(settings, job.job_id).exists()


def test_a_replayed_upload_does_not_trip_over_the_removal(settings):
    """The first upload swept the directory; the replay must still answer.

    The removal is idempotent for exactly this: a replay arrives after the run
    finished, so there is nothing left to remove and that is not an error.
    """
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.complete_job(
        settings, job.job_id, agent_id="agent-1", exit_code=0, idempotency_key="upload-1"
    )

    replay = jobs_service.complete_job(
        settings, job.job_id, agent_id="agent-1", exit_code=0, idempotency_key="upload-1"
    )

    assert replay.status == "succeeded"
    assert not _inputs(settings, job.job_id).exists()


def test_an_idempotent_replay_of_the_start_removes_the_losing_directory(settings):
    """The second start writes inputs under a job_id that never becomes a row."""
    jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin", idempotency_key="req-1"
    )

    with pytest.raises(jobs_service.IdempotentReplay):
        jobs_service.start_scan(
            settings, StartScanRequest(mode="balanced"), username="admin", idempotency_key="req-1"
        )

    root = settings.state_dir / "job_inputs"
    surviving = {p.name for p in root.iterdir()} if root.is_dir() else set()
    # Only the job that exists may keep a directory: the loser wrote one under
    # its own id and must have taken it back.
    live = {job.job_id for job in jobs_service.list_jobs(settings)[0]}
    assert surviving <= live


def test_a_local_run_removes_the_inputs(tmp_path: Path):
    """The local path, where this process is the worker rather than an agent."""
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="local",
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)

    job_id = "job-local-1"
    inputs = jobs_service.job_inputs_dir(base, job_id)
    inputs.mkdir(parents=True)
    (inputs / jobs_service.SCAN_SCOPE_INPUT).write_text("{}", encoding="utf-8")

    # A command that exits cleanly stands in for the scanner: what is under
    # test is the cleanup in the worker's finally, not the scan.
    jobs_service._run_job(base, job_id, [sys.executable, "-c", ""])

    assert not inputs.exists()
