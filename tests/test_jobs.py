"""Unit tests for api.services.jobs — legacy import, startup reconciliation, claiming.

Since ROADMAP P1.2 the queue is a Postgres table rather than ``_JOBS`` +
``state/api_jobs.json``, so these tests need a migrated database (see
tests/conftest.py) and assert against rows, not against the file. The file
still appears here as *input*: an upgrade must carry its jobs over exactly
once.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.services import agents as agents_service
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services.jobs import get_job, load_jobs
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


def _write_jobs_file(state_dir: Path, jobs: list[dict]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "api_jobs.json").write_text(json.dumps(jobs), encoding="utf-8")


def _base_job(job_id: str, *, execution: str, status: str) -> dict:
    return {
        "job_id": job_id,
        "status": status,
        "run_id": None,
        "mode": "balanced",
        "command": ["python", "-m", "scanner.main"],
        "started_at": "2026-07-24T13:24:26+00:00",
        "finished_at": None,
        "exit_code": None,
        "error": None,
        "requested_by": "admin",
        "execution": execution,
        "tenant_id": "default",
    }


@pytest.fixture()
def settings(tmp_path: Path):
    """Test settings over a clean control plane, with the default tenant seeded."""
    base = make_settings(tmp_path, state_dir=tmp_path / "state", output_dir=tmp_path / "output")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    agents_service.configure(base)
    return base


def test_load_jobs_reconciles_orphaned_local_job(settings):
    """A local-mode job's only executor is an in-process thread (_run_job) --
    it dies with the process. A job still `running`/`queued` at startup was
    orphaned by a crash/restart and will never be updated again; load_jobs must
    mark it failed instead of leaving it stuck forever (the Jobs page showing a
    scan "running" indefinitely)."""
    _write_jobs_file(
        settings.state_dir,
        [
            _base_job("orphan-running", execution="local", status="running"),
            _base_job("orphan-queued", execution="local", status="queued"),
        ],
    )
    load_jobs(settings)

    for job_id in ("orphan-running", "orphan-queued"):
        job = get_job(settings, job_id)
        assert job is not None
        assert job.status == "failed"
        assert job.finished_at is not None
        assert "restart" in (job.error or "").lower()


def test_load_jobs_leaves_agent_jobs_and_terminal_jobs_untouched(settings):
    """Agent-mode jobs execute on a remote worker independent of this
    process's lifetime, so a restart here must not touch their status.
    Already-terminal local jobs (succeeded/failed) are left alone too."""
    _write_jobs_file(
        settings.state_dir,
        [
            _base_job("agent-running", execution="agent", status="running"),
            _base_job("agent-queued", execution="agent", status="queued"),
            _base_job("local-done", execution="local", status="succeeded"),
        ],
    )
    load_jobs(settings)

    assert get_job(settings, "agent-running").status == "running"
    assert get_job(settings, "agent-queued").status == "queued"
    assert get_job(settings, "local-done").status == "succeeded"


def test_legacy_queue_is_imported_exactly_once(settings):
    """The JSON file is an upgrade path, not a second source of truth: it is
    imported and then retired, so a restart cannot resurrect jobs deleted since."""
    _write_jobs_file(
        settings.state_dir, [_base_job("agent-queued", execution="agent", status="queued")]
    )
    load_jobs(settings)
    assert get_job(settings, "agent-queued") is not None
    assert not (settings.state_dir / "api_jobs.json").exists()
    assert (settings.state_dir / "api_jobs.json.imported").is_file()

    # Deleting the row and restarting must not bring it back.
    jobs_service.reset_for_tests(settings)
    load_jobs(settings)
    assert get_job(settings, "agent-queued") is None


def test_restart_does_not_fail_another_replicas_local_jobs(settings):
    """Local jobs run inside one specific replica, and the queue is now shared:
    a starting replica may only reconcile the orphans it owns, or a rolling
    restart would fail every scan the other replicas are still running."""
    from api.schemas import StartScanRequest

    settings.instance_id = "replica-a"
    started = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    # force_status, not a transition: the job's own thread may already have
    # moved it, and this test only needs the row staged as another replica's
    # in-flight local job.
    jobs_service.force_status(settings, started.job_id, "running")

    settings.instance_id = "replica-b"
    load_jobs(settings)
    assert get_job(settings, started.job_id).status == "running"

    settings.instance_id = "replica-a"
    load_jobs(settings)
    assert get_job(settings, started.job_id).status == "failed"


def test_claim_hands_each_agent_a_distinct_job(settings):
    """Two agents claiming from the same tenant queue must not both receive the
    head of the queue -- the guarantee the per-process threading.Lock could not
    make once a second replica existed."""
    from api.schemas import StartScanRequest

    settings.job_execution_mode = "agent"
    first = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    second = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")

    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    agents_service.register_agent(agent_id="agent-2", tenant_id="default")

    claimed_first = jobs_service.claim_job(settings, "agent-1")
    claimed_second = jobs_service.claim_job(settings, "agent-2")

    assert {claimed_first.job_id, claimed_second.job_id} == {first.job_id, second.job_id}
    # Oldest first, and nothing left to hand out.
    assert claimed_first.job_id == first.job_id
    assert jobs_service.claim_job(settings, "agent-1") is None


def test_claim_is_scoped_to_the_agents_tenant(settings):
    """A queued job must never cross tenants, whichever agent asks for it."""
    from api.schemas import StartScanRequest

    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    settings.job_execution_mode = "agent"
    jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", tenant_id="ten_a"), username="admin"
    )
    agents_service.register_agent(agent_id="agent-default", tenant_id="default")

    assert jobs_service.claim_job(settings, "agent-default") is None


def _start_agent_job(settings, *, agent_id: str = "agent-1"):
    from api.schemas import StartScanRequest

    settings.job_execution_mode = "agent"
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    agents_service.register_agent(agent_id=agent_id, tenant_id="default")
    return job


def test_claim_parks_the_job_in_claimed_until_the_agent_reports_starting(settings):
    """P1.3 splits the old single `running` state: between the claim and the
    agent's first heartbeat, nobody has said the scan started, and that gap is
    exactly what the P1.4 reaper has to be able to see."""
    job = _start_agent_job(settings)
    jobs_service.claim_job(settings, "agent-1")
    assert get_job(settings, job.job_id).status == "claimed"

    # A heartbeat from an agent that does not hold the job changes nothing.
    agents_service.register_agent(agent_id="agent-2", tenant_id="default")
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-2")
    assert get_job(settings, job.job_id).status == "claimed"

    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
    assert get_job(settings, job.job_id).status == "running"

    # Heartbeats keep arriving for the whole scan; they must stay no-ops.
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
    assert get_job(settings, job.job_id).status == "running"


def test_a_second_result_upload_is_rejected_instead_of_overwriting(settings):
    """An agent retrying after a network timeout used to be able to rewrite the
    outcome of a job that had already finished."""
    job = _start_agent_job(settings)
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=0)
    assert get_job(settings, job.job_id).status == "succeeded"

    with pytest.raises(job_states.InvalidJobTransition):
        jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=1)
    assert get_job(settings, job.job_id).status == "succeeded"


def test_cancel_stops_a_queued_job_and_rejects_the_agents_late_upload(settings):
    job = _start_agent_job(settings)
    cancelled = jobs_service.cancel_job(settings, job.job_id, username="operator")
    assert cancelled.status == "cancelled"
    assert cancelled.error == "Cancelled by operator"
    assert cancelled.finished_at is not None

    # A cancelled job is off the queue for good.
    assert jobs_service.claim_job(settings, "agent-1") is None
    with pytest.raises(job_states.InvalidJobTransition):
        jobs_service.cancel_job(settings, job.job_id, username="operator")


def test_cancel_refuses_a_running_job(settings):
    """There is no kill channel to an in-flight scan, so the API must not claim
    to have stopped one (see api/services/job_states.py)."""
    job = _start_agent_job(settings)
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")

    with pytest.raises(job_states.InvalidJobTransition):
        jobs_service.cancel_job(settings, job.job_id, username="operator")
    assert get_job(settings, job.job_id).status == "running"


def test_cancel_is_tenant_scoped(settings):
    job = _start_agent_job(settings)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    with pytest.raises(PermissionError):
        jobs_service.cancel_job(settings, job.job_id, username="operator", tenant_id="ten_a")
    assert get_job(settings, job.job_id).status == "queued"


def test_claimed_jobs_count_as_running_in_the_queue_gauges(settings):
    """A claimed job is out with a worker, not waiting — counting it as queued
    would read as a backlog nothing is working on (docs/slo.md)."""
    from api.services import metrics as metrics_service

    job = _start_agent_job(settings)
    assert metrics_service.JOBS_QUEUED._value.get() == 1  # noqa: SLF001

    jobs_service.claim_job(settings, "agent-1")
    assert metrics_service.JOBS_QUEUED._value.get() == 0  # noqa: SLF001
    assert metrics_service.JOBS_RUNNING._value.get() == 1  # noqa: SLF001

    jobs_service.cancel_job(settings, job.job_id, username="operator")


def test_local_run_is_tagged_with_the_jobs_tenant(settings, monkeypatch):
    """A locally executed scan must leave an owning-tenant marker in its run
    directory (ROADMAP P0). Without it the run reads back as `default` and
    would show up in every tenant's run list."""
    import subprocess
    import types

    from api.schemas import StartScanRequest

    run_dir = settings.output_dir / "runs" / "20260805T101500Z"
    run_dir.mkdir(parents=True)
    (settings.state_dir / "latest_run.json").write_text(
        json.dumps({"run_id": "20260805T101500Z"}), encoding="utf-8"
    )
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    # start_scan would launch the thread itself; drive _run_job directly so the
    # assertions do not race it.
    monkeypatch.setattr(jobs_service.threading, "Thread", _NoopThread)
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced", tenant_id="ten_a"), username="admin"
    )
    jobs_service._run_job(settings, job.job_id, ["true"])  # noqa: SLF001

    assert get_job(settings, job.job_id).status == "succeeded"
    assert runs_service.read_run_tenant(run_dir) == "ten_a"


class _NoopThread:
    """Stand-in for threading.Thread so start_scan does not run the job twice."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        pass


def test_failed_asset_upsert_is_recorded_on_the_job(settings, monkeypatch):
    """The Phase 7 asset upsert is best-effort and must not fail the scan -- but
    swallowing it silently left the job reading as a clean success with an empty
    asset list, and the reason only in the pod log. Surface it on the job."""
    import subprocess
    import types

    from api.services import assets as assets_service

    (settings.output_dir / "runs" / "20260806T193750Z").mkdir(parents=True)
    (settings.state_dir / "latest_run.json").write_text(
        json.dumps({"run_id": "20260806T193750Z"}), encoding="utf-8"
    )
    _write_jobs_file(
        settings.state_dir, [_base_job("job-2", execution="local", status="queued")]
    )
    load_jobs(settings)
    # load_jobs just reconciled the imported orphan; put it back on the queue.
    jobs_service.force_status(settings, "job-2", "queued", finished_at=None, error=None)

    def _boom(*_a, **_k):
        raise RuntimeError("assets table is gone")

    monkeypatch.setattr(assets_service, "upsert_assets_from_run", _boom)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    jobs_service._run_job(settings, "job-2", ["true"])  # noqa: SLF001

    job = get_job(settings, "job-2")
    # The scan itself still succeeded -- the upsert must not change that.
    assert job.status == "succeeded"
    assert job.exit_code == 0
    assert job.asset_upsert_error == "RuntimeError: assets table is gone"


def test_successful_asset_upsert_leaves_no_error_on_the_job(settings, monkeypatch):
    import subprocess
    import types

    from api.services import assets as assets_service

    (settings.output_dir / "runs" / "20260806T193750Z").mkdir(parents=True)
    (settings.state_dir / "latest_run.json").write_text(
        json.dumps({"run_id": "20260806T193750Z"}), encoding="utf-8"
    )
    _write_jobs_file(
        settings.state_dir, [_base_job("job-3", execution="local", status="queued")]
    )
    load_jobs(settings)
    jobs_service.force_status(settings, "job-3", "queued", finished_at=None, error=None)

    monkeypatch.setattr(assets_service, "upsert_assets_from_run", lambda *a, **k: None)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    jobs_service._run_job(settings, "job-3", ["true"])  # noqa: SLF001

    assert get_job(settings, "job-3").asset_upsert_error is None
