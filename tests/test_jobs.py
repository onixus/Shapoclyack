"""Unit tests for api.services.jobs persistence/startup reconciliation."""

from __future__ import annotations

import json
from pathlib import Path

from api.services.jobs import get_job, load_jobs
from api.settings import Settings


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


def test_load_jobs_reconciles_orphaned_local_job(tmp_path: Path):
    """A local-mode job's only executor is an in-process thread (_run_job) --
    it dies with the process. A job still `running`/`queued` on disk at
    startup was orphaned by a crash/restart and will never be updated again;
    load_jobs must mark it failed instead of leaving it stuck forever (the
    Jobs page showing a scan "running" indefinitely)."""
    state_dir = tmp_path / "state"
    _write_jobs_file(
        state_dir,
        [
            _base_job("orphan-running", execution="local", status="running"),
            _base_job("orphan-queued", execution="local", status="queued"),
        ],
    )
    settings = Settings(state_dir=state_dir)
    load_jobs(settings)

    for job_id in ("orphan-running", "orphan-queued"):
        job = get_job(job_id)
        assert job is not None
        assert job.status == "failed"
        assert job.finished_at is not None
        assert "restart" in (job.error or "").lower()

    persisted = {item["job_id"]: item for item in json.loads((state_dir / "api_jobs.json").read_text())}
    assert persisted["orphan-running"]["status"] == "failed"
    assert persisted["orphan-queued"]["status"] == "failed"


def test_load_jobs_leaves_agent_jobs_and_terminal_jobs_untouched(tmp_path: Path):
    """Agent-mode jobs execute on a remote worker independent of this
    process's lifetime, so a restart here must not touch their status.
    Already-terminal local jobs (succeeded/failed) are left alone too."""
    state_dir = tmp_path / "state"
    _write_jobs_file(
        state_dir,
        [
            _base_job("agent-running", execution="agent", status="running"),
            _base_job("agent-queued", execution="agent", status="queued"),
            _base_job("local-done", execution="local", status="succeeded"),
        ],
    )
    settings = Settings(state_dir=state_dir)
    load_jobs(settings)

    assert get_job("agent-running").status == "running"
    assert get_job("agent-queued").status == "queued"
    assert get_job("local-done").status == "succeeded"
