"""Run artifact directory reaper (Issue #187). File-only — no Postgres."""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

from api.services.run_retention import (
    start_worker,
    stop_worker,
    sweep,
    worker_stats,
)
from tests.conftest import make_settings


def _age(path: Path, *, days: float) -> None:
    when = time.time() - days * 86400.0
    os.utime(path, (when, when))


def _write_run(root: Path, run_id: str, *, meta: dict | None = None) -> Path:
    run_dir = root / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "summary.json").write_text('{"alive_hosts": 1}', encoding="utf-8")
    (run_dir / "alive_hosts.json").write_text('[{"host": "1.2.3.4"}]', encoding="utf-8")
    meta_content = meta if meta is not None else {"run_id": run_id, "status": "completed"}
    (run_dir / "run_meta.json").write_text(json.dumps(meta_content), encoding="utf-8")
    return run_dir


def test_sweep_deletes_expired_run_directory(tmp_path: Path):
    settings = make_settings(tmp_path, run_retention_days=30)
    old_run = _write_run(settings.output_dir, "run-old")
    _age(old_run / "run_meta.json", days=45)
    _age(old_run, days=45)

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 1
    assert stats["kept"] == 0
    assert not old_run.exists()


def test_sweep_keeps_fresh_run_directory(tmp_path: Path):
    settings = make_settings(tmp_path, run_retention_days=30)
    new_run = _write_run(settings.output_dir, "run-fresh")

    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 0
    assert stats["kept"] == 1
    assert new_run.exists()


def test_sweep_disabled_when_zero_days(tmp_path: Path):
    settings = make_settings(tmp_path, run_retention_days=0)
    old_run = _write_run(settings.output_dir, "run-old")
    _age(old_run / "run_meta.json", days=100)

    stats = sweep(settings, now=datetime.now(UTC))
    # Six keys since #258: the reaper also sweeps job_inputs, and 0 days
    # disables that half too.
    assert stats == {
        "deleted": 0,
        "errors": 0,
        "kept": 0,
        "job_inputs_deleted": 0,
        "job_inputs_errors": 0,
        "job_inputs_kept": 0,
    }
    assert old_run.exists()


def test_sweep_parses_iso_timestamp_in_run_meta(tmp_path: Path):
    settings = make_settings(tmp_path, run_retention_days=30)
    run_dir = _write_run(
        settings.output_dir,
        "run-with-iso",
        meta={"finished_at": "2021-01-01T12:00:00Z"},
    )
    # Directory mtime could be now, but run_meta timestamp is old
    stats = sweep(settings, now=datetime.now(UTC))
    assert stats["deleted"] == 1
    assert not run_dir.exists()


def test_worker_lifecycle(tmp_path: Path):
    settings = make_settings(
        tmp_path,
        run_retention_enabled=True,
        run_retention_days=10,
        run_retention_interval_seconds=60,
    )
    start_worker(settings)
    stats = worker_stats()
    assert stats is not None
    stop_worker()
    assert worker_stats() is None


def _write_job_inputs(settings, job_id: str) -> Path:
    inputs_dir = settings.state_dir / "job_inputs" / job_id
    inputs_dir.mkdir(parents=True)
    (inputs_dir / "scan_scope.json").write_text('{"entries": []}', encoding="utf-8")
    return inputs_dir


def test_sweep_deletes_orphaned_job_inputs(tmp_path: Path):
    """A job that never completed leaves its inputs behind; the reaper takes them (#258).

    The completion paths remove these, so anything the reaper meets is a job
    nobody finished — or a directory from before that cleanup existed.
    """
    settings = make_settings(tmp_path, run_retention_days=30)
    stale = _write_job_inputs(settings, "job-abandoned")
    fresh = _write_job_inputs(settings, "job-running")
    _age(stale, days=45)

    stats = sweep(settings, now=datetime.now(UTC))

    assert not stale.exists()
    assert fresh.exists(), "a job younger than the cutoff may still be running"
    assert stats["job_inputs_deleted"] == 1
    assert stats["job_inputs_kept"] == 1
    # The run-artifact counts stay about run artifacts: /api/system reads them.
    assert stats["deleted"] == 0


def test_sweep_leaves_job_inputs_alone_when_retention_is_disabled(tmp_path: Path):
    settings = make_settings(tmp_path, run_retention_days=0)
    stale = _write_job_inputs(settings, "job-abandoned")
    _age(stale, days=999)

    stats = sweep(settings, now=datetime.now(UTC))

    assert stale.exists()
    assert stats["job_inputs_deleted"] == 0
