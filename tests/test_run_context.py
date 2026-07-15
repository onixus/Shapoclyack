from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanner.pipeline.config_schema import RuntimeConfig
from scanner.pipeline.run_context import resolve_run_paths, write_run_meta


def test_per_run_output_creates_run_subdirs(tmp_path: Path):
    runtime = RuntimeConfig(
        output_dir=str(tmp_path / "out"),
        state_dir=str(tmp_path / "state"),
        per_run_output=True,
    )
    paths = resolve_run_paths(runtime, run_id="test-run-1", resume=False)
    assert paths.output_dir == tmp_path / "out" / "runs" / "test-run-1"
    assert paths.state_dir == tmp_path / "state" / "runs" / "test-run-1"
    assert paths.logs_dir == paths.output_dir / "logs"


def test_resume_reads_latest_run_pointer(tmp_path: Path):
    state_base = tmp_path / "state"
    state_base.mkdir()
    (state_base / "latest_run.json").write_text(
        json.dumps({"run_id": "prev-run"}) + "\n",
        encoding="utf-8",
    )
    runtime = RuntimeConfig(
        output_dir=str(tmp_path / "out"),
        state_dir=str(state_base),
        per_run_output=True,
    )
    paths = resolve_run_paths(runtime, run_id=None, resume=True)
    assert paths.run_id == "prev-run"


def test_resume_without_run_id_raises_when_no_pointer(tmp_path: Path):
    runtime = RuntimeConfig(
        output_dir=str(tmp_path / "out"),
        state_dir=str(tmp_path / "state"),
        per_run_output=True,
    )
    with pytest.raises(ValueError, match="resume requires"):
        resolve_run_paths(runtime, run_id=None, resume=True)


def test_write_run_meta(tmp_path: Path):
    from scanner.pipeline.run_context import RunPaths

    paths = RunPaths(
        run_id="abc",
        output_dir=tmp_path / "out",
        state_dir=tmp_path / "state",
        logs_dir=tmp_path / "out" / "logs",
    )
    write_run_meta(paths, "balanced", "scanner/config/default.yaml")
    meta = json.loads((paths.output_dir / "run_meta.json").read_text(encoding="utf-8"))
    assert meta["run_id"] == "abc"
    assert meta["profile"] == "balanced"
