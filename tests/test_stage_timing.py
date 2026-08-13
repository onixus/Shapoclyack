"""Unit tests for scanner stage wall-clock timing."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from scanner.pipeline.stage_timing import StageTimer


def test_run_records_duration(tmp_path: Path) -> None:
    timer = StageTimer()

    def work() -> str:
        time.sleep(0.05)
        return "ok"

    assert timer.run("demo", work) == "ok"
    assert len(timer.records) == 1
    rec = timer.records[0]
    assert rec.name == "demo"
    assert rec.status == "ok"
    assert rec.duration_sec >= 0.04


def test_run_records_error_then_reraises() -> None:
    timer = StageTimer()

    def boom() -> None:
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError, match="nope"):
        timer.run("broken", boom)

    assert timer.records[0].status == "error"
    assert timer.records[0].name == "broken"


def test_skip_and_write_json(tmp_path: Path) -> None:
    timer = StageTimer()
    timer.skip("nuclei", "checkpoint")
    timer.run("ports", lambda: None)
    path = timer.write(tmp_path)
    assert path == tmp_path / "stage_timings.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["pipeline_wall_sec"] >= 0
    names = [s["name"] for s in data["stages"]]
    assert names == ["nuclei", "ports"]
    assert data["stages"][0]["status"] == "skipped"
    assert "top_stages" in data
