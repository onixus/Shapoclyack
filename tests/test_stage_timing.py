"""Unit tests for scanner stage wall-clock timing."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from scanner.pipeline.stage_timing import StageTimer, process_resources


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


def test_timings_carry_the_run_cpu_and_memory_of_the_tools_it_ran(tmp_path: Path) -> None:
    """A sensor's per-run cost for sizing (#337): the scan's own process plus
    the nmap/nuclei/... children it waited for."""
    before = process_resources()
    assert before is not None
    subprocess.run([sys.executable, "-c", "sum(i * i for i in range(3_000_000))"], check=True)
    data = json.loads(StageTimer().write(tmp_path).read_text(encoding="utf-8"))
    resources = data["resources"]
    assert resources["children_cpu_sec"] > before["children_cpu_sec"]
    assert resources["cpu_sec"] >= before["cpu_sec"]
    assert resources["max_rss_mb"] > 0
    assert resources["children_max_rss_mb"] > 0


def test_resources_read_children_and_convert_maxrss(monkeypatch) -> None:
    """Which getrusage is which, and ru_maxrss's unit per platform (review of #337)."""
    import resource

    def fake(who):
        own = who == resource.RUSAGE_SELF
        return type(
            "Usage",
            (),
            {
                "ru_utime": 1.0 if own else 10.0,
                "ru_stime": 0.5 if own else 5.0,
                "ru_maxrss": 2 * 2**20 if own else 4 * 2**20,
            },
        )()

    monkeypatch.setattr(resource, "getrusage", fake)
    monkeypatch.setattr(sys, "platform", "linux")
    assert process_resources() == {
        "cpu_sec": 1.5,
        "children_cpu_sec": 15.0,
        "max_rss_mb": 2048.0,
        "children_max_rss_mb": 4096.0,
    }
    # macOS reports ru_maxrss in bytes, not KiB.
    monkeypatch.setattr(sys, "platform", "darwin")
    assert process_resources()["max_rss_mb"] == 2.0


def test_resources_are_null_without_getrusage(monkeypatch) -> None:
    """Windows has no resource module; the timings file must still be written."""
    monkeypatch.setitem(sys.modules, "resource", None)
    assert StageTimer().as_dict()["resources"] is None
