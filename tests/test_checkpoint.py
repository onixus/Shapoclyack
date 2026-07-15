from __future__ import annotations

from pathlib import Path

from scanner.pipeline.checkpoint import CheckpointStore


def test_stage_done_persists(tmp_path: Path):
    state = tmp_path / "checkpoint.json"
    cp = CheckpointStore(state)
    assert not cp.is_done("discover")
    cp.mark_done("discover")
    assert cp.is_done("discover")
    # reload from disk
    assert CheckpointStore(state).is_done("discover")


def test_item_tracking_persists(tmp_path: Path):
    state = tmp_path / "checkpoint.json"
    cp = CheckpointStore(state)
    assert cp.done_items("nse") == set()
    cp.mark_item_done("nse", "10.0.0.1")
    cp.mark_item_done("nse", "10.0.0.2")
    assert cp.is_item_done("nse", "10.0.0.1")

    reloaded = CheckpointStore(state)
    assert reloaded.done_items("nse") == {"10.0.0.1", "10.0.0.2"}


def test_clear_resets_stages_and_items(tmp_path: Path):
    state = tmp_path / "checkpoint.json"
    cp = CheckpointStore(state)
    cp.mark_done("ports")
    cp.mark_item_done("discover", "batch-1")
    cp.clear()
    assert not cp.is_done("ports")
    assert cp.done_items("discover") == set()
    assert CheckpointStore(state).done_items("discover") == set()
