from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from scanner.pipeline.batch_runner import run_batches_parallel
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.errors import StageFailureError


def test_run_batches_parallel_serial(tmp_path: Path) -> None:
    checkpoint = CheckpointStore(tmp_path / "checkpoint.json")
    aggregate: set[str] = set()
    aggregate_file = tmp_path / "results.txt"
    seen: list[str] = []

    def process_batch(bid: str, members: list[str]) -> list[str]:
        seen.append(bid)
        return members

    batches = [("b1", ["1.1.1.1"]), ("b2", ["2.2.2.2"])]

    run_batches_parallel(
        stage="discover",
        batches=batches,
        done_ids=set(),
        concurrency=1,
        process_batch=process_batch,
        aggregate=aggregate,
        aggregate_file=aggregate_file,
        checkpoint=checkpoint,
        checkpoint_key="discover",
    )

    assert seen == ["b1", "b2"]
    assert aggregate == {"1.1.1.1", "2.2.2.2"}
    assert aggregate_file.read_text(encoding="utf-8").splitlines() == ["1.1.1.1", "2.2.2.2"]
    assert checkpoint.done_items("discover") == {"b1", "b2"}


def test_run_batches_parallel_skips_done_batches(tmp_path: Path) -> None:
    checkpoint = CheckpointStore(tmp_path / "checkpoint.json")
    aggregate: set[str] = {"1.1.1.1"}
    calls: list[str] = []

    run_batches_parallel(
        stage="discover",
        batches=[("b1", ["1.1.1.1"]), ("b2", ["2.2.2.2"])],
        done_ids={"b1"},
        concurrency=2,
        process_batch=lambda bid, members: (calls.append(bid) or members),
        aggregate=aggregate,
        aggregate_file=tmp_path / "results.txt",
        checkpoint=checkpoint,
        checkpoint_key="discover",
    )

    assert calls == ["b2"]
    assert aggregate == {"1.1.1.1", "2.2.2.2"}


def test_run_batches_parallel_runs_concurrently(tmp_path: Path) -> None:
    checkpoint = CheckpointStore(tmp_path / "checkpoint.json")
    aggregate: set[str] = set()
    active = 0
    peak = 0
    lock = threading.Lock()

    def process_batch(bid: str, members: list[str]) -> list[str]:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        time.sleep(0.05)
        with lock:
            active -= 1
        return members

    batches = [(f"b{i}", [f"10.0.0.{i}"]) for i in range(1, 5)]

    run_batches_parallel(
        stage="discover",
        batches=batches,
        done_ids=set(),
        concurrency=4,
        process_batch=process_batch,
        aggregate=aggregate,
        aggregate_file=tmp_path / "results.txt",
        checkpoint=checkpoint,
        checkpoint_key="discover",
    )

    assert peak >= 2
    assert len(aggregate) == 4


def test_run_batches_parallel_propagates_failure(tmp_path: Path) -> None:
    checkpoint = CheckpointStore(tmp_path / "checkpoint.json")

    def process_batch(bid: str, members: list[str]) -> list[str]:
        raise RuntimeError("naabu failed")

    with pytest.raises(StageFailureError, match="discover"):
        run_batches_parallel(
            stage="discover",
            batches=[("b1", ["1.1.1.1"])],
            done_ids=set(),
            concurrency=2,
            process_batch=process_batch,
            aggregate=set(),
            aggregate_file=tmp_path / "results.txt",
            checkpoint=checkpoint,
            checkpoint_key="discover",
        )
