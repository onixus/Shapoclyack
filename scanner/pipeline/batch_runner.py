from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .checkpoint import CheckpointStore
from .errors import StageFailureError
from .utils import write_lines


def run_batches_parallel(
    *,
    stage: str,
    batches: list[tuple[str, list[str]]],
    done_ids: set[str],
    concurrency: int,
    process_batch: Callable[[str, list[str]], list[str]],
    aggregate: set[str],
    aggregate_file: Path,
    checkpoint: CheckpointStore,
    checkpoint_key: str,
) -> None:
    """Run independent batches with optional parallelism.

    Each batch writes to its own tagged subdirectory via ``process_batch``.
    Results are merged into ``aggregate`` and persisted to ``aggregate_file``
    under a lock; checkpoint progress is recorded per batch id.
    """
    pending = [(bid, members) for bid, members in batches if bid not in done_ids]
    if not pending:
        return

    workers = max(1, concurrency)
    lock = threading.Lock()
    total = len(pending)

    def _run_one(bid: str, members: list[str]) -> tuple[str, list[str]]:
        try:
            return bid, process_batch(bid, members)
        except Exception as exc:  # noqa: BLE001
            raise StageFailureError(stage, exc) from exc

    logging.info("%s: %s pending batch(es), concurrency=%s", stage, total, workers)

    def _commit(bid: str, batch_results: list[str], completed: int) -> None:
        logging.info("%s batch completed %s/%s (%s)", stage, completed, total, bid)
        with lock:
            aggregate.update(batch_results)
            write_lines(aggregate_file, sorted(aggregate))
        checkpoint.mark_item_done(checkpoint_key, bid)

    if workers == 1:
        for index, (bid, members) in enumerate(pending, start=1):
            logging.info("%s batch %s/%s (%s)", stage, index, total, bid)
            done_bid, batch_results = _run_one(bid, members)
            _commit(done_bid, batch_results, index)
        return

    completed = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_run_one, bid, members): bid for bid, members in pending
        }
        for future in as_completed(futures):
            bid = futures[future]
            try:
                done_bid, batch_results = future.result()
            except StageFailureError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise StageFailureError(stage, exc) from exc
            completed += 1
            _commit(done_bid, batch_results, completed)
