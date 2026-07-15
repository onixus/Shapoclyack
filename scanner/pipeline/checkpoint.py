from __future__ import annotations

import threading
from pathlib import Path

from .utils import load_json, save_json


class CheckpointStore:
    """Crash-safe progress tracker.

    Tracks coarse stage completion (``stages``) and fine-grained per-item
    progress (``items``: batches, hosts) so ``--resume`` skips finished work.
    Thread-safe: the NSE stage marks per-host progress from worker threads.
    """

    def __init__(self, state_file: Path) -> None:
        self.state_file = state_file
        self._lock = threading.Lock()
        raw = load_json(state_file, fallback={})
        # Backward/forward tolerant load.
        self.stages: dict[str, bool] = dict(raw.get("stages", {}))
        self.items: dict[str, set[str]] = {
            key: set(values) for key, values in raw.get("items", {}).items()
        }

    def _save_locked(self) -> None:
        save_json(
            self.state_file,
            {
                "stages": self.stages,
                "items": {key: sorted(values) for key, values in self.items.items()},
            },
        )

    def is_done(self, stage: str) -> bool:
        return bool(self.stages.get(stage))

    def mark_done(self, stage: str) -> None:
        with self._lock:
            self.stages[stage] = True
            self._save_locked()

    def done_items(self, key: str) -> set[str]:
        with self._lock:
            return set(self.items.get(key, set()))

    def is_item_done(self, key: str, item: str) -> bool:
        with self._lock:
            return item in self.items.get(key, set())

    def mark_item_done(self, key: str, item: str) -> None:
        with self._lock:
            self.items.setdefault(key, set()).add(item)
            self._save_locked()

    def clear(self) -> None:
        with self._lock:
            self.stages = {}
            self.items = {}
            self._save_locked()
