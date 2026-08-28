"""Delete aged scan run artifact directories (ROADMAP #187).

Scan outputs written to ``output_dir/runs/<run_id>/`` accumulate over time and
can consume significant disk space on persistent volumes. This worker walks
``output_dir/runs/*`` and deletes any run directory older than
``run_retention_days``.

0 days disables the reaper. Deletes are fail-soft per run directory. Multiple
API replicas may sweep the same tree; removing an already-deleted directory is
handled cleanly.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.settings import Settings

LOG = logging.getLogger("shapoclyack.run-retention")

_worker: RunRetentionWorker | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _parse_timestamp(meta_path: Path) -> float | None:
    if not meta_path.is_file():
        return None
    try:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            for field in ("finished_at", "started_at", "created_at"):
                val = data.get(field)
                if isinstance(val, str) and val.strip():
                    try:
                        cleaned = val.strip().replace("Z", "+00:00")
                        dt = datetime.fromisoformat(cleaned)
                        return dt.timestamp()
                    except (ValueError, TypeError):
                        pass
    except Exception:  # noqa: BLE001
        pass
    return None


def sweep(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Delete expired run directories. Returns counts (deleted, errors, kept)."""
    now = now or _now()
    days = settings.run_retention_days
    if days <= 0:
        return {"deleted": 0, "errors": 0, "kept": 0}

    cutoff = now.timestamp() - days * 86400.0
    deleted = errors = kept = 0
    runs_root = settings.output_dir / "runs"

    if not runs_root.is_dir():
        return {"deleted": 0, "errors": 0, "kept": 0}

    for run_dir in runs_root.iterdir():
        if not run_dir.is_dir():
            continue

        try:
            meta = run_dir / "run_meta.json"
            meta_ts = _parse_timestamp(meta)

            if meta_ts is not None:
                age_base = meta_ts
            elif meta.is_file():
                age_base = meta.stat().st_mtime
            else:
                age_base = run_dir.stat().st_mtime

            if age_base > cutoff:
                kept += 1
                continue

            shutil.rmtree(run_dir, ignore_errors=False)
            deleted += 1
            LOG.info("Run retention: deleted expired run directory %s", run_dir.name)
        except OSError:
            errors += 1
            LOG.warning("Run retention: could not remove run directory %s", run_dir, exc_info=True)
        except Exception:  # noqa: BLE001
            errors += 1
            LOG.exception("Run retention: unexpected error removing %s", run_dir)

    return {"deleted": deleted, "errors": errors, "kept": kept}


class RunRetentionWorker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = {"last_run_at": None, "last": {}}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="octo-run-retention", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Run retention worker started (interval=%ds, days=%d)",
            self._settings.run_retention_interval_seconds,
            self._settings.run_retention_days,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        LOG.info("Run retention worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._stats["last"] = sweep(self._settings)
                self._stats["last_run_at"] = _now().isoformat()
            except Exception:  # noqa: BLE001
                LOG.exception("Run retention tick failed")
            self._stop.wait(self._settings.run_retention_interval_seconds)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)


def start_worker(settings: Settings) -> None:
    global _worker
    if not settings.run_retention_enabled:
        return
    if _worker is None:
        _worker = RunRetentionWorker(settings)
        _worker.start()


def stop_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


def worker_stats() -> dict[str, Any] | None:
    return None if _worker is None else _worker.stats()
