"""Delete aged screenshot PNGs (P4.4).

A screenshot of a login page can hold names and tokens even after the
DOM redaction pass, so the files must not live as long as the rest of a
run directory. This worker walks ``output_dir/runs/*/screenshots/*.png``
and unlinks anything older than ``screenshot_retention_days``.
``screenshots.json`` stays — it names what was captured, not the pixels.

0 days disables the reaper. Deletes are fail-soft per file. Several API
replicas may sweep the same tree; unlink of a missing file is a no-op.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.settings import Settings

LOG = logging.getLogger("shapoclyack.screenshot-retention")

_worker: ScreenshotRetentionWorker | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def sweep(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Delete expired PNG files. Returns counts (deleted, errors, kept)."""
    now = now or _now()
    days = settings.screenshot_retention_days
    if days <= 0:
        return {"deleted": 0, "errors": 0, "kept": 0}
    cutoff = now.timestamp() - days * 86400.0
    deleted = errors = kept = 0
    runs_root = settings.output_dir / "runs"
    roots = [runs_root] if runs_root.is_dir() else []
    # A run written before per_run_output also lands screenshots next to the
    # default output dir.
    default_shots = settings.output_dir / "screenshots"
    if default_shots.is_dir():
        roots.append(settings.output_dir)
    for run_dir in _run_dirs(roots):
        shot_dir = run_dir / "screenshots"
        if not shot_dir.is_dir():
            continue
        for path in shot_dir.glob("*.png"):
            try:
                age_base = path.stat().st_mtime
                meta = run_dir / "run_meta.json"
                if meta.is_file():
                    age_base = min(age_base, meta.stat().st_mtime)
                if age_base > cutoff:
                    kept += 1
                    continue
                path.unlink()
                deleted += 1
            except OSError:
                errors += 1
                LOG.warning("screenshot retention: could not unlink %s", path, exc_info=True)
    return {"deleted": deleted, "errors": errors, "kept": kept}


def _run_dirs(roots: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in roots:
        if root.name == "runs":
            out.extend(p for p in root.iterdir() if p.is_dir())
        else:
            out.append(root)
    return out


class ScreenshotRetentionWorker:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = {"last_run_at": None, "last": {}}

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="octo-screenshot-retention", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Screenshot retention worker started (interval=%ds, days=%d)",
            self._settings.screenshot_retention_interval_seconds,
            self._settings.screenshot_retention_days,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        LOG.info("Screenshot retention worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._stats["last"] = sweep(self._settings)
                self._stats["last_run_at"] = _now().isoformat()
            except Exception:  # noqa: BLE001
                LOG.exception("Screenshot retention tick failed")
            self._stop.wait(self._settings.screenshot_retention_interval_seconds)

    def stats(self) -> dict[str, Any]:
        return dict(self._stats)


def start_worker(settings: Settings) -> None:
    global _worker
    if not settings.screenshot_retention_enabled:
        return
    if _worker is None:
        _worker = ScreenshotRetentionWorker(settings)
        _worker.start()


def stop_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


def worker_stats() -> dict[str, Any] | None:
    return None if _worker is None else _worker.stats()
