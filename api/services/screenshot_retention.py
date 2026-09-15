"""Delete aged screenshot PNGs (P4.4).

A screenshot of a login page can hold names and tokens even after the
DOM redaction pass, so the files must not live as long as the rest of a
run directory. This worker walks the artifact store's
``runs/*/screenshots/*.png`` and deletes anything older than
``screenshot_retention_days``. ``screenshots.json`` stays — it names what was
captured, not the pixels.

Through the store since #336, so the images go from object storage too. They
are the artifact this mattered most for: a bucket that keeps every screenshot
forever is a personal-data retention problem that no amount of DOM redaction
answers.

0 days disables the reaper. Deletes are fail-soft per file. Several API
replicas may sweep the same tree; unlink of a missing file is a no-op.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.services import artifact_store
from api.services.artifact_store import workspace
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
    store = artifact_store.get_store(settings)

    for run_id in workspace.run_ids(settings):
        prefix = artifact_store.keys.run_artifact(run_id, "screenshots")
        try:
            entries = [
                entry
                for entry in store.list_prefix(prefix)
                if entry.key.lower().endswith(".png")
            ]
        except artifact_store.ArtifactStoreError:
            errors += 1
            LOG.warning("screenshot retention: could not list %s", prefix, exc_info=True)
            continue
        if not entries:
            # Most runs have no screenshots at all -- the stage is off by
            # default -- so the run's metadata is not read until there is
            # something its age could condemn.
            continue
        # The run's own metadata, so a *run* older than the cutoff loses its
        # screenshots even when the files themselves were written later (a
        # re-upload, a restored backup). min() of the two, as before: whichever
        # says "older" wins.
        run_written = _run_meta_modified(store, run_id)
        for entry in entries:
            try:
                age_base = entry.modified
                if run_written is not None:
                    age_base = min(age_base, run_written)
                if age_base > cutoff:
                    kept += 1
                    continue
                store.delete(entry.key)
                # The working copy on this pod goes too, or the image stays
                # downloadable from whichever replica cached it.
                (workspace.cache_root(settings) / run_id / "screenshots").joinpath(
                    entry.key.rsplit("/", 1)[-1]
                ).unlink(missing_ok=True)
                deleted += 1
            except (artifact_store.ArtifactStoreError, OSError):
                errors += 1
                LOG.warning(
                    "screenshot retention: could not delete %s", entry.key, exc_info=True
                )

    deleted_flat, errors_flat, kept_flat = _sweep_flat_layout(settings, cutoff)
    return {
        "deleted": deleted + deleted_flat,
        "errors": errors + errors_flat,
        "kept": kept + kept_flat,
    }


def _run_meta_modified(store: artifact_store.ArtifactStore, run_id: str) -> float | None:
    """When this run's metadata was written, or ``None`` when it has none."""
    try:
        entry = store.stat(artifact_store.keys.run_artifact(run_id, "run_meta.json"))
    except artifact_store.ArtifactStoreError:
        return None
    return entry.modified if entry is not None else None


def _sweep_flat_layout(settings: Settings, cutoff: float) -> tuple[int, int, int]:
    """The pre-``per_run_output`` layout: screenshots beside the output dir.

    Filesystem-only and kept for the installations that still have such a
    directory — it has no run id, so there is no key it could live under.
    """
    deleted = errors = kept = 0
    shot_dir = Path(settings.output_dir) / "screenshots"
    if not shot_dir.is_dir():
        return (0, 0, 0)
    meta = Path(settings.output_dir) / "run_meta.json"
    for path in shot_dir.glob("*.png"):
        try:
            age_base = path.stat().st_mtime
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
    return (deleted, errors, kept)


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
