"""Delete aged scan run artifact directories and job inputs (ROADMAP #187, #258).

Scan outputs accumulate over time and consume whatever they are stored on.
This worker walks the artifact store's ``runs/`` prefix and deletes any run
older than ``run_retention_days`` -- through the store (#336), so the same
sweep bounds a persistent volume and an object-storage bucket. Nothing else
prunes the bucket: a lifecycle rule would be a second retention policy, in a
second place, with no idea which runs an operator is still looking at.

It also sweeps ``job_inputs/<job_id>/`` on the same cutoff (#258).
Those are removed by the job completion paths; what reaches the reaper is what
never completed, plus whatever an installation accumulated before that cleanup
existed.

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
from typing import Any

from api.services import artifact_store
from api.services.artifact_store import workspace
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.run-retention")

_worker: RunRetentionWorker | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp_from_meta(data: Any) -> float | None:
    """Epoch seconds from a parsed ``run_meta.json``, or ``None``."""
    if not isinstance(data, dict):
        return None
    for field in ("finished_at", "started_at", "created_at"):
        val = data.get(field)
        if isinstance(val, str) and val.strip():
            try:
                return datetime.fromisoformat(val.strip().replace("Z", "+00:00")).timestamp()
            except (ValueError, TypeError):
                continue
    return None


def _sweep_job_inputs(settings: Settings, cutoff: float) -> dict[str, int]:
    """Delete aged ``job_inputs/<job_id>/`` subtrees (#258).

    The completion paths in ``api.services.jobs`` remove these when a job
    finishes, so what is left here is what never finished cleanly: a job
    abandoned by an agent that never uploaded, an API killed mid-scan, or
    anything an installation accumulated before that cleanup existed. Swept on
    age alone, by the same clock as the run artifacts above rather than by a
    second mechanism -- a scan still running after ``run_retention_days`` is
    not a scan anyone is waiting for, and the reaper never runs at all when
    retention is disabled.
    """
    deleted = errors = kept = 0
    store = artifact_store.get_store(settings)
    try:
        job_ids = list(store.list_children(artifact_store.keys.JOB_INPUTS))
    except artifact_store.ArtifactStoreError:
        LOG.warning("Run retention: could not list job inputs", exc_info=True)
        return {"deleted": 0, "errors": 1, "kept": 0}

    for job_id in job_ids:
        prefix = artifact_store.keys.job_inputs_prefix(job_id)
        try:
            newest = _prefix_modified(store, prefix)
            if newest is None:
                # Listed a moment ago and empty now: another replica swept it
                # between the two calls, which is the outcome either way.
                deleted += 1
                continue
            if newest > cutoff:
                kept += 1
                continue
            store.delete_prefix(prefix)
            # The pod that wrote them keeps a copy for the local runner; it
            # goes with the stored one so the two cannot disagree about what
            # an unfinished job still has.
            shutil.rmtree(settings.state_dir / "job_inputs" / job_id, ignore_errors=True)
            deleted += 1
            LOG.info("Run retention: deleted orphaned job input directory %s", job_id)
        except (artifact_store.ArtifactStoreError, OSError):
            errors += 1
            LOG.warning(
                "Run retention: could not remove job input directory %s", job_id, exc_info=True
            )
    return {"deleted": deleted, "errors": errors, "kept": kept}


def _prefix_modified(store: artifact_store.ArtifactStore, prefix: str) -> float | None:
    """Newest modification time under ``prefix``, or ``None`` when it is empty.

    Newest rather than oldest: a subtree is as young as its most recent write,
    and ageing one out on its *first* file would delete a job whose inputs were
    added to an hour ago.
    """
    newest: float | None = None
    for entry in store.list_prefix(prefix):
        if newest is None or entry.modified > newest:
            newest = entry.modified
    return newest


def _stats(
    runs: tuple[int, int, int] = (0, 0, 0),
    inputs: dict[str, int] | None = None,
) -> dict[str, int]:
    """Build :func:`sweep`'s result. One place, so the early returns and the
    normal path cannot report different shapes (a caller reading a key that
    only some paths carry would fail on a fresh install, where the runs
    directory does not exist yet)."""
    deleted, errors, kept = runs
    inputs = inputs or {"deleted": 0, "errors": 0, "kept": 0}
    return {
        "deleted": deleted,
        "errors": errors,
        "kept": kept,
        "job_inputs_deleted": inputs["deleted"],
        "job_inputs_errors": inputs["errors"],
        "job_inputs_kept": inputs["kept"],
    }


def sweep(settings: Settings, *, now: datetime | None = None) -> dict[str, int]:
    """Delete expired run directories and orphaned job inputs.

    Returns counts (deleted, errors, kept) for the run artifacts, plus the same
    three under ``job_inputs_*`` (#258). The run-artifact keys keep their names
    and meaning so existing callers and the ``/api/system`` payload are
    unaffected.
    """
    now = now or _now()
    days = settings.run_retention_days
    if days <= 0:
        return _stats()

    cutoff = now.timestamp() - days * 86400.0
    deleted = errors = kept = 0
    store = artifact_store.get_store(settings)

    for run in workspace.run_refs(settings):
        run_id = run.path
        try:
            age_base = _run_age(store, run)
            if age_base is None:
                # Gone between the listing and now.
                deleted += 1
                continue
            if age_base > cutoff:
                kept += 1
                continue
            workspace.delete_run(settings, run)
            workspace.forget_run_marker(run)
            deleted += 1
            LOG.info("Run retention: deleted expired run %s", run_id)
        except (artifact_store.ArtifactStoreError, OSError):
            errors += 1
            LOG.warning("Run retention: could not remove run %s", run_id, exc_info=True)
        except Exception:  # noqa: BLE001
            errors += 1
            LOG.exception("Run retention: unexpected error removing %s", run_id)

    return _stats((deleted, errors, kept), _sweep_job_inputs(settings, cutoff))


def _run_age(
    store: artifact_store.ArtifactStore, run: artifact_store.keys.RunRef
) -> float | None:
    """When this run last mattered, in epoch seconds, or ``None`` if it is gone.

    Three answers, in the order they deserve to be believed:

    1. ``run_meta.json``'s own timestamps, because they say when the *scan*
       happened. Storage timestamps say when the bytes were last written, and a
       restored backup or a re-uploaded archive would make a year-old run look
       like this morning's.
    2. Failing that, when ``run_meta.json`` was written -- it is the last file a
       run produces, so its age is the run's age even when its contents carry
       no timestamp (an older scanner, a CLI run).
    3. Failing that, the newest object anywhere in the run. Newest rather than
       oldest: a run is as young as its most recent write, and ageing one out on
       its first file would delete a scan still being added to.
    """
    meta_key = artifact_store.keys.run_artifact(run, "run_meta.json")
    try:
        meta = json.loads(store.get_bytes(meta_key).decode("utf-8"))
    except artifact_store.ArtifactNotFound:
        meta = None
    except (artifact_store.ArtifactStoreError, UnicodeDecodeError, json.JSONDecodeError):
        meta = None
    stamp = _timestamp_from_meta(meta)
    if stamp is not None:
        return stamp
    if meta is not None:
        entry = store.stat(meta_key)
        if entry is not None:
            return entry.modified
    return _prefix_modified(store, artifact_store.keys.run_prefix(run))


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
