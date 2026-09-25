"""What a sensor keeps of its own scans on disk, and for how long.

The scanner writes each run to ``<output_dir>/runs/<run_id>`` (and a small
``<state_dir>/runs/<run_id>`` beside it); the worker tars the run into the job's
temporary directory and uploads that. The archive goes with the temporary
directory when the job ends, but the run directory used to stay for ever: a
systemd sensor filled its disk one scan at a time, and an in-cluster one grew
its ``emptyDir`` until the kubelet evicted the pod — mid-scan, because that is
when the directory grows.

What is removed:

* a run whose archive the API **acknowledged** — the results call answered 2xx,
  which it does only once the ingest is finished — at the end of that job;
* every other run once it is ``OCTO_AGENT_RUN_RETENTION_HOURS`` old: the scan
  failed and sent nothing, the upload failed, the API refused the result, or a
  crash or an older release left it behind. Kept until then for debugging;
* past ``OCTO_AGENT_RUN_MAX_BYTES``, the oldest removable runs until the total
  is under it again.

What is never removed, whatever the limits say:

* the run a job is executing (:meth:`RunRetention.job`);
* the partial results of a cancelled scan that the API has not acknowledged,
  for :data:`OWED_PROTECTION_SECONDS` (#360). The API still takes that archive
  late, and this is the only copy of it;
* the **baseline**: the run the scanner's ``latest_run.json`` names. The next
  scan diffs against it, and that ``diff.json`` is where the API's asset events
  come from (``api/services/asset_events.py`` — new hosts, ports, CVEs and
  expiring certificates, and the webhooks behind them); ``--delta`` reads its
  ``alive_ips.txt``. Removing it fails nothing: the next run quietly has no diff
  and publishes no events. So an acknowledged run that is also the baseline
  stays until the next run replaces it — one run on disk in the steady state.

Which runs are this sensor's own, and how each one ended, is kept in a small
ledger beside ``runs/`` (``.octo-agent-runs/<run_id>.json``) rather than in the
run directory, which is what gets archived and uploaded.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shutil
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

LOG = logging.getLogger("octo-agent")

#: ``scanner/pipeline/run_ids.RUN_ID_RE``, copied rather than imported so that
#: ``import agent.worker`` does not start depending on the scanner package;
#: ``tests/test_agent_run_retention.py`` keeps the two equal. It matters more
#: here than anywhere: a run id is the API's string, and this module deletes the
#: directory it names — ``..`` would be the whole output directory.
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")

#: How long a cancelled scan's unacknowledged partial results are kept out of
#: every sweep. The API takes the archive until one cancellation grace period
#: after the reaper finished the job (``api/services/job_results.py``,
#: ``_accepts_late_archive``) — about eleven minutes at the default
#: ``OCTO_JOB_CANCEL_GRACE_SECONDS``. An hour covers any grace an operator
#: plausibly sets; after it the run is an ordinary unacknowledged one.
OWED_PROTECTION_SECONDS = 3600.0

#: How often an idle sensor sweeps. The end of every job sweeps as well, so
#: this only has to catch runs ageing past the retention while nothing runs.
SWEEP_INTERVAL_SECONDS = 900.0

DEFAULT_RETENTION_HOURS = 72.0
DEFAULT_MAX_BYTES = 5 * 1024**3

#: ``runs/_tenants`` is the API's local artifact store (``api/services/
#: artifact_store/keys.py``). A sensor's own output never has it, so seeing it
#: means OCTO_OUTPUT_DIR is shared with an API — and every flat ``runs/<id>``
#: there that this sensor did not write may be the API's only copy of a run.
_API_STORE_MARKER = "_tenants"
_LEDGER_DIR = ".octo-agent-runs"
_RUNNING = "running"
_OWED = "owed"
_DELIVERED = "delivered"


@dataclass(frozen=True)
class _Run:
    run_id: str
    size: int
    #: The newest modification anywhere in the run: a failed run's age is from
    #: its last write, not from when the directory was created.
    mtime: float


class RunRetention:
    """Removes run directories this sensor no longer needs; see the module doc.

    ``retention_hours`` and ``max_bytes`` of 0 switch that limit off. Removing
    an acknowledged run does not depend on either.
    """

    def __init__(
        self,
        output_dir: Path,
        *,
        config: Path | None = None,
        retention_hours: float = DEFAULT_RETENTION_HOURS,
        max_bytes: int = DEFAULT_MAX_BYTES,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.runs_dir = Path(output_dir) / "runs"
        self._ledger_dir = Path(output_dir) / _LEDGER_DIR
        self._config = config
        self.retention_seconds = max(0.0, float(retention_hours)) * 3600.0
        self.max_bytes = max(0, int(max_bytes))
        self._clock = clock
        self._lock = threading.Lock()
        self._active: set[str] = set()
        self._warned_shared = False

    @contextlib.contextmanager
    def job(self, run_id: str) -> Iterator[None]:
        """Hold ``run_id`` out of every sweep while a job executes it; sweep after.

        Covers the scan, the packing of the archive and the upload — a
        cancelled run's partial results are "in progress" until the API has
        answered for them. A run id the API requeued to this sensor starts its
        ledger entry over: how the last attempt ended is not about this one.
        """
        with self._lock:
            self._active.add(run_id)
        self._record(run_id, _RUNNING)
        try:
            yield
        finally:
            with self._lock:
                self._active.discard(run_id)
            self.sweep()

    def mark_owed(self, run_id: str) -> None:
        """A cancelled scan's partial results are about to be sent (#360).

        Written *before* the upload, so a sensor killed while sending them
        still knows on restart that they are owed.
        """
        self._record(run_id, _OWED)

    def mark_delivered(self, run_id: str) -> None:
        """The API acknowledged this run's archive: the sensor's copy is spare."""
        self._record(run_id, _DELIVERED)

    def sweep(self) -> list[str]:
        """Remove what the rules allow; return the run ids removed. Never raises.

        A sweep that fails is logged and tried again at the next one: the disk
        filling up is a slow problem, and a scan must not be lost to it.
        """
        try:
            return self._sweep()
        except Exception:  # noqa: BLE001
            LOG.warning("Sweeping old run directories in %s failed", self.runs_dir, exc_info=True)
            return []

    def _sweep(self) -> list[str]:
        if not self.runs_dir.is_dir():
            return []
        now = self._clock()
        ledger = self._read_ledger()
        runs = self._list_runs()
        state_dir = self._state_dir()
        with self._lock:
            protected = set(self._active)
        baseline = self._baseline(runs, state_dir)
        if baseline is not None:
            protected.add(baseline)
        for run_id, (state, at) in ledger.items():
            if state == _OWED and now - at < OWED_PROTECTION_SECONDS:
                protected.add(run_id)

        shared = (self.runs_dir / _API_STORE_MARKER).is_dir()
        if shared and not self._warned_shared:
            self._warned_shared = True
            LOG.warning(
                "%s also holds an API's run store (runs/%s); only runs this sensor "
                "executed itself are removed from it. Give the sensor an "
                "OCTO_OUTPUT_DIR of its own",
                self.runs_dir,
                _API_STORE_MARKER,
            )

        def removable(run: _Run) -> bool:
            return run.run_id not in protected and (not shared or run.run_id in ledger)

        removed: list[str] = []
        kept: list[_Run] = []
        for run in runs:
            reason = None
            if removable(run):
                if ledger.get(run.run_id, ("", 0.0))[0] == _DELIVERED:
                    reason = "acknowledged by the API"
                elif self.retention_seconds and now - run.mtime > self.retention_seconds:
                    reason = f"older than {self.retention_seconds / 3600:g}h"
            if reason is not None and self._remove(run.run_id, reason, state_dir):
                removed.append(run.run_id)
            else:
                kept.append(run)

        if self.max_bytes:
            total = sum(run.size for run in kept)
            for run in sorted(kept, key=lambda item: item.mtime):
                if total <= self.max_bytes:
                    break
                if removable(run) and self._remove(
                    run.run_id, "over OCTO_AGENT_RUN_MAX_BYTES", state_dir
                ):
                    removed.append(run.run_id)
                    total -= run.size
            if total > self.max_bytes:
                LOG.warning(
                    "Run directories in %s take %d bytes, over the %d budget; what is left "
                    "is the run in progress, the baseline the next scan diffs against, or "
                    "partial results the API is still owed",
                    self.runs_dir,
                    total,
                    self.max_bytes,
                )

        self._prune_ledger({run.run_id for run in runs} - set(removed))
        return removed

    def _list_runs(self) -> list[_Run]:
        runs: list[_Run] = []
        with os.scandir(self.runs_dir) as entries:
            for entry in entries:
                # Real directories named like a run id only: not the API's
                # ``_tenants``, not a hidden staging tree, not a symlink that
                # would have the sweep delete whatever it points at.
                if not RUN_ID_RE.fullmatch(entry.name) or not entry.is_dir(follow_symlinks=False):
                    continue
                try:
                    size, mtime = _measure(Path(entry.path))
                except OSError:
                    continue  # removed under us
                runs.append(_Run(entry.name, size, mtime))
        return runs

    def _baseline(self, runs: list[_Run], state_dir: Path | None) -> str | None:
        """The run the next scan diffs against, or the newest one if that is unknown.

        ``latest_run.json`` is the scanner's own answer, so it is used when it
        can be read. When it cannot — no config, no PyYAML, the pointer not
        there — the newest run is what the scanner last started, and keeping
        one run too many costs less than removing the one it diffs against.
        """
        pointed = _latest_run_id(state_dir) if state_dir is not None else None
        if pointed is not None:
            return pointed
        return max(runs, key=lambda run: run.mtime).run_id if runs else None

    def _state_dir(self) -> Path | None:
        """``runtime.state_dir`` of the scanner config this worker passes along.

        Relative paths resolve against this process's working directory, which
        is the one the scanner inherits. ``None`` when it cannot be known.
        """
        if self._config is None:
            return None
        try:
            import yaml  # the scanner's dependency; the worker itself does not need it
        except ImportError:
            return None
        try:
            raw = yaml.safe_load(self._config.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return None
        runtime = raw.get("runtime") if isinstance(raw, dict) else None
        state_dir = runtime.get("state_dir") if isinstance(runtime, dict) else None
        # scanner/pipeline/config_schema.RuntimeConfig's default.
        return Path(str(state_dir or "scanner/state"))

    def _remove(self, run_id: str, reason: str, state_dir: Path | None) -> bool:
        path = self.runs_dir / run_id
        if not RUN_ID_RE.fullmatch(run_id) or path.is_symlink():
            return False
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except OSError:
            LOG.warning("Could not remove run directory %s", path, exc_info=True)
            return False
        # The scanner's per-run state (checkpoint.json) is only ever read by a
        # --resume of the same run, which the worker never asks for.
        if state_dir is not None:
            state_path = state_dir / "runs" / run_id
            if not state_path.is_symlink():
                shutil.rmtree(state_path, ignore_errors=True)
        with contextlib.suppress(OSError):
            (self._ledger_dir / f"{run_id}.json").unlink()
        LOG.info("Removed run directory %s (%s)", path, reason)
        return True

    def _record(self, run_id: str, state: str) -> None:
        if not RUN_ID_RE.fullmatch(run_id):
            return
        target = self._ledger_dir / f"{run_id}.json"
        tmp = self._ledger_dir / f".{run_id}.tmp"
        try:
            self._ledger_dir.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps({"state": state, "at": self._clock()}), encoding="utf-8")
            os.replace(tmp, target)
        except OSError:
            # Failing safe: a run the ledger does not call delivered is kept
            # until it ages out, never removed early.
            LOG.warning("Could not record run %s as %s", run_id, state, exc_info=True)

    def _read_ledger(self) -> dict[str, tuple[str, float]]:
        ledger: dict[str, tuple[str, float]] = {}
        try:
            paths = list(self._ledger_dir.glob("*.json"))
        except OSError:
            return ledger
        for path in paths:
            if not RUN_ID_RE.fullmatch(path.stem):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                ledger[path.stem] = (str(data["state"]), float(data["at"]))
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return ledger

    def _prune_ledger(self, existing: set[str]) -> None:
        """Drop entries for runs that are gone, other than the one in progress.

        A job's entry is written before the scanner creates its directory, and
        a job cancelled before it started never creates one at all.
        """
        with self._lock:
            keep = existing | self._active
        try:
            paths = list(self._ledger_dir.glob("*.json"))
        except OSError:
            return
        for path in paths:
            if path.stem not in keep:
                with contextlib.suppress(OSError):
                    path.unlink()


def _latest_run_id(state_dir: Path) -> str | None:
    """The run id in the scanner's ``latest_run.json``, if it is a valid one."""
    try:
        data = json.loads((state_dir / "latest_run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    run_id = str(data.get("run_id") or "") if isinstance(data, dict) else ""
    return run_id if RUN_ID_RE.fullmatch(run_id) else None


def _measure(path: Path) -> tuple[int, float]:
    """Apparent size of the files under ``path``, and the newest mtime in it."""
    total = 0
    newest = path.lstat().st_mtime
    for root, dirs, files in os.walk(path):
        for names, is_file in ((dirs, False), (files, True)):
            for name in names:
                try:
                    st = os.lstat(os.path.join(root, name))
                except OSError:
                    continue
                newest = max(newest, st.st_mtime)
                if is_file:
                    total += st.st_size
    return total, newest
