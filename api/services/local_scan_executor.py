"""Local scan process lifecycle.

Owns the process handles for scans executed inside the API replica. Queue state,
lease state and post-run projections stay in jobs; this module is deliberately
limited to process/thread lifecycle so the executor can be replaced without
dragging job persistence with it.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import threading
import time

_USE_PROCESS_GROUP = sys.platform != "win32"

_lock = threading.Lock()
_threads: set[threading.Thread] = set()
_processes: dict[str, "subprocess.Popen[str]"] = {}
_draining = threading.Event()

# Captured before tests replace threading.Thread.
REAL_THREAD = threading.Thread


def register_thread(thread: threading.Thread) -> None:
    """Register a real executor thread and discard finished handles."""
    if not isinstance(thread, REAL_THREAD):
        return
    with _lock:
        _threads.difference_update({item for item in _threads if not item.is_alive()})
        _threads.add(thread)


def run_scanner(job_id: str, command: list[str]) -> subprocess.CompletedProcess[str]:
    """Run one scanner process and keep it reachable while it lives."""
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=_USE_PROCESS_GROUP,
    )
    with _lock:
        _processes[job_id] = proc
    if _draining.is_set():
        _terminate(proc)
    try:
        stdout, stderr = proc.communicate()
    finally:
        with _lock:
            _processes.pop(job_id, None)
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)


def _terminate(proc: "subprocess.Popen[str]") -> None:
    """Terminate a scanner and its child tools, escalating to SIGKILL."""
    if proc.poll() is not None:
        return
    try:
        if _USE_PROCESS_GROUP:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:  # pragma: no cover - Windows CI is not used
            proc.terminate()
    except (ProcessLookupError, OSError):
        return
    try:
        proc.wait(timeout=5.0)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        if _USE_PROCESS_GROUP:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover
            proc.kill()
    except (ProcessLookupError, OSError):
        pass
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=5.0)


def live() -> list[str]:
    """Describe local scanner processes and executor threads still alive."""
    with _lock:
        alive = [
            f"job {job_id} (pid {proc.pid})"
            for job_id, proc in _processes.items()
            if proc.poll() is None
        ]
        alive.extend(
            f"executor thread {thread.name}" for thread in _threads if thread.is_alive()
        )
    return alive


def stop_all(timeout: float = 30.0) -> bool:
    """Stop all local scans and wait for executor bookkeeping to finish."""
    deadline = time.monotonic() + timeout
    _draining.set()
    try:
        while True:
            with _lock:
                processes = list(_processes.values())
                threads = [thread for thread in _threads if thread.is_alive()]
            for proc in processes:
                _terminate(proc)
            if not threads:
                break
            for thread in threads:
                thread.join(min(0.5, max(0.0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                break
    finally:
        _draining.clear()

    survivors = live()
    with _lock:
        _threads.clear()
        _processes.clear()
    return not survivors


# Compatibility views for tests and diagnostic tooling. They intentionally
# expose the live containers, not copies.
processes = _processes
threads = _threads
