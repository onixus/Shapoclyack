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
    """Run the scanner to completion, leaving a handle on it while it lives.

    Same result as the ``subprocess.run`` this replaces, plus two things that
    call is structurally unable to offer: the process is registered in
    :data:`_processes` while it runs, so :func:`stop_all` can
    find it, and it is put in its own session, so signalling it reaches the
    tools it has shelled out to rather than just the Python parent. That is the
    same shape the agent's copy of this has used since #360
    (``agent/worker.py:_run_scan``); the API's local path simply never had a
    caller that wanted the process back.
    """
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
        # Started into a stop. The window is small -- between the thread being
        # registered and this line -- but it is the whole of the leak that
        # survived the first version of this: a stop that finds the registry
        # empty has nothing to signal, and goes on to wait out a scan that had
        # not been spawned yet when it looked.
        _terminate(proc)
    try:
        stdout, stderr = proc.communicate()
    finally:
        with _lock:
            _processes.pop(job_id, None)
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)


def _terminate(proc: "subprocess.Popen[str]") -> None:
    """Put down one scanner and everything it started.

    The process *group*, for the reason ``agent/worker.py`` gives: a scan is
    ``scanner.main`` driving nmap, httpx and nuclei, and killing only the
    parent leaves the tool that is actually touching the target running with
    nobody to report it. SIGTERM first so the pipeline can close its files,
    SIGKILL for whatever ignores it.
    """
    if proc.poll() is not None:
        return
    try:
        if _USE_PROCESS_GROUP:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:  # pragma: no cover - the suite does not run on Windows
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
        else:  # pragma: no cover - the suite does not run on Windows
            proc.kill()
    except (ProcessLookupError, OSError):
        pass
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=5.0)


def live() -> list[str]:
    """The local scans still running here, described for a failure message.

    What makes a leak hard to chase is that the process says nothing about the
    test that started it until you go and read ``/proc``; naming the job and
    the pid at the moment the stop gives up saves that step.
    """
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
    """Stop every scan this process is running locally. ``False`` on timeout.

    Test-suite scaffolding, like ``agent_deployer.join_workers`` and
    ``channels.join_senders``, and not a production path: the API has no way to
    stop a running local scan and ``cancel_job`` says so rather than pretending
    otherwise.

    What makes it necessary is that a started scan is a real ``scanner.main``
    doing real work while the test that asked for it is asserting on a row. A
    test like "an operator granted only viewer may not start a scan" finishes
    in milliseconds; the scan the *allowed* half of it started runs for
    minutes. One session ended with seven of them alive at once, aged up to six
    minutes, all children of a pytest that had long since moved on -- and some
    outlived pytest itself, because the executor thread is a daemon and daemon
    threads are not waited for.

    The threads are joined *after* the processes are signalled, never instead
    of it: the executor's bookkeeping writes status, metrics and scratch files
    to the same tables the next test truncates, so returning while one is still
    running would trade the leak for the race #257 and #351 already document.

    The registry is emptied either way, so the answer is given once: see the
    comment on that below.
    """
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
            # A slice rather than the whole budget, because an executor still
            # on its way to ``Popen`` is alive and holding no process yet: the
            # next pass is what signals the scan it spawns in the meantime.
            for thread in threads:
                thread.join(min(0.5, max(0.0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                break
    finally:
        _draining.clear()

    survivors = live()
    with _lock:
        # Emptied whether or not everything stopped. What survived a SIGKILL
        # to its process group will not answer a second round either, and
        # keeping the handle would fail the teardown of every test after the
        # one that actually caused it — burying the report in its own echo.
        # The caller is told once, here; the session-wide check in
        # tests/scanner_gate.py is what still sees the process itself.
        _threads.clear()
        _processes.clear()
    return not survivors


# Compatibility views for tests and diagnostic tooling. They intentionally
# expose the live containers, not copies.
processes = _processes
threads = _threads
