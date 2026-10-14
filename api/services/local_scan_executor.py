"""Local scan process lifecycle.

Owns the process handles for scans executed inside the API replica. Queue state,
lease state and post-run projections stay in jobs; this module is deliberately
limited to process/thread lifecycle so the executor can be replaced without
dragging job persistence with it.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time

from agent.runtime.process import run_process, terminate_process

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
    """Run through shared mechanics, with this replica's live registry.

    Local scans retain their historical unlimited duration. Draining is a
    replica-local teardown signal, not cross-replica production cancellation.
    """

    def register(proc):
        with _lock:
            _processes[job_id] = proc

    def unregister(proc):
        with _lock:
            if _processes.get(job_id) is proc:
                _processes.pop(job_id, None)

    result = run_process(
        command,
        cancel_event=_draining,
        on_spawn=register,
        on_finish=unregister,
        use_session=_USE_PROCESS_GROUP,
    )
    return subprocess.CompletedProcess(
        command, result.returncode, result.stdout, result.stderr
    )


def wait_unless_draining(seconds: float) -> bool:
    """Sleep ``seconds``, waking early when :func:`stop_all` begins.

    For a local scan waiting for its tenant's slot (#365): ``True`` means the
    process is stopping its scans and the waiting thread should give up
    rather than hold :func:`stop_all` for the rest of its budget.
    """
    return _draining.wait(seconds)


def _terminate(proc: "subprocess.Popen[str]") -> None:
    """Compatibility forwarding wrapper."""
    terminate_process(proc, use_session=_USE_PROCESS_GROUP)


def live() -> list[str]:
    """The local scans still running here, described for a failure message.

    What makes a leak hard to chase is that the process says nothing about the
    test that started it until you go and read ``/proc``; naming the job and
    the pid at the moment the stop gives up saves that step.
    """
    with _lock:
        alive = [
            f"job {job_id} (pid {proc.pid})" for job_id, proc in _processes.items()
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

    On timeout the registry and draining barrier remain until a subsequent
    stop observes completion; late spawns cannot escape a failed shutdown.
    """
    deadline = time.monotonic() + timeout
    _draining.set()
    try:
        while True:
            with _lock:
                processes = list(_processes.values())
                threads = [thread for thread in _threads if thread.is_alive()]
            for proc in processes:
                terminate_process(
                    proc,
                    use_session=_USE_PROCESS_GROUP,
                    deadline=deadline,
                    term_grace=min(5.0, max(0.0, deadline - time.monotonic()) / 2),
                )
            if not threads and not processes:
                break
            # A slice rather than the whole budget, because an executor still
            # on its way to ``Popen`` is alive and holding no process yet: the
            # next pass is what signals the scan it spawns in the meantime.
            for thread in threads:
                thread.join(min(0.5, max(0.0, deadline - time.monotonic())))
            if time.monotonic() >= deadline:
                break
    finally:
        survivors = live()
        if not survivors:
            _draining.clear()

    with _lock:
        _threads.difference_update(
            {thread for thread in _threads if not thread.is_alive()}
        )
    # A timed-out handle remains visible until run_process's on_finish removes
    # it. Clearing it here would conceal an inherited pipe or late spawn.

    return not survivors


# Compatibility views for tests and diagnostic tooling. They intentionally
# expose the live containers, not copies.
processes = _processes
threads = _threads
