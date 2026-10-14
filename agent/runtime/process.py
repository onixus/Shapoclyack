"""Bounded process mechanics shared by local API and autonomous POSIX sensor.

The caller owns registries, leases, archives and business result policies.
Windows fallback stops only the direct process; it does not promise a tree.
"""

from __future__ import annotations

import contextlib
import errno
import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from collections.abc import Callable, Mapping, Sequence


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    reason: str = "exited"


def terminate_process(
    proc: subprocess.Popen[str],
    *,
    use_session: bool = sys.platform != "win32",
    deadline: float | None = None,
    shutdown_budget: float = 10.0,
    term_grace: float = 5.0,
) -> None:
    """Serialize group cleanup under one deadline, including lock contention."""
    end = deadline if deadline is not None else time.monotonic() + shutdown_budget
    if getattr(proc, "_scan_stopped", False) is True:
        return
    # Every stop can tighten an owner's budget without acquiring its held
    # lock. Atomic append never overwrites a concurrent shorter deadline.
    deadlines = proc.__dict__.setdefault("_scan_shutdown_deadlines", [])
    deadlines.append(end)
    # Popen has a normal instance dictionary. setdefault installs one shared
    # lock atomically without a second, globally contended coordination lock.
    lock = proc.__dict__.setdefault("_scan_stop_lock", threading.Lock())
    if not lock.acquire(timeout=max(0.0, end - time.monotonic())):
        return
    try:
        if getattr(proc, "_scan_stopped", False) is True:
            return
        gone = False

        def group_operation(sig: int) -> None:
            nonlocal gone
            if gone:
                return
            if proc.returncode is not None:
                # The leader is reaped, so its PID is free again. While any
                # member of our group lives the kernel keeps that number
                # reserved as the PGID; once something else owns the PID, the
                # group is empty and the number now names a stranger's group.
                try:
                    os.getpgid(proc.pid)
                except ProcessLookupError:
                    pass
                except OSError as exc:
                    if exc.errno != errno.ESRCH:
                        gone = True
                        return
                else:
                    gone = True
                    return
            try:
                # The initial session PGID is the original PID, even after
                # leader exit. Once ESRCH is observed, ownership is terminal:
                # no later signal may hit an unrelated reused group id.
                os.killpg(proc.pid, sig)
            except ProcessLookupError:
                gone = True
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    gone = True

        def send(sig: int) -> None:
            if use_session:
                group_operation(sig)
            elif proc.poll() is None:
                with contextlib.suppress(ProcessLookupError, OSError):
                    proc.terminate() if sig == signal.SIGTERM else proc.kill()

        send(signal.SIGTERM)
        grace_end = min(end, time.monotonic() + term_grace)
        while not gone and time.monotonic() < min(grace_end, _shutdown_end(proc, end)):
            proc.poll()
            if use_session:
                group_operation(0)
                if gone:
                    break
            elif proc.poll() is not None:
                break
            time.sleep(
                min(
                    0.02,
                    max(
                        0.0, min(grace_end, _shutdown_end(proc, end)) - time.monotonic()
                    ),
                )
            )
        send(signal.SIGKILL)
        # A waiter may tighten the budget after SIGKILL as well. Reaping in
        # slices avoids committing to the original owner's longer wait.
        while True:
            remaining = max(0.0, _shutdown_end(proc, end) - time.monotonic())
            try:
                proc.wait(timeout=min(0.02, remaining))
                break
            except subprocess.TimeoutExpired:
                if remaining <= 0:
                    break
        proc._scan_stopped = True  # type: ignore[attr-defined]
    finally:
        lock.release()


def run_process(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    timeout: float | None = None,
    cancel_event: threading.Event | None = None,
    on_spawn: Callable[[subprocess.Popen[str]], None] | None = None,
    on_finish: Callable[[subprocess.Popen[str]], None] | None = None,
    use_session: bool = sys.platform != "win32",
    poll_interval: float = 0.1,
    shutdown_budget: float = 10.0,
) -> ProcessResult:
    """Drain both pipes while checking cancellation and a monotonic deadline.

    Spawn errors deliberately propagate: each adapter retains its prior error
    policy. Cancellation before spawn never starts a child.
    """
    if cancel_event is not None and cancel_event.is_set():
        return ProcessResult(143, reason="cancelled")
    deadline = None if timeout is None else time.monotonic() + timeout
    proc = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=use_session,
        env=env,
    )
    shutdown_end = None
    try:
        if on_spawn is not None:
            on_spawn(proc)
        while True:
            reason = None
            if cancel_event is not None and cancel_event.is_set():
                reason = "cancelled"
            elif deadline is not None and time.monotonic() >= deadline:
                reason = "timeout"
            if reason is not None:
                shutdown_end = time.monotonic() + shutdown_budget
                terminate_process(
                    proc,
                    use_session=use_session,
                    deadline=shutdown_end,
                    term_grace=min(5.0, shutdown_budget / 2),
                )
                shutdown_end = _shutdown_end(proc, shutdown_end)
                try:
                    stdout, stderr = proc.communicate(
                        timeout=max(0.0, shutdown_end - time.monotonic())
                    )
                except subprocess.TimeoutExpired as exc:
                    stdout = _text(exc.output)
                    stderr = _text(exc.stderr)
                return ProcessResult(
                    143 if reason == "cancelled" else 124, stdout, stderr, reason
                )
            wait = (
                poll_interval
                if deadline is None
                else min(poll_interval, max(0.0, deadline - time.monotonic()))
            )
            try:
                stdout, stderr = proc.communicate(timeout=wait)
                return ProcessResult(proc.returncode, stdout, stderr)
            except subprocess.TimeoutExpired:
                continue
    finally:
        # Exceptional callbacks/decoding must not orphan a child either.
        # Ownership lasts through complete group cleanup, including a natural
        # leader exit whose children closed their inherited output pipes.
        # Cancellation/timeout reuse the existing end, never a second budget.
        if shutdown_end is None:
            shutdown_end = time.monotonic() + shutdown_budget
        terminate_process(
            proc,
            use_session=use_session,
            deadline=shutdown_end,
            term_grace=min(5.0, shutdown_budget / 2),
        )
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None:
                pipe.close()
        if on_finish is not None:
            on_finish(proc)


def _text(value: str | bytes | None) -> str:
    return value.decode(errors="replace") if isinstance(value, bytes) else value or ""


def _shutdown_end(proc: subprocess.Popen[str], fallback: float) -> float:
    return min([fallback, *proc.__dict__.get("_scan_shutdown_deadlines", ())])
