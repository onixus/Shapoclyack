"""A local scan belongs to the process that started it, and can be put down.

Starting a scan in local execution mode spawns ``python -m scanner.main`` from
a daemon thread, and the API deliberately offers no way to stop one:
``cancel_job`` refuses a running local job because the only thing that could
signal it is the thread that spawned it, which may be in another replica.

That left the test suite with no way either. Tests that start a scan and then
assert on the row — an RBAC refusal, a 202, a tenant id — finish in
milliseconds and used to leave the scan running for minutes; a session on
2026-09-21 held seven of them at once, and some outlived pytest, because a
daemon thread is never joined and its child is simply reparented at exit.

``stop_local_scans`` is the missing handle, and these are the three claims it
makes: the scan dies, everything it started dies with it, and the executor
thread is finished writing before the call returns.
"""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.services.integrations import webhooks as webhooks_service
from api.services.jobs import get_job
from tests.conftest import approve_scan_scope, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    base = make_settings(tmp_path, job_execution_mode="local")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    agents_service.configure(base)
    # The executor thread runs _run_job's post-scan bookkeeping to the end,
    # which reaches the webhook fan-out; without this it logs an assertion
    # instead, in the middle of the test that is watching it finish.
    webhooks_service.configure(base)
    webhooks_service.reset_for_tests()
    return base


def _stand_in_for_the_scanner(monkeypatch, script: str) -> None:
    """Make the next local scan run ``script`` instead of the real pipeline.

    The command is replaced rather than the pipeline configured to be slow: a
    scan long enough to still be running when the test looks at it is a scan
    long enough to hurt if the test is wrong about killing it, and what is
    under test here is the lifecycle, not the scanner.
    """
    monkeypatch.setattr(
        jobs_service, "_build_command", lambda *a, **k: [sys.executable, "-c", script]
    )


def _wait_for_the_scan(job_id: str, timeout: float = 30.0):
    """The scanner process for ``job_id``, once the executor thread has it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        proc = jobs_service._local_scan_procs.get(job_id)  # noqa: SLF001
        if proc is not None:
            return proc
        time.sleep(0.01)
    raise AssertionError(f"no scanner process registered for {job_id}")


def _wait_for_the_file(path: Path, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"the stand-in never wrote {path}")


def _alive(pid: int) -> bool:
    """Whether ``pid`` is a process that is still running.

    Asked of ``ps`` rather than of ``os.kill(pid, 0)``, which succeeds for a
    zombie -- and a zombie is exactly what the grandchild becomes here. Its
    parent is the scanner this test has just killed, so nobody is left to reap
    it: on macOS init does that within milliseconds, but the CI container's pid
    1 is the pipeline's shell and reaps nothing, so the test read a corpse as a
    survivor and failed there and only there.
    """
    state = subprocess.run(
        ["ps", "-o", "state=", "-p", str(pid)], capture_output=True, text=True, check=False
    ).stdout.strip()
    return bool(state) and not state.startswith("Z")


def test_a_started_local_scan_can_be_stopped(settings, monkeypatch):
    """The whole of the bug in one test: a scan that outlives its caller, and
    a caller that can now end it."""
    _stand_in_for_the_scanner(monkeypatch, "import time; time.sleep(600)")

    started = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    proc = _wait_for_the_scan(started.job_id)
    assert proc.poll() is None, "the stand-in exited on its own; the test proves nothing"

    assert jobs_service.stop_local_scans(timeout=30.0)
    assert proc.poll() is not None
    # Nothing is left registered, so a second call is a no-op rather than a
    # second round of signals at some unrelated process that reused the pid.
    assert not jobs_service._local_scan_procs  # noqa: SLF001
    assert jobs_service.stop_local_scans(timeout=5.0)


def test_the_tools_the_scan_started_go_down_with_it(settings, monkeypatch, tmp_path):
    """A scan is ``scanner.main`` driving nmap, httpx and nuclei. Signalling
    only the parent would leave whatever is actually touching the target
    running, with nobody left to report it — which is why the scanner gets a
    session of its own."""
    marker = tmp_path / "grandchild.pid"
    _stand_in_for_the_scanner(
        monkeypatch,
        "import pathlib, subprocess, sys, time;"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)']);"
        f"pathlib.Path({str(marker)!r}).write_text(str(child.pid));"
        "time.sleep(600)",
    )

    started = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    _wait_for_the_scan(started.job_id)
    _wait_for_the_file(marker)
    grandchild = int(marker.read_text())
    assert _alive(grandchild)

    assert jobs_service.stop_local_scans(timeout=30.0)
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline and _alive(grandchild):
        time.sleep(0.05)
    assert not _alive(grandchild), (
        f"pid {grandchild} survived the stop: the scanner was signalled, its tools were not"
    )


def test_the_executor_is_done_writing_before_the_call_returns(settings, monkeypatch):
    """Returning while the thread still runs would trade the leak for the race
    #257 and #351 document: the executor writes the job's status, its metrics
    and its scratch files to the same tables the next test truncates."""
    _stand_in_for_the_scanner(monkeypatch, "import time; time.sleep(600)")

    started = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    _wait_for_the_scan(started.job_id)

    assert jobs_service.stop_local_scans(timeout=30.0)
    job = get_job(settings, started.job_id)
    # Terminal, not "running": the killed scan has been accounted for, which is
    # the observable proof that the thread ran to the end of _run_job.
    assert job.status in {"failed", "cancelled"}, job.status
    assert job.finished_at is not None


def test_a_scan_that_ignores_sigterm_is_killed(settings, monkeypatch, tmp_path):
    """SIGTERM first so the pipeline can close its files; SIGKILL for whatever
    decides not to."""
    ready = tmp_path / "deaf.ready"
    _stand_in_for_the_scanner(
        monkeypatch,
        "import pathlib, signal, time;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"pathlib.Path({str(ready)!r}).write_text('ok');"
        "time.sleep(600)",
    )

    started = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin"
    )
    proc = _wait_for_the_scan(started.job_id)
    # Waited for, not assumed: a process signalled before the interpreter has
    # run its first line dies of the SIGTERM it never got the chance to ignore,
    # and the test would then pass without touching the escalation at all.
    _wait_for_the_file(ready)

    assert jobs_service.stop_local_scans(timeout=30.0)
    assert proc.poll() is not None
    assert proc.returncode == -signal.SIGKILL, proc.returncode


def test_a_stubbed_out_thread_class_is_not_taken_for_a_scan(settings, monkeypatch):
    """Several tests replace ``threading.Thread`` so that ``start_scan`` writes
    the row without running anything. The registry must not take their double
    for an executor: ``tests/test_api_targets.py`` uses a ``MagicMock``, whose
    ``is_alive()`` is a truthy mock forever, and one of those left in the set
    failed the teardown of every test that came after it."""
    monkeypatch.setattr(jobs_service.threading, "Thread", MagicMock())

    jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")

    assert not jobs_service.live_local_scans()
    assert jobs_service.stop_local_scans(timeout=1.0)


def test_nothing_started_is_nothing_to_stop(settings):
    """The autouse fixture calls this after every test in the suite, so the
    common case has to be free."""
    assert jobs_service.stop_local_scans(timeout=0.0)
