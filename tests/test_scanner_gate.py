"""The scanner-child gate itself (tests/scanner_gate.py).

The gate exists because no test report could show the leak it looks for: the
tests that abandoned a scan all passed. That makes the gate's own arithmetic
the only thing standing between the suite and a silent return of the bug, so
it is exercised here against process tables written by hand — a real leak is
not something a test may create on purpose.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

from tests import scanner_gate

SCANNER = "/usr/bin/python3 -m scanner.main --config /tmp/pytest-of-x/test_something0/c.yaml"


def test_a_scan_below_this_process_is_found():
    table = [
        (100, 1, "/usr/bin/python3 -m pytest -q"),
        (200, 100, SCANNER),
    ]
    assert scanner_gate.scanner_descendants(100, table) == [(200, SCANNER)]


def test_a_scan_somewhere_else_on_the_machine_is_not_ours():
    """A developer's own scan, or a second worktree's run, is not this
    session's leak to report — and failing somebody else's suite for it would
    be worse than the leak."""
    table = [
        (100, 1, "/usr/bin/python3 -m pytest -q"),
        (300, 1, SCANNER),
        (400, 300, SCANNER),
    ]
    assert scanner_gate.scanner_descendants(100, table) == []


def test_the_whole_subtree_counts_not_just_the_children():
    """An agent-executed scan is a grandchild: pytest runs the worker, the
    worker runs the scanner."""
    table = [
        (100, 1, "/usr/bin/python3 -m pytest -q"),
        (200, 100, "/usr/bin/python3 -m agent.worker"),
        (300, 200, SCANNER),
    ]
    assert scanner_gate.scanner_descendants(100, table) == [(300, SCANNER)]


def test_a_recycled_pid_does_not_send_the_walk_in_circles():
    """``ps`` is sampled rather than snapshotted, so the table it returns need
    not describe a tree."""
    table = [
        (100, 1, "/usr/bin/python3 -m pytest -q"),
        (200, 100, "sh -c loop"),
        (100, 200, "/usr/bin/python3 -m pytest -q"),
    ]
    assert scanner_gate.scanner_descendants(100, table) == []


def test_the_report_names_the_test_that_started_the_scan():
    """The point of printing the command line in full: a local scan is
    configured through files under its own test's tmp_path, so the path is the
    only record of which test left it behind."""
    lines = scanner_gate.leak_report([(200, SCANNER)])
    assert lines
    assert any("test_something0" in line for line in lines)
    assert "1 scanner process(es)" in lines[0]


def test_a_clean_session_reports_nothing():
    assert scanner_gate.leak_report([]) == []


def test_a_reaped_corpse_is_not_a_running_process():
    """The distinction ``os.kill(pid, 0)`` cannot make, and the whole of why
    this helper exists.

    A scan whose parent has just been killed is left unreaped wherever pid 1
    does not reap -- a container's pid 1 is the pipeline's shell, which reaps
    nothing, while macOS init does it in milliseconds. So the question "is it
    still running" answered differently on the two, and the local run could not
    have told us (shapoclyack-branches #1).
    """
    child = subprocess.Popen([sys.executable, "-c", ""])
    try:
        # Deliberately not ``child.poll()``: that reaps it, which is exactly
        # what must not happen before the state is read.
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and scanner_gate.process_state(child.pid) not in {"Z", ""}:
            time.sleep(0.01)
        assert scanner_gate.process_state(child.pid) == "Z", "the corpse was reaped too early"
        assert not scanner_gate.is_running(child.pid)
    finally:
        child.wait()


def test_this_process_is_running():
    assert scanner_gate.is_running(os.getpid())


def test_the_gate_can_read_the_process_table_here():
    """Not a tautology: the check that failed silently in CI is the one that
    could not read the table at all, and it looked exactly like a pass."""
    scanner_gate.scanner_descendants(os.getpid())
    assert scanner_gate._source is not None, (  # noqa: SLF001
        "neither /proc nor ps answered: the gate would pass every run without looking"
    )
