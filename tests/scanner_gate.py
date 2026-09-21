"""The scanner-child gate: no scan may outlive the session that started it.

The suite starts real scans. ``job_execution_mode`` defaults to ``local``, and
a local scan is ``python -m scanner.main`` spawned from a daemon thread inside
the API process — which here is pytest. Nothing in the API stops one
(``api/services/jobs.py:cancel_job`` refuses a running local job and explains
why), so until tests/conftest.py's ``_stop_local_scans`` fixture existed, every
test that started a scan and then asserted on a row left that scan running.

The damage was invisible in the report. Those tests pass — they are about 202s
and RBAC refusals, not about scans — so the only symptom was the machine: a
session on 2026-09-21 carried seven ``scanner.main`` processes at once, aged
1:37 to 5:56, all children of a pytest that had moved on, and took 15 minutes
against 13:36 for the same suite. Some outlived pytest itself: a daemon thread
is never joined, so at interpreter exit its child is simply reparented.

Nothing in a test result would have caught that, which is what this module is
for. It is the same shape as tests/integration_gate.py — a session-wide hook
that refuses to let a run end green on a condition the per-test reports cannot
express — and it lives in its own module for the same reason that one does: so
the check is readable on its own and can be driven directly by a test
(tests/test_ci_checks.py). It is registered from the repository-root
conftest.py, because a conftest may bind only one function per hook name and
tests/conftest.py has already given ``pytest_sessionfinish`` to the
integration gate.

Descendants of this process, not every ``scanner.main`` on the machine: a
developer's own scan, or another worktree's test run, is not this session's
leak to report.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

#: What a scan looks like in a process listing. The command is built by
#: ``jobs._build_command`` and ``agent/worker.py``, both of which run the
#: scanner as a module, so this substring is the whole of the match.
SCANNER_MARKER = "scanner.main"

_PS_ARGS = ("ps", "-A", "-o", "pid=,ppid=,command=")

#: How the process table was read, for the summary to report. ``None`` means it
#: could not be read at all, which is not the same answer as "nothing leaked".
_source: str | None = None


def _procfs_table() -> list[tuple[int, int, str]] | None:
    """The process table from ``/proc``, or ``None`` where there is no ``/proc``.

    Tried before ``ps`` because the CI container has no ``ps`` at all: the gate
    read an empty table there and passed every run without looking at anything
    (shapoclyack-branches #2 found this the hard way, through a test that used
    ``ps`` for something else).
    """
    proc = Path("/proc")
    if not (proc / "self" / "stat").exists():
        return None
    rows: list[tuple[int, int, str]] = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            # Exited between the listing and the read. Not an error: a process
            # that is already gone is not a leak.
            continue
        ppid = _ppid_from_stat(stat)
        if ppid is None:
            continue
        # NUL-separated argv; a kernel thread has an empty one and keeps the
        # comm from stat, which never matches the marker anyway.
        command = cmdline.decode("utf-8", errors="replace").replace("\0", " ").strip()
        rows.append((int(entry.name), ppid, command))
    return rows


def _ppid_from_stat(stat: str) -> int | None:
    """The parent pid out of one ``/proc/<pid>/stat`` line.

    Split after the last ``)`` rather than on whitespace: the second field is
    the executable name in parentheses and may contain both spaces and
    parentheses of its own, which is the classic way to misparse this file.
    """
    close = stat.rfind(")")
    if close == -1:
        return None
    fields = stat[close + 1 :].split()
    if len(fields) < 2:
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def _ps_table() -> list[tuple[int, int, str]] | None:
    """The process table from ``ps``, or ``None`` where there is none to run."""
    try:
        completed = subprocess.run(
            _PS_ARGS, capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    rows: list[tuple[int, int, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.split(None, 2)
        if len(fields) < 3:
            continue
        try:
            pid, ppid = int(fields[0]), int(fields[1])
        except ValueError:
            continue
        rows.append((pid, ppid, fields[2]))
    return rows


def _process_table() -> list[tuple[int, int, str]]:
    """``(pid, ppid, command)`` for every process, or nothing if it cannot be read.

    A gate that cannot look must not fail the run -- an unreadable process
    table is an unanswered question, not a leak -- but it must not pass
    silently either, so which source answered is recorded for the summary.
    """
    global _source
    for name, reader in (("procfs", _procfs_table), ("ps", _ps_table)):
        rows = reader()
        if rows is not None:
            _source = name
            return rows
    _source = None
    return []


def process_state(pid: int) -> str:
    """The process's state letter: ``""`` if it is gone, ``"?"`` if unknowable.

    Exported because ``os.kill(pid, 0)`` is the obvious way to ask whether a
    process is still there and is the wrong one: it succeeds for a zombie, and
    a scan whose parent has just been killed leaves exactly that behind
    wherever pid 1 does not reap (a container's pid 1 is the pipeline's shell,
    which reaps nothing; macOS init reaps in milliseconds, so the difference
    shows up only in CI).
    """
    stat_file = Path(f"/proc/{pid}/stat")
    if stat_file.exists():
        try:
            stat = stat_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        close = stat.rfind(")")
        fields = stat[close + 1 :].split() if close != -1 else []
        return fields[0] if fields else "?"
    if Path("/proc/self/stat").exists():
        # There is a /proc and this pid is not in it.
        return ""
    try:
        completed = subprocess.run(
            ["ps", "-o", "state=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "?"
    return completed.stdout.strip()


def is_running(pid: int) -> bool:
    """Whether ``pid`` is a live process. A zombie is not one."""
    state = process_state(pid)
    return bool(state) and not state.startswith("Z") and state != "?"


def scanner_descendants(
    root_pid: int, table: list[tuple[int, int, str]] | None = None
) -> list[tuple[int, str]]:
    """Scanner processes below ``root_pid``, as ``(pid, command)``.

    The whole subtree rather than the direct children: a scan run by the agent
    worker is a grandchild, and a scanner that has already shelled out to nmap
    has children of its own that name the scan in nothing but their parent.
    """
    rows = _process_table() if table is None else table
    children: dict[int, list[int]] = {}
    command: dict[int, str] = {}
    for pid, ppid, cmd in rows:
        children.setdefault(ppid, []).append(pid)
        command[pid] = cmd

    found: list[tuple[int, str]] = []
    seen: set[int] = set()
    stack = list(children.get(root_pid, ()))
    while stack:
        pid = stack.pop()
        if pid in seen:
            # The table is sampled, not a snapshot, so a recycled pid could
            # otherwise walk in a circle.
            continue
        seen.add(pid)
        stack.extend(children.get(pid, ()))
        if SCANNER_MARKER in command.get(pid, ""):
            found.append((pid, command[pid]))
    return sorted(found)


def leak_report(leaked: list[tuple[int, str]]) -> list[str]:
    """Lines describing ``leaked``, or nothing at all when it is empty.

    The command line is printed in full on purpose: a local scan is configured
    through files under the test's own ``tmp_path``, so the path in it names
    the test that started the scan — which is the one thing a session-end check
    otherwise cannot tell you.
    """
    if not leaked:
        return []
    lines = [
        f"{len(leaked)} scanner process(es) outlived the session that started them. "
        f"A test started a scan that nothing stopped; see the {SCANNER_MARKER} "
        "registry in api/services/jobs.py and the _stop_local_scans fixture in "
        "tests/conftest.py."
    ]
    lines.extend(f"  pid {pid}: {cmd}" for pid, cmd in leaked)
    return lines


_leaked: list[tuple[int, str]] = []
_sampled = False


def reset_for_tests() -> None:
    """Drop the recorded session state (tests/test_ci_checks.py)."""
    global _sampled
    _leaked.clear()
    _sampled = False


def _sample() -> list[tuple[int, str]]:
    """The session's leak, read once however the two hooks end up ordered.

    Which of them runs first is not ours to decide: conftest hook
    implementations are called before the terminal reporter's, so
    ``pytest_sessionfinish`` may well reach the decision before the summary is
    printed. Both call this, and the first one to arrive takes the sample.
    """
    global _sampled
    if not _sampled:
        _leaked[:] = scanner_descendants(os.getpid())
        _sampled = True
    return _leaked


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ARG001
    problems = leak_report(_sample())
    if _source is None:
        # Said out loud rather than passed over. A check that quietly skips
        # wherever its tooling is missing proves nothing while looking exactly
        # like a check that passed -- which is how this gate spent two CI runs
        # reading an empty table in a container with no ``ps``.
        terminalreporter.section("scanner processes")
        terminalreporter.write_line(
            "could not read the process table (no /proc, no ps): this run says "
            "nothing about scans left running",
            yellow=True,
        )
        return
    if not problems:
        return
    terminalreporter.section("scanner processes")
    for line in problems:
        terminalreporter.write_line(f"FAILED {line}", red=True)


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001 - pytest hook signature
    if not _sample():
        return
    # Only ever upgrades green to red, like the integration gate: a run already
    # failing for its own reasons keeps the status that names the real cause.
    if session.exitstatus == 0:
        session.exitstatus = 1
