"""Incremental pytest timing evidence, including interrupted sessions."""

import json
import time
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--ci-timing-jsonl", help="Exclusive-create incremental timing log")


def _open_exclusive(path):
    """Create the log, or the first free ``<stem>.<n><suffix>`` next to it.

    Evidence from an earlier run in the same workspace is never truncated,
    and a rerun is never refused for it.
    """
    path = Path(path)
    for attempt in range(1000):
        candidate = path if not attempt else path.with_name(f"{path.stem}.{attempt}{path.suffix}")
        try:
            return candidate.open("x", encoding="utf-8", buffering=1)
        except FileExistsError:
            continue
    raise FileExistsError(path)


def pytest_configure(config):
    path = config.getoption("--ci-timing-jsonl")
    # Under pytest-xdist each worker loads plugins too; the controller sees
    # every report, so only it writes.
    if path and not hasattr(config, "workerinput"):
        try:
            stream = _open_exclusive(path)
        except OSError as exc:
            raise pytest.UsageError(f"Cannot create timing evidence: {exc}") from exc
        config.pluginmanager.register(TimingLog(stream), "ci-timing-writer")


class TimingLog:
    def __init__(self, stream):
        self.stream = stream

    def write(self, **fields):
        self.stream.write(json.dumps({"at": time.time(), **fields}) + "\n")
        self.stream.flush()

    def pytest_sessionstart(self, session):
        self.write(event="session_start")

    def pytest_runtest_logstart(self, nodeid, location):
        self.write(event="test_start", nodeid=nodeid)

    def pytest_runtest_logreport(self, report):
        self.write(event="phase", nodeid=report.nodeid, phase=report.when,
                   duration=report.duration, outcome=report.outcome)

    def pytest_sessionfinish(self, session, exitstatus):
        self.write(event="session_finish", exitstatus=int(exitstatus))

    def pytest_unconfigure(self, config):
        self.stream.close()
