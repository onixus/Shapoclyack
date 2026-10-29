"""Incremental pytest timing evidence, including interrupted sessions."""

import json
import time
from pathlib import Path

import pytest


def pytest_addoption(parser):
    parser.addoption("--ci-timing-jsonl", help="Exclusive-create incremental timing log")


def pytest_configure(config):
    path = config.getoption("--ci-timing-jsonl")
    if path:
        try:
            stream = Path(path).open("x", encoding="utf-8", buffering=1)
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
