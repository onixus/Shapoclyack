"""The verification run's connect probe tells refused from dropped (#451).

naabu prints open ports only, so a port a firewall drops and a port that
answers with a RST are the same absence in its output. The closure as
``endpoint_unreachable`` rests on this probe's ``refused`` instead.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from scanner.pipeline import reachability
from scanner.pipeline.config_schema import ReachabilityConfig
from scanner.pipeline.scan_policy import SECONDARY_ACTIVE_STAGE_POLICIES


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_a_listening_port_is_open_and_a_closed_one_refused(tmp_path: Path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    open_port = listener.getsockname()[1]
    closed_port = _free_port()
    try:
        result = reachability.run_reachability_probe(
            ["127.0.0.1"], {open_port, closed_port}, ReachabilityConfig(enabled=True, timeout_seconds=1), tmp_path
        )
    finally:
        listener.close()
    by_port = {probe["port"]: probe for probe in result["probes"]}
    assert by_port[open_port]["result"] == "open"
    assert by_port[closed_port] == {
        "host": "127.0.0.1",
        "port": closed_port,
        "result": "refused",
        "attempts": ["refused", "refused"],
    }
    assert json.loads((tmp_path / "reachability.json").read_text(encoding="utf-8")) == result


@pytest.mark.parametrize(
    ("attempts", "verdict"),
    [
        (["refused", "refused"], "refused"),
        (["refused", "timeout"], "timeout"),  # one answer lost: no proof
        (["timeout", "refused"], "timeout"),
        (["refused", "open"], "open"),
        (["unreachable", "unreachable"], "unreachable"),
        ([], "error"),
    ],
)
def test_only_refusal_on_every_attempt_is_refused(attempts, verdict):
    assert reachability._verdict(attempts) == verdict


def test_excluded_ports_are_not_touched_and_the_count_is_bounded(tmp_path: Path, monkeypatch):
    seen: list[tuple[str, int]] = []

    def attempt(host, port, timeout):
        seen.append((host, port))
        return "refused"

    monkeypatch.setattr(reachability, "_attempt", attempt)
    result = reachability.run_reachability_probe(
        ["10.0.0.1", "10.0.0.2"],
        {22, 443, 9100},
        ReachabilityConfig(enabled=True, attempts=1, max_probes=3),
        tmp_path,
        exclude_ports=[9100],
    )
    assert result["truncated"] is True
    assert len(result["probes"]) == 3
    assert all(port != 9100 for _host, port in seen)


def test_off_unless_a_verification_turns_it_on(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(reachability, "_attempt", lambda *a: pytest.fail("probed while disabled"))
    result = reachability.run_reachability_probe(["10.0.0.1"], {443}, ReachabilityConfig(), tmp_path)
    assert result["enabled"] is False and result["probes"] == []


def test_the_tenant_scan_policy_governs_it():
    assert SECONDARY_ACTIVE_STAGE_POLICIES["reachability"] == ("concurrency", "enabled")
