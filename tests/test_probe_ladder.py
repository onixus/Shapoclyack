from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanner.pipeline.config_schema import (
    DiscoveryConfig,
    IcmpDiscoveryConfig,
    TcpProbeDiscoveryConfig,
)
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.icmp_discover import icmp_ping_filter, parse_fping_output
from scanner.pipeline.probe_ladder import (
    _reset_host_syn_state,
    merge_discovery_stats,
    parse_naabu_host_lines,
    run_probe_ladder,
)


@pytest.fixture(autouse=True)
def _fresh_host_syn_state():
    _reset_host_syn_state()
    yield
    _reset_host_syn_state()


def test_parse_fping_output_a_flag_ips():
    stdout = "10.0.0.1\n10.0.0.5\n"
    assert parse_fping_output(stdout) == ["10.0.0.1", "10.0.0.5"]


def test_parse_naabu_host_lines_host_port():
    assert parse_naabu_host_lines("10.0.0.1:80\n10.0.0.2:443\n") == ["10.0.0.1", "10.0.0.2"]


def test_parse_naabu_host_lines_keeps_ipv6_intact():
    assert parse_naabu_host_lines(
        "2001:db8::1\n[2001:db8::2]:443/tcp\n"
    ) == ["2001:db8::1", "2001:db8::2"]


def test_run_probe_ladder_icmp_then_tcp_then_naabu(tmp_path: Path, monkeypatch):
    discovery = DiscoveryConfig(
        icmp=IcmpDiscoveryConfig(enabled=True),
        tcp_probe=TcpProbeDiscoveryConfig(enabled=True, ports=[80]),
        probe_order=["icmp", "tcp", "naabu"],
    )
    calls: list[str] = []

    def fake_icmp(targets, output_dir, icmp_cfg, **kwargs):
        calls.append("icmp")
        return ["10.0.0.1"], ["10.0.0.2", "10.0.0.3"]

    def fake_tcp(targets, output_dir, **kwargs):
        calls.append("tcp")
        assert targets == ["10.0.0.2", "10.0.0.3"]
        return ["10.0.0.2"], ["10.0.0.3"]

    def fake_naabu(targets, output_dir, **kwargs):
        calls.append("naabu")
        assert targets == ["10.0.0.3"]
        return ["10.0.0.3"]

    monkeypatch.setattr("scanner.pipeline.probe_ladder.icmp_ping_filter", fake_icmp)
    monkeypatch.setattr("scanner.pipeline.probe_ladder.tcp_port_probe", fake_tcp)
    monkeypatch.setattr("scanner.pipeline.probe_ladder.naabu_host_discovery", fake_naabu)

    alive, stats = run_probe_ladder(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        tmp_path,
        discovery,
        rate=1000,
        timeout=30,
        retries=1,
        tag="batch1",
        scope_members=["10.0.0.0/24"],
    )
    assert alive == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert stats == {"icmp": 1, "tcp": 1, "naabu": 1}
    assert calls == ["icmp", "tcp", "naabu"]
    assert json.loads((tmp_path / "discover" / "batch1.probe_stats.json").read_text(encoding="utf-8")) == stats


def test_run_probe_ladder_naabu_only_when_probes_disabled(tmp_path: Path, monkeypatch):
    discovery = DiscoveryConfig(probe_order=["icmp", "tcp", "naabu"])
    calls: list[str] = []

    def fake_naabu(targets, output_dir, **kwargs):
        calls.append("naabu")
        return ["10.0.0.5"]

    monkeypatch.setattr("scanner.pipeline.probe_ladder.naabu_host_discovery", fake_naabu)

    alive, stats = run_probe_ladder(
        ["10.0.0.5"],
        tmp_path,
        discovery,
        rate=1000,
        timeout=30,
        retries=1,
        tag="b2",
        scope_members=["10.0.0.5"],
    )
    assert alive == ["10.0.0.5"]
    assert stats == {"icmp": 0, "tcp": 0, "naabu": 1}
    assert calls == ["naabu"]


def test_host_discovery_uses_probe_ladder(tmp_path: Path, monkeypatch):
    discovery = DiscoveryConfig(icmp=IcmpDiscoveryConfig(enabled=True))

    def fake_ladder(targets, output_dir, discovery_cfg, **kwargs):
        return ["10.0.0.10"], {"icmp": 1, "tcp": 0, "naabu": 0}

    monkeypatch.setattr("scanner.pipeline.discover.run_probe_ladder", fake_ladder)

    alive = host_discovery(
        ["10.0.0.10"],
        tmp_path,
        rate=1000,
        timeout=30,
        retries=1,
        skip_discovery=False,
        discovery=discovery,
        tag="t1",
    )
    assert alive == ["10.0.0.10"]


def test_merge_discovery_stats(tmp_path: Path):
    discover = tmp_path / "discover"
    discover.mkdir()
    (discover / "a.probe_stats.json").write_text(
        '{"icmp": 2, "tcp": 1, "naabu": 3}',
        encoding="utf-8",
    )
    (discover / "b.probe_stats.json").write_text(
        '{"icmp": 0, "tcp": 2, "naabu": 1}',
        encoding="utf-8",
    )
    merged = merge_discovery_stats(tmp_path)
    assert merged == {"icmp": 2, "tcp": 3, "naabu": 4, "batches": 2}
    assert json.loads((tmp_path / "discovery_stats.json").read_text(encoding="utf-8")) == merged


def test_icmp_ping_filter_splits_alive_and_pending(tmp_path: Path, monkeypatch):
    icmp = IcmpDiscoveryConfig(enabled=True, timeout_ms=300, retries=0)

    def fake_run_command(command, **kwargs):
        result = MagicMock()
        result.stdout = "10.0.0.1\n10.0.0.3\n"
        return result

    monkeypatch.setattr("scanner.pipeline.icmp_discover.run_command", fake_run_command)
    alive, pending = icmp_ping_filter(
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        tmp_path,
        icmp,
        timeout=30,
        retries=1,
        tag="batch1",
    )
    assert alive == ["10.0.0.1", "10.0.0.3"]
    assert pending == ["10.0.0.2"]


def test_icmp_ping_filter_runs_one_explicit_command_per_address_family(
    tmp_path: Path, monkeypatch
):
    icmp = IcmpDiscoveryConfig(enabled=True, timeout_ms=300, retries=0)
    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        result.stdout = "2001:db8::1\n" if "-6" in command else "10.0.0.1\n"
        return result

    monkeypatch.setattr("scanner.pipeline.icmp_discover.run_command", fake_run_command)
    alive, pending = icmp_ping_filter(
        ["10.0.0.1", "10.0.0.2", "2001:db8::1", "2001:db8::2"],
        tmp_path,
        icmp,
        timeout=30,
        retries=0,
        tag="mixed",
    )

    assert alive == ["10.0.0.1", "2001:db8::1"]
    assert pending == ["10.0.0.2", "2001:db8::2"]
    assert len(commands) == 2
    assert any("-4" in command for command in commands)
    assert any("-6" in command for command in commands)


def test_naabu_host_discovery_cross_checks_empty_syn_with_connect(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        result.stdout = (
            "203.0.113.10:80\n203.0.113.11:443\n"
            if "-Pn" in command
            else ""
        )
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10", "203.0.113.11"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=1,
        tag="external",
        scope_members=["203.0.113.0/24"],
    )

    assert alive == ["203.0.113.10", "203.0.113.11"]
    assert len(commands) == 2
    assert "-sn" in commands[0]
    assert all(flag in commands[1] for flag in ["-Pn", "-s", "c", "-p", "80,443"])
    assert (tmp_path / "discover" / "external.naabu.alive.txt").read_text(
        encoding="utf-8"
    ) == "203.0.113.10\n203.0.113.11\n"


def test_naabu_host_discovery_does_not_connect_to_excluded_ports(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        result.stdout = ""
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=1,
        tag="excluded",
        scope_members=["203.0.113.10"],
        exclude_ports=[80, 443],
    )

    assert alive == []
    assert len(commands) == 1
    assert "-sn" in commands[0]


def test_failed_syn_is_not_an_empty_batch_when_connect_finds_nobody(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        if "-Pn" in command:
            result = MagicMock()
            result.stdout = ""
            return result
        raise OSError("naabu: no CAP_NET_RAW")

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    with pytest.raises(OSError, match="CAP_NET_RAW"):
        naabu_host_discovery(
            ["203.0.113.10"],
            tmp_path,
            rate=100,
            timeout=30,
            retries=0,
            tag="failed",
            scope_members=["203.0.113.10"],
        )

    assert any("-Pn" in command for command in commands)
    assert not (tmp_path / "discover" / "failed.naabu.alive.txt").exists()


def test_failed_syn_with_both_probe_ports_excluded_does_not_connect(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        raise OSError("naabu: no CAP_NET_RAW")

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    with pytest.raises(OSError, match="CAP_NET_RAW"):
        naabu_host_discovery(
            ["203.0.113.10"],
            tmp_path,
            rate=100,
            timeout=30,
            retries=0,
            tag="excluded-fail",
            scope_members=["203.0.113.10"],
            exclude_ports=[80, 443],
        )

    assert len(commands) == 1
    assert "-sn" in commands[0]
    assert "-Pn" not in commands[0]


def test_failed_syn_keeps_connect_hosts_and_skips_syn_afterwards(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    calls = {"syn": 0, "connect": 0}

    def fake_run_command(command, **kwargs):
        result = MagicMock()
        if "-Pn" in command:
            calls["connect"] += 1
            result.stdout = "203.0.113.10:80\n"
            return result
        calls["syn"] += 1
        raise OSError("naabu: no CAP_NET_RAW")

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    kwargs = dict(rate=100, timeout=30, retries=0, scope_members=["203.0.113.0/24"])
    first = naabu_host_discovery(["203.0.113.10"], tmp_path, tag="batch-a", **kwargs)
    second = naabu_host_discovery(["203.0.113.11"], tmp_path, tag="batch-b", **kwargs)

    assert first == ["203.0.113.10"]
    assert second == ["203.0.113.10"]
    assert calls == {"syn": 1, "connect": 2}


def test_connect_cross_check_failure_keeps_the_empty_syn_result(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    def fake_run_command(command, **kwargs):
        if "-Pn" in command:
            raise OSError("connect naabu failed")
        result = MagicMock()
        result.stdout = ""
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=0,
        tag="cross-fail",
        scope_members=["203.0.113.10"],
    )

    assert alive == []


def test_agreed_empty_cross_check_trusts_syn_for_later_batches(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    calls = {"syn": 0, "connect": 0}

    def fake_run_command(command, **kwargs):
        result = MagicMock()
        result.stdout = ""
        if "-Pn" in command:
            calls["connect"] += 1
        else:
            calls["syn"] += 1
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    kwargs = dict(rate=100, timeout=30, retries=0, scope_members=["203.0.113.10"])
    assert (
        naabu_host_discovery(["203.0.113.10"], tmp_path, tag="empty-a", **kwargs) == []
    )
    assert (
        naabu_host_discovery(["203.0.113.10"], tmp_path, tag="empty-b", **kwargs) == []
    )
    assert calls == {"syn": 2, "connect": 1}


def _listed_hosts(command: list[str]) -> str:
    return Path(command[command.index("-list") + 1]).read_text(encoding="utf-8")


def test_partial_syn_connects_only_the_hosts_it_missed(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        if "-Pn" in command:
            assert _listed_hosts(command) == "2001:db8::2\n"
            result.stdout = "[2001:db8::2]:443\n"
        else:
            result.stdout = "2001:db8::1\n"
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["2001:db8:0:0:0:0:0:1", "2001:db8::2"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=0,
        tag="partial",
        scope_members=["2001:db8::/32"],
    )

    assert alive == ["2001:db8::1", "2001:db8::2"]
    assert len(commands) == 2
    assert "-sn" in commands[0]
    assert all(flag in commands[1] for flag in ["-Pn", "-s", "c", "-p", "80,443"])


def test_partial_syn_does_not_connect_when_both_probe_ports_are_excluded(
    tmp_path: Path, monkeypatch
):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        result.stdout = "203.0.113.10\n"
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10", "203.0.113.11"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=0,
        tag="partial-excluded",
        scope_members=["203.0.113.0/24"],
        exclude_ports=[80, 443],
    )

    assert alive == ["203.0.113.10"]
    assert len(commands) == 1
    assert "-sn" in commands[0]
    assert "-Pn" not in commands[0]


def test_partial_syn_does_not_connect_a_miss_outside_scope(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    commands: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        commands.append(command)
        result = MagicMock()
        result.stdout = "203.0.113.10\n"
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10", "203.0.113.11"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=0,
        tag="partial-scope",
        scope_members=["203.0.113.10"],
    )

    assert alive == ["203.0.113.10"]
    assert len(commands) == 1


def test_a_trusted_syn_still_connects_hosts_it_misses(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    calls = {"syn": 0, "connect": 0}

    def fake_run_command(command, **kwargs):
        result = MagicMock()
        listed = _listed_hosts(command)
        if "-Pn" in command:
            calls["connect"] += 1
            assert "203.0.113.21" in listed
            assert "203.0.113.20" not in listed
            result.stdout = "203.0.113.21:80\n"
            return result
        calls["syn"] += 1
        result.stdout = (
            "203.0.113.10\n" if "203.0.113.10" in listed else "203.0.113.20\n"
        )
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    kwargs = dict(rate=100, timeout=30, retries=0, scope_members=["203.0.113.0/24"])
    assert naabu_host_discovery(["203.0.113.10"], tmp_path, tag="full", **kwargs) == [
        "203.0.113.10"
    ]
    assert naabu_host_discovery(
        ["203.0.113.20", "203.0.113.21"], tmp_path, tag="partial", **kwargs
    ) == ["203.0.113.20", "203.0.113.21"]
    assert calls == {"syn": 2, "connect": 1}


def test_failed_pending_connect_keeps_the_syn_hosts(tmp_path: Path, monkeypatch):
    from scanner.pipeline.probe_ladder import naabu_host_discovery

    def fake_run_command(command, **kwargs):
        if "-Pn" in command:
            raise OSError("connect naabu failed")
        result = MagicMock()
        result.stdout = "203.0.113.10\n"
        return result

    monkeypatch.setattr("scanner.pipeline.probe_ladder.run_command", fake_run_command)
    alive = naabu_host_discovery(
        ["203.0.113.10", "203.0.113.11"],
        tmp_path,
        rate=100,
        timeout=30,
        retries=0,
        tag="pending-fail",
        scope_members=["203.0.113.0/24"],
    )

    assert alive == ["203.0.113.10"]
