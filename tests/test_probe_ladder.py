from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from scanner.pipeline.config_schema import (
    DiscoveryConfig,
    IcmpDiscoveryConfig,
    TcpProbeDiscoveryConfig,
)
from scanner.pipeline.discover import host_discovery
from scanner.pipeline.icmp_discover import icmp_ping_filter, parse_fping_output
from scanner.pipeline.probe_ladder import (
    merge_discovery_stats,
    parse_naabu_host_lines,
    run_probe_ladder,
)


def test_parse_fping_output_a_flag_ips():
    stdout = "10.0.0.1\n10.0.0.5\n"
    assert parse_fping_output(stdout) == ["10.0.0.1", "10.0.0.5"]


def test_parse_naabu_host_lines_host_port():
    assert parse_naabu_host_lines("10.0.0.1:80\n10.0.0.2:443\n") == ["10.0.0.1", "10.0.0.2"]


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
