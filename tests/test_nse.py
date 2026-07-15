from __future__ import annotations

from pathlib import Path

from scanner.pipeline.nse import (
    _build_nmap_command,
    _chunk_host_ports,
    _group_output_basename,
    _group_ports_by_host,
    _per_process_rate,
)


def test_group_ports_by_host_groups_and_sorts():
    entries = ["10.0.0.1:443/tcp", "10.0.0.1:80/tcp", "10.0.0.2:22/tcp"]
    grouped = _group_ports_by_host(entries, "tcp")
    assert grouped == {"10.0.0.1": ["80", "443"], "10.0.0.2": ["22"]}


def test_group_ports_by_host_filters_protocol():
    entries = ["10.0.0.1:80/tcp", "10.0.0.1:53/udp"]
    assert _group_ports_by_host(entries, "tcp") == {"10.0.0.1": ["80"]}
    assert _group_ports_by_host(entries, "udp") == {"10.0.0.1": ["53"]}


def test_per_process_rate_splits_budget():
    assert _per_process_rate(2000, 4) == 500
    assert _per_process_rate(0, 4) == 0
    assert _per_process_rate(3, 8) == 1
    assert _per_process_rate(1000, 0) == 1000


def test_build_nmap_command_tcp():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["80", "443"]},
        Path("/tmp/out/10.0.0.1"),
        scripts="default,safe,vuln",
        version_detection=True,
        os_detection=True,
        nmap_timing="T4",
        per_process_rate=500,
        scan_protocol="tcp",
    )
    assert "-sU" not in cmd
    assert "-Pn" in cmd
    assert "-sV" in cmd
    assert "-O" in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "500"
    assert cmd[cmd.index("-p") + 1] == "80,443"


def test_build_nmap_command_udp():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["53"]},
        Path("/tmp/out/udp"),
        scripts="default",
        version_detection=True,
        os_detection=True,
        nmap_timing="T4",
        per_process_rate=0,
        scan_protocol="udp",
    )
    assert "-sU" in cmd
    assert "-sV" in cmd
    assert "-O" not in cmd


def test_build_nmap_command_multi_host():
    cmd = _build_nmap_command(
        {"10.0.0.1": ["80"], "10.0.0.2": ["22", "443"]},
        Path("/tmp/out/group"),
        scripts="default,safe",
        version_detection=False,
        os_detection=False,
        nmap_timing="T3",
        per_process_rate=0,
        scan_protocol="tcp",
    )
    p_idx = cmd.index("-p")
    assert cmd[p_idx + 1] == "22,80,443"
    assert cmd[p_idx + 2 : p_idx + 4] == ["10.0.0.1", "10.0.0.2"]
    assert cmd.count("-p") == 1


def test_build_nmap_command_multi_host_same_port():
    cmd = _build_nmap_command(
        {"10.99.0.2": ["80"], "10.99.0.3": ["80"]},
        Path("/tmp/out/group"),
        scripts="default",
        version_detection=True,
        os_detection=False,
        nmap_timing="T4",
        per_process_rate=0,
        scan_protocol="tcp",
    )
    p_idx = cmd.index("-p")
    assert cmd[p_idx + 1] == "80"
    assert cmd[p_idx + 2 : p_idx + 4] == ["10.99.0.2", "10.99.0.3"]
    assert cmd.count("-p") == 1


def test_chunk_host_ports_groups_hosts():
    host_ports = {
        "10.0.0.1": ["80"],
        "10.0.0.2": ["22"],
        "10.0.0.3": ["443"],
        "10.0.0.4": ["8080"],
    }
    groups = _chunk_host_ports(host_ports, 2)
    assert len(groups) == 2
    assert sum(len(group) for group in groups) == 4


def test_group_output_basename_includes_protocol():
    assert _group_output_basename(["10.0.0.1"], "tcp") == "tcp_10.0.0.1"
    multi = _group_output_basename(["10.0.0.1", "10.0.0.2"], "udp")
    assert multi.startswith("udp_group_")
