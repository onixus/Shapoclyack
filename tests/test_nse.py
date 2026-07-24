from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.pipeline.nse import (
    _build_nmap_command,
    _chunk_host_ports,
    _group_output_basename,
    _group_ports_by_host,
    _per_process_rate,
    _scan_host_group,
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


def test_build_nmap_command_tcp_as_root():
    with patch("scanner.pipeline.nse._running_as_root", return_value=True):
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
    assert "--osscan-guess" in cmd
    assert cmd[cmd.index("--max-rate") + 1] == "500"
    assert cmd[cmd.index("-p") + 1] == "80,443"


def test_build_nmap_command_tcp_non_root_skips_os_detection():
    """nmap hard-requires euid 0 for -O and refuses to run the WHOLE command
    (not just OS detection) when unprivileged -- the all-in-one image runs
    as a non-root user by design (Dockerfile.allinone), so -O/--osscan-guess
    must be dropped here rather than silently losing -sV and every NSE
    script along with it."""
    with patch("scanner.pipeline.nse._running_as_root", return_value=False):
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
    assert "-O" not in cmd
    assert "--osscan-guess" not in cmd
    assert "-sV" in cmd


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


def test_scan_host_group_logs_warning_on_nonzero_exit(caplog, tmp_path: Path):
    """A failed nmap invocation (e.g. the root-required-for-OS-detection case)
    used to vanish silently (capture_output=False, check=False) -- the whole
    NSE stage would produce zero findings with no trace anywhere. It must now
    be captured and logged so operators can see why a scan came back empty."""
    fake_result = MagicMock(
        returncode=1,
        stdout="",
        stderr="TCP/IP fingerprinting (for OS scan) requires root privileges.\nQUITTING!\n",
    )
    with patch("scanner.pipeline.nse.run_command", return_value=fake_result) as mock_run:
        with caplog.at_level(logging.WARNING):
            hosts = _scan_host_group(
                {"10.0.0.1": ["80"]},
                tmp_path,
                scripts="default",
                version_detection=True,
                os_detection=False,
                nmap_timing="T4",
                per_process_rate=0,
                timeout=60,
                retries=0,
                scan_protocol="tcp",
            )

    assert hosts == ["10.0.0.1"]
    assert any("nmap exited" in record.message for record in caplog.records)
    _, kwargs = mock_run.call_args
    assert kwargs["capture_output"] is True
