"""S5 port heuristics: historical ∪ top-N (never silent 1–1024)."""

from __future__ import annotations

from pathlib import Path

from scanner.pipeline.port_heuristics import (
    apply_historical_top_n_union,
    custom_ports_file_is_operator_set,
    historical_tcp_ports,
    tcp_ports_from_open_ports_lines,
    union_historical_and_top_n,
)
from scanner.pipeline.pulse_probe import _default_port_spec, build_pulse_command
from scanner.pipeline.top_tcp_ports import TOP_TCP_100, top_tcp_ports
from scanner.pipeline.utils import write_lines


def test_top_tcp_ports_sizes() -> None:
    assert len(TOP_TCP_100) == 100
    assert len(set(TOP_TCP_100)) == 100
    assert len(top_tcp_ports(1000)) == 1000
    assert 80 in TOP_TCP_100 and 443 in TOP_TCP_100


def test_tcp_ports_from_open_ports_lines_ignores_udp() -> None:
    ports = tcp_ports_from_open_ports_lines(
        [
            "10.0.0.1:443/tcp",
            "10.0.0.1:53/udp",
            "10.0.0.2:22",
            "not-an-endpoint",
        ]
    )
    assert ports == {443, 22}


def test_union_includes_historical_and_top_n() -> None:
    union = union_historical_and_top_n(historical={31337, 80}, top_n=100, exclude={80})
    assert 31337 in union
    assert 80 not in union
    assert 443 in union
    assert len(union) >= 100


def test_apply_historical_top_n_union_writes_file(tmp_path: Path) -> None:
    prev = tmp_path / "prev"
    prev.mkdir()
    write_lines(prev / "open_ports.txt", ["10.0.0.1:8443/tcp", "10.0.0.2:2222/tcp"])
    stub = tmp_path / "ports.txt"
    stub.write_text("# use profile top-ports\n", encoding="utf-8")
    out = tmp_path / "run"
    out.mkdir()
    result = apply_historical_top_n_union(
        output_dir=out,
        previous_run_dir=prev,
        top_n=100,
        exclude_ports=[],
        existing_custom_ports_file=stub,
    )
    assert result is not None
    text = result.read_text(encoding="utf-8")
    assert "8443" in text and "2222" in text and "443" in text
    assert (out / "ports" / "port_heuristic_union.json").is_file()


def test_apply_skips_without_history(tmp_path: Path) -> None:
    stub = tmp_path / "ports.txt"
    stub.write_text("# use profile top-ports\n", encoding="utf-8")
    assert (
        apply_historical_top_n_union(
            output_dir=tmp_path / "run",
            previous_run_dir=None,
            top_n=100,
            exclude_ports=None,
            existing_custom_ports_file=stub,
        )
        is None
    )


def test_operator_custom_ports_win(tmp_path: Path) -> None:
    custom = tmp_path / "custom.txt"
    custom.write_text("9000,7443\n", encoding="utf-8")
    assert custom_ports_file_is_operator_set(custom) is True
    prev = tmp_path / "prev"
    prev.mkdir()
    write_lines(prev / "open_ports.txt", ["10.0.0.1:443/tcp"])
    assert (
        apply_historical_top_n_union(
            output_dir=tmp_path / "run",
            previous_run_dir=prev,
            top_n=100,
            exclude_ports=[],
            existing_custom_ports_file=custom,
        )
        is None
    )


def test_historical_tcp_ports_reads_previous(tmp_path: Path) -> None:
    prev = tmp_path / "prev"
    prev.mkdir()
    write_lines(prev / "open_ports.txt", ["1.2.3.4:8080/tcp"])
    assert historical_tcp_ports(prev) == {8080}
    assert historical_tcp_ports(None) == set()


def test_pulse_default_port_spec_is_not_1_1024() -> None:
    spec = _default_port_spec()
    assert "1-1024" not in spec
    assert "80" in spec and "443" in spec
    cmd = build_pulse_command(
        bin_path="pulse",
        hosts_file=Path("/tmp/hosts"),
        ports=[],
        concurrency=10,
        rate=100,
        adaptive=False,
        host_parallel=0,
        timeout_ms=300,
        banner=False,
        os_detect=False,
        cve=False,
        cve_online=False,
        syn=False,
        checkpoint=None,
        max_hosts=10,
        jarm=False,
    )
    assert cmd[cmd.index("-p") + 1] == spec
    assert "--jarm" not in cmd
    assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "300"
