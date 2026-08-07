from __future__ import annotations

from pathlib import Path

from scanner.pipeline.ports import _flatten_custom_ports, _naabu_entries


def test_flatten_custom_ports_missing_file(tmp_path: Path):
    assert _flatten_custom_ports(tmp_path / "nope.txt") is None


def test_flatten_custom_ports_only_comments(tmp_path: Path):
    f = tmp_path / "ports.txt"
    f.write_text("# use profile top-ports\n", encoding="utf-8")
    assert _flatten_custom_ports(f) is None


def test_flatten_custom_ports_joins_lines(tmp_path: Path):
    f = tmp_path / "ports.txt"
    f.write_text("22\n80,443\n1-1024\n", encoding="utf-8")
    assert _flatten_custom_ports(f) == ["22", "80", "443", "1-1024"]


def test_flatten_custom_ports_strips_udp_prefix(tmp_path: Path):
    f = tmp_path / "ports_udp.txt"
    f.write_text("u:53\n123\n", encoding="utf-8")
    assert _flatten_custom_ports(f) == ["53", "123"]


def test_naabu_entries_adds_protocol_suffix():
    entries = _naabu_entries("10.0.0.1:80\n10.0.0.2:443\n", "tcp")
    assert entries == ["10.0.0.1:80/tcp", "10.0.0.2:443/tcp"]


def test_naabu_port_scan_skips_redundant_host_discovery(tmp_path, monkeypatch):
    """The port scan must pass -Pn.

    Hosts reaching this stage are already proven alive by discovery. Without
    -Pn naabu repeats that discovery itself, and when its probes are blocked
    (a CONNECT-scan fallback inside a container) it drops every host and
    reports zero open ports without logging an error.
    """
    from scanner.pipeline import ports as ports_mod

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    def fake_run_command(command, **kwargs):
        captured.append(command)
        return _Result()

    monkeypatch.setattr(ports_mod, "run_command", fake_run_command)
    ports_mod._run_naabu(
        alive_hosts=["10.0.0.1"],
        batch_dir=tmp_path,
        tag="t",
        rate=1000,
        timeout=60,
        retries=1,
        port_args=["-top-ports", "1000"],
        protocol="tcp",
        udp_probes=False,
    )

    assert captured, "naabu was never invoked"
    assert "-Pn" in captured[0]
