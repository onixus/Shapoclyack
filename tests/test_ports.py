from __future__ import annotations

from pathlib import Path

import pytest

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


def _capture_naabu(monkeypatch, *, fail_syn: bool = False):
    """Stub run_command, returning the list that collects each invocation."""
    from scanner.pipeline import ports as ports_mod

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    def fake_run_command(command, **kwargs):
        captured.append(command)
        if fail_syn and "s" in command and command[command.index("s") - 1] == "-s":
            raise RuntimeError("naabu: could not raise CAP_NET_RAW")
        return _Result()

    monkeypatch.setattr(ports_mod, "run_command", fake_run_command)
    monkeypatch.setattr(ports_mod, "_syn_unavailable", False)
    return captured


def _scan(tmp_path, **overrides):
    from scanner.pipeline import ports as ports_mod

    kwargs = {
        "alive_hosts": ["10.0.0.1"],
        "batch_dir": tmp_path,
        "tag": "t",
        "rate": 1000,
        "timeout": 60,
        "retries": 1,
        "port_args": ["-top-ports", "1000"],
        "protocol": "tcp",
        "udp_probes": False,
    }
    kwargs.update(overrides)
    return ports_mod._run_naabu(**kwargs)


def test_tcp_scan_asks_for_syn_by_default(tmp_path, monkeypatch):
    """naabu's own -s default is CONNECT, so SYN must be requested explicitly.

    Without this the CAP_NET_RAW granted by setcap in the images and by
    capabilities.add in the manifests is never used.
    """
    captured = _capture_naabu(monkeypatch)
    _scan(tmp_path)

    assert captured[0][captured[0].index("-s") + 1] == "s"


def test_tcp_scan_falls_back_to_connect_when_syn_fails(tmp_path, monkeypatch):
    captured = _capture_naabu(monkeypatch, fail_syn=True)
    _scan(tmp_path)

    assert len(captured) == 2, "expected a CONNECT retry after the SYN attempt"
    assert captured[1][captured[1].index("-s") + 1] == "c"


def test_syn_failure_is_not_retried_on_later_batches(tmp_path, monkeypatch):
    """The fallback is per run, not per batch -- one probe of SYN is enough."""
    captured = _capture_naabu(monkeypatch, fail_syn=True)
    _scan(tmp_path, tag="first")
    captured.clear()
    _scan(tmp_path, tag="second")

    assert len(captured) == 1
    assert captured[0][captured[0].index("-s") + 1] == "c"


def test_explicit_connect_never_attempts_syn(tmp_path, monkeypatch):
    captured = _capture_naabu(monkeypatch)
    _scan(tmp_path, scan_type="connect")

    assert len(captured) == 1
    assert captured[0][captured[0].index("-s") + 1] == "c"


def test_explicit_syn_does_not_fall_back(tmp_path, monkeypatch):
    captured = _capture_naabu(monkeypatch, fail_syn=True)
    with pytest.raises(RuntimeError):
        _scan(tmp_path, scan_type="syn")

    assert len(captured) == 1


def test_udp_batch_omits_scan_type(tmp_path, monkeypatch):
    """-s selects the TCP technique; passing it on a UDP batch is meaningless."""
    captured = _capture_naabu(monkeypatch)
    _scan(tmp_path, protocol="udp", port_args=["-p", "u:53"], udp_probes=True)

    assert "-s" not in captured[0]
