from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pipeline.config_schema import ValidationError, load_config
from scanner.pipeline.ports import _flatten_custom_ports, _naabu_entries


@pytest.fixture(autouse=True)
def _forget_syn_state():
    """The SYN decision is memoised per process, so tests must not inherit it."""
    from scanner.pipeline import ports as ports_mod

    ports_mod._reset_syn_state()
    yield
    ports_mod._reset_syn_state()


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


def _capture_naabu(monkeypatch, *, fail_syn: bool = False, syn_out: str = "", connect_out: str = ""):
    """Stub run_command, returning the list that collects each invocation.

    ``syn_out``/``connect_out`` are the stdout each technique reports, so a test
    can express "SYN saw nothing but CONNECT saw ports" — the silent failure
    mode that an exit code cannot express.
    """
    from scanner.pipeline import ports as ports_mod

    captured: list[list[str]] = []

    class _Result:
        def __init__(self, stdout: str):
            self.stdout = stdout

    def fake_run_command(command, **kwargs):
        captured.append(command)
        technique = command[command.index("-s") + 1] if "-s" in command else None
        if technique == "s":
            if fail_syn:
                raise RuntimeError("naabu: could not raise CAP_NET_RAW")
            return _Result(syn_out)
        return _Result(connect_out)

    monkeypatch.setattr(ports_mod, "run_command", fake_run_command)
    ports_mod._reset_syn_state()
    return captured


def _techniques(captured: list[list[str]]) -> list[str]:
    return [c[c.index("-s") + 1] for c in captured if "-s" in c]


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

    assert _techniques(captured) == ["s", "c"]


def test_empty_syn_is_cross_checked_against_connect(tmp_path, monkeypatch):
    """SYN can exit 0 having seen nothing, which an exit code cannot reveal.

    The CI image does exactly this: `-s s` succeeds and returns no ports for a
    host with an open one, so trusting the exit status alone reports a clean
    scan of a host that is not clean.
    """
    captured = _capture_naabu(monkeypatch, syn_out="", connect_out="10.0.0.1:80\n")
    entries = _scan(tmp_path)

    assert _techniques(captured) == ["s", "c"]
    assert entries == ["10.0.0.1:80/tcp"], "the CONNECT result must win"


def test_syn_is_trusted_when_connect_agrees_it_is_empty(tmp_path, monkeypatch):
    """Both empty means the ports really are closed, not that SYN is broken."""
    captured = _capture_naabu(monkeypatch, syn_out="", connect_out="")
    _scan(tmp_path, tag="first")
    captured.clear()
    _scan(tmp_path, tag="second")

    assert _techniques(captured) == ["s"], "later batches must not re-run the cross-check"


def test_syn_failure_is_not_retried_on_later_batches(tmp_path, monkeypatch):
    """The decision is per run, not per batch -- one probe of SYN is enough."""
    captured = _capture_naabu(monkeypatch, fail_syn=True)
    _scan(tmp_path, tag="first")
    captured.clear()
    _scan(tmp_path, tag="second")

    assert _techniques(captured) == ["c"]


def test_silent_syn_failure_switches_later_batches_to_connect(tmp_path, monkeypatch):
    captured = _capture_naabu(monkeypatch, syn_out="", connect_out="10.0.0.1:80\n")
    _scan(tmp_path, tag="first")
    captured.clear()
    _scan(tmp_path, tag="second")

    assert _techniques(captured) == ["c"]


def test_working_syn_is_not_cross_checked(tmp_path, monkeypatch):
    """A SYN batch that finds ports proves itself; no CONNECT probe is owed."""
    captured = _capture_naabu(monkeypatch, syn_out="10.0.0.1:80\n")
    _scan(tmp_path)

    assert _techniques(captured) == ["s"]


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


def _config_with_top_ports(value: object) -> dict:
    """Minimal valid config whose `safe` profile carries the value under test."""
    return {
        "runtime": {"mode": "balanced"},
        "profiles": {
            "safe": {
                "discover_rate": 1000,
                "port_rate": 1000,
                "top_ports": value,
                "nse_profile": "baseline",
            },
            "balanced": {
                "discover_rate": 3000,
                "port_rate": 3000,
                "top_ports": 1000,
                "nse_profile": "baseline",
            },
            "fast": {
                "discover_rate": 7000,
                "port_rate": 7000,
                "top_ports": 1000,
                "nse_profile": "baseline",
            },
        },
        "nse_profiles": {"baseline": {"scripts": "default,safe"}},
    }


@pytest.mark.parametrize("value", [100, 1000])
def test_config_accepts_the_top_ports_naabu_understands(value: int):
    cfg = load_config(_config_with_top_ports(value))
    assert cfg.profiles["safe"].top_ports == value


@pytest.mark.parametrize("value", [1, 200, 500, 65535])
def test_config_rejects_top_ports_naabu_cannot_parse(value: int):
    """-top-ports names a port set, it is not a count.

    naabu takes only 100 or 1000 (or `full`, which this field does not offer),
    and aborts the whole batch with "could not parse ports: invalid top ports
    option" on anything else. That must fail at config-validation time: a
    profile carrying e.g. 500 used to validate cleanly and then blow up on
    every port batch of every run.
    """
    with pytest.raises(ValidationError) as excinfo:
        load_config(_config_with_top_ports(value))
    assert "profiles.safe.top_ports" in str(
        [".".join(str(p) for p in err["loc"]) for err in excinfo.value.errors()]
    )
    # The message has to name the accepted set, not just say "invalid".
    assert "100" in str(excinfo.value) and "1000" in str(excinfo.value)


def test_top_ports_reaches_naabu_verbatim(tmp_path, monkeypatch):
    """The profile value is passed through as the -top-ports argument as-is,
    which is why the config, not the port stage, has to constrain it."""
    from scanner.pipeline import ports as ports_mod

    captured: list[list[str]] = []

    class _Result:
        stdout = ""

    monkeypatch.setattr(
        ports_mod,
        "run_command",
        lambda command, **kwargs: (captured.append(command), _Result())[1],
    )
    ports_mod.fast_port_scan(
        alive_hosts=["10.0.0.1"],
        output_dir=tmp_path,
        rate=1000,
        top_ports=1000,
        top_udp_ports=100,
        timeout=60,
        retries=1,
        protocol_mode="tcp",
        custom_ports_file=tmp_path / "absent.txt",
        custom_udp_ports_file=tmp_path / "absent-udp.txt",
        udp_probes=False,
    )

    assert captured, "naabu was never invoked"
    command = captured[0]
    assert command[command.index("-top-ports") + 1] == "1000"
