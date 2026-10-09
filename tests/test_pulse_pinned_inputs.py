"""Pulse runs on inputs we ship, not on whatever the host has (#543, ADR 0002)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.pipeline import pulse_probe as pp
from scanner.pipeline.config_schema import ProfilePulseConfig, PulseProbeConfig

_ONE_SERVICE = '{"open": [{"ip": "10.0.0.1", "port": 22, "service": "ssh"}]}'


class _Completed:
    def __init__(self, stdout: str):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = 0


def _command(**overrides):
    args = dict(
        bin_path="pulse",
        hosts_file=Path("/tmp/hosts.txt"),
        ports=[22],
        concurrency=10,
        rate=0,
        adaptive=False,
        host_parallel=0,
        timeout_ms=800,
        banner=True,
        os_detect=True,
        cve=False,
        cve_online=False,
        syn=False,
        checkpoint=None,
        max_hosts=10,
    )
    args.update(overrides)
    return pp.build_pulse_command(**args)


def _flag_value(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_command_passes_our_services_table():
    cmd = _command()
    assert Path(_flag_value(cmd, "--services-db")) == pp.SERVICES_DB
    assert pp.SERVICES_DB.is_file()


def test_command_forces_sinfp_with_os():
    assert _flag_value(_command(), "--os-mode") == "sinfp"
    assert "--os-mode" not in _command(os_detect=False)


@pytest.mark.parametrize("mode", ["nmap", "auto"])
def test_command_refuses_nmap_os_engines(mode):
    with pytest.raises(ValueError, match="sinfp"):
        _command(os_mode=mode)


def test_missing_table_degrades_to_empty_file_not_host_nmap(monkeypatch, tmp_path):
    monkeypatch.setattr(pp, "SERVICES_DB", tmp_path / "gone.tsv")
    assert _flag_value(_command(), "--services-db") == "/dev/null"


def test_services_table_is_iana_not_nmap():
    text = pp.SERVICES_DB.read_text(encoding="utf-8")
    assert "IANA" in text.splitlines()[0]
    # Nmap's spelling for port 2222; IANA's is ethernet-ip-1.
    assert "EtherNetIP-1" not in text
    assert "ethernet-ip-1\t2222/tcp" in text


def test_pulse_process_gets_private_empty_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", "/Users/operator")
    monkeypatch.setenv("PULSE_SERVICES_DB", "/opt/homebrew/share/nmap/nmap-services")
    seen: list[tuple[list[str], dict[str, str], list[Path]]] = []

    def fake_run_command(command, **kwargs):
        env = kwargs["env"]
        # Snapshot at spawn time: nothing of the operator's ~/.pulse is visible.
        seen.append((command, env, list(Path(env["HOME"]).iterdir())))
        return _Completed(_ONE_SERVICE)

    monkeypatch.setattr(pp, "run_command", fake_run_command)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)

    pp.run_pulse_probe(["10.0.0.1:22/tcp"], output_dir=tmp_path)

    assert seen
    for command, env, home_entries in seen:
        assert env["HOME"] != "/Users/operator"
        assert home_entries == []
        assert "PULSE_SERVICES_DB" not in env
        assert Path(_flag_value(command, "--services-db")) == pp.SERVICES_DB
        assert _flag_value(command, "--os-mode") == "sinfp"
        # The private HOME is removed once the process is done.
        assert not Path(env["HOME"]).exists()


@pytest.mark.parametrize("mode", ["nmap", "auto"])
def test_config_rejects_nmap_os_modes(mode):
    with pytest.raises(ValidationError, match="replace it with 'sinfp'"):
        PulseProbeConfig(os_mode=mode)
    with pytest.raises(ValidationError, match="replace it with 'sinfp'"):
        ProfilePulseConfig(os_mode=mode)


def test_config_default_is_sinfp():
    assert PulseProbeConfig().os_mode == "sinfp"
    assert ProfilePulseConfig().os_mode is None


_LEAKY = (
    "SHODAN_API_KEY",
    "CENSYS_API_KEY",
    "PULSE_API_TOKEN",
    "PULSE_ALERT_SLACK",
    "PULSE_NVD_API_KEY",
    "PULSE_OS_DB",
    "PULSE_SERVICES_DB",
    "OCTO_SECRET_THING",
    "AWS_SECRET_ACCESS_KEY",
)


def test_pulse_env_is_an_allowlist(monkeypatch, tmp_path):
    """Pulse reads SHODAN_API_KEY/CENSYS_API_KEY itself and would send every target out."""
    for name in _LEAKY:
        monkeypatch.setenv(name, "leak")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("NVD_API_KEY", "nvd-key")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:3128")
    monkeypatch.setenv("no_proxy", "localhost")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    monkeypatch.setenv("SSL_CERT_FILE", "/etc/ssl/ca.pem")

    env = pp.pulse_env(tmp_path)

    assert env["HOME"] == str(tmp_path)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["NVD_API_KEY"] == "nvd-key"
    assert env["HTTPS_PROXY"] == "http://proxy:3128"
    assert env["no_proxy"] == "localhost"
    assert env["LC_ALL"] == "C.UTF-8"
    assert env["SSL_CERT_FILE"] == "/etc/ssl/ca.pem"
    assert set(_LEAKY).isdisjoint(env)


def test_services_table_is_outside_the_enrichment_volume():
    """scanner/data is shadowed by the enrichment PVC; the table must live elsewhere."""
    data_dir = Path(pp.__file__).resolve().parents[1] / "data"
    assert data_dir not in pp.SERVICES_DB.parents
