"""Pulse runs on inputs we ship, not on whatever the host has (#543, ADR 0002)."""

from __future__ import annotations

import json
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


def test_run_records_which_services_table_it_used(tmp_path, monkeypatch, caplog):
    # A sensor that lost the table must say so in the run, once, not per chunk.
    monkeypatch.setattr(pp, "SERVICES_DB", tmp_path / "gone.tsv")
    seen: list[list[str]] = []

    def fake_run_command(command, **kwargs):
        seen.append(command)
        return _Completed(_ONE_SERVICE)

    monkeypatch.setattr(pp, "run_command", fake_run_command)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "pulse")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)

    out = tmp_path / "out"
    pp.run_pulse_probe(["10.0.0.1:22/tcp", "10.0.0.2:22/tcp"], output_dir=out, chunk_hosts=1)

    assert len(seen) == 2
    assert all(_flag_value(c, "--services-db") == "/dev/null" for c in seen)
    raw = json.loads((out / "pulse" / "raw.json").read_text(encoding="utf-8"))
    assert raw["adapter"]["services_db"] == "/dev/null"
    assert caplog.text.count("falls back to its embedded port table") == 1


def test_config_rejects_nmap_os_mode():
    with pytest.raises(ValidationError, match="replace it with 'sinfp'"):
        PulseProbeConfig(os_mode="nmap")
    with pytest.raises(ValidationError, match="replace it with 'sinfp'"):
        ProfilePulseConfig(os_mode="nmap")


def test_config_maps_the_old_auto_default_to_sinfp(caplog):
    # ``auto`` was the shipped default: configs copied from an older release
    # must keep loading after the upgrade, not stop every scan.
    assert PulseProbeConfig(os_mode="auto").os_mode == "sinfp"
    assert ProfilePulseConfig(os_mode="auto").os_mode == "sinfp"
    assert "deprecated" in caplog.text


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


# Spelled out, not derived from pp._ENV_ALLOW: trimming the list must go red.
_EXPECTED_ALLOWED = (
    "PATH", "LANG", "LANGUAGE", "TZ", "TMPDIR", "NVD_API_KEY", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
)  # fmt: skip


@pytest.mark.parametrize("name", _EXPECTED_ALLOWED)
def test_every_allowed_variable_reaches_pulse(name, monkeypatch, tmp_path):
    monkeypatch.setenv(name, "value-for-" + name)
    assert pp.pulse_env(tmp_path)[name] == "value-for-" + name


def test_services_table_is_outside_the_enrichment_volume():
    """scanner/data is shadowed by the enrichment PVC; the table must live elsewhere."""
    data_dir = Path(pp.__file__).resolve().parents[1] / "data"
    assert data_dir not in pp.SERVICES_DB.parents
