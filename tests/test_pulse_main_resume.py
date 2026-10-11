"""Exercise real scanner.main resume orchestration, with all network work mocked."""
from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.pulse_progress import completion_manifest
from scanner.pipeline.utils import save_json, write_lines


HOSTS = ["192.0.2.1", "192.0.2.2"]
ENDPOINTS = [f"{host}:443/tcp" for host in HOSTS]
STAGES = (
    "cloudflare", "ct", "asn", "ownership", "cloud", "resolve", "domain_monitor",
    "dns_hygiene", "mail_posture", "discover-l2", "discover", "discover-hostnames",
    "ports", "pulse", "nse", "tls_posture", "fingerprint", "screenshots", "nuclei",
    "related_domains", "credential_leaks", "controls",
)


def _payload(hosts, *, receipts=True):
    result = {"open": [{"ip": h, "port": 443, "protocol": "tcp"} for h in hosts]}
    if receipts:
        result["completion"] = completion_manifest({h: [443] for h in hosts})
    return result


@pytest.fixture
def cli(tmp_path, monkeypatch):
    from scanner import main as sm
    from scanner.pipeline import pulse_probe as pp
    from scanner.pipeline.config_schema import load_config

    output, state, logs = (tmp_path / name for name in ("output", "state", "logs"))
    for path in (output, state, logs):
        path.mkdir()
    config = load_config({
        "runtime": {"mode": "safe", "output_dir": str(output), "state_dir": str(state)},
        "ports": {"custom_ports_file": str(tmp_path / "absent-ports.txt")},
        "profiles": {name: {"discover_rate": 10, "port_rate": 10, "top_ports": 100}
                     for name in ("safe", "balanced", "fast")},
        # Plugins have their own tests below; here subprocess.run is forbidden and
        # `pulse plugin check` is one.
        "service_probe": {"backend": "pulse", "pulse": {"retry_settle_seconds": 0, "plugins": False}},
        "reporting": {"pdf_summary": False},
        "alerts": {"enabled": False}, "defectdojo": {"enabled": False},
    })
    paths = SimpleNamespace(output_dir=output, state_dir=state, logs_dir=logs, run_id="fixture")
    monkeypatch.setattr(sm, "_config_for_run", lambda args: (config, "safe", "custom"))
    monkeypatch.setattr(sm, "resolve_run_paths", lambda *args, **kwargs: paths)
    monkeypatch.setattr(sm, "setup_logging", lambda *args, **kwargs: None)
    monkeypatch.setattr(sm, "build_reports", lambda **kwargs: None)
    monkeypatch.setattr(sm, "verify_alive_without_ports", lambda **kwargs: kwargs["alive_hosts"])
    monkeypatch.setattr(sm, "load_seed_alive", lambda _: [])
    monkeypatch.setattr(sm, "load_previous_alive", lambda _: [])

    def forbidden(*args, **kwargs):
        pytest.fail("test attempted an unmocked network stage or subprocess")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    for name in (
        "import_cloudflare_dns_targets", "discover_ct_subdomains_sync", "discover_asn_ranges",
        "resolve_ownership", "discover_cloud_buckets_sync", "resolve_fqdns", "monitor_domains",
        "check_dns_hygiene", "check_mail_posture", "run_l2_discovery", "run_discovery_stage",
        "enrich_discovery_hostnames", "fast_port_scan", "check_tls_posture",
        "fingerprint_hosts_sync", "capture_screenshots_sync", "run_nuclei_scan",
        "discover_related_domains", "check_credential_leaks", "send_alerts", "export_to_defectdojo",
    ):
        monkeypatch.setattr(sm, name, forbidden)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    calls = []
    commands = []
    outcome = {"code": 0}

    def probe(command, **kwargs):
        hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
        ports = [int(p) for p in command[command.index("-p") + 1].split(",")]
        disk = CheckpointStore(state / "checkpoint.json")
        assert not disk.is_done("pulse"), "stale coarse completion survived until replay"
        assert not set(hosts) & disk.done_items("pulse"), "unverified host was not invalidated"
        calls.extend((host, port) for host in hosts for port in ports)
        commands.append(command)
        body = {"open": [{"ip": host, "port": port} for host in hosts for port in ports]}
        return subprocess.CompletedProcess(command, outcome["code"], json.dumps(body), "")
    monkeypatch.setattr(pp, "run_command", probe)

    checkpoint_path = state / "checkpoint.json"
    save_json(checkpoint_path, {"stages": dict.fromkeys(STAGES, True),
                               "items": {"pulse": HOSTS, "nse": ["unrelated-item"]}})
    ranges, domains = tmp_path / "ranges.txt", tmp_path / "domains.txt"
    write_lines(ranges, HOSTS)
    write_lines(domains, [])
    write_lines(output / "open_ports.txt", ENDPOINTS)
    write_lines(output / "alive_ips.txt", HOSTS)
    monkeypatch.setattr(sys, "argv", ["scanner.main", "--resume", "--run-id", "fixture",
                                       "--ranges", str(ranges), "--domains", str(domains)])
    monkeypatch.setenv("OCTO_SERVICE_BACKEND", "pulse")
    monkeypatch.delenv("OCTO_PULSE_SHADOW", raising=False)
    return SimpleNamespace(main=sm.main, output=output, checkpoint=checkpoint_path,
                           calls=calls, outcome=outcome, config=config, commands=commands, sm=sm)


@pytest.mark.parametrize("cache_kind", ["missing", "corrupt", "legacy", "partial", "complete"])
def test_coarse_done_does_not_bypass_artifact_validation(cli, cache_kind):
    raw_path = cli.output / "pulse/raw.json"
    if cache_kind == "corrupt":
        raw_path.parent.mkdir()
        raw_path.write_text("{broken", encoding="utf-8")
    elif cache_kind != "missing":
        hosts = HOSTS if cache_kind == "complete" else HOSTS[:1]
        save_json(raw_path, _payload(hosts, receipts=cache_kind != "legacy"))
    assert cli.main() == 0
    expected = [] if cache_kind == "complete" else (
        [(HOSTS[1], 443)] if cache_kind == "partial" else [(h, 443) for h in HOSTS]
    )
    assert cli.calls == expected
    cp = CheckpointStore(cli.checkpoint)
    assert cp.is_done("pulse")
    assert cp.done_items("pulse") == set(HOSTS)
    assert cp.is_done("nse") and cp.done_items("nse") == {"unrelated-item"}
    services = cli.output / "services.json"
    assert {row["ip"] for row in json.loads(services.read_text())} == set(HOSTS)
    services.unlink()
    # Subsequent all-done resume restores a missing canonical file without scanning.
    assert cli.main() == 0
    assert cli.calls == expected
    assert {row["ip"] for row in json.loads(services.read_text())} == set(HOSTS)
    assert cli.main() == 0  # Current-pass chunks are now empty; receipts still work.
    assert cli.calls == expected


def test_main_failed_replay_cannot_reinstate_old_coarse_or_host_completion(cli):
    cli.outcome["code"] = 2
    assert cli.main() == 0  # Partial scan outcome policy is unchanged; stage stays pending.
    cp = CheckpointStore(cli.checkpoint)
    assert not cp.is_done("pulse")
    assert cp.done_items("pulse") == set()
    assert cp.is_done("nse")
    assert cli.calls == [(h, 443) for h in HOSTS]
    cli.outcome["code"] = 0
    assert cli.main() == 0
    assert cli.calls == [(h, 443) for h in HOSTS] * 2
    assert CheckpointStore(cli.checkpoint).is_done("pulse")
    assert cli.main() == 0
    assert len(cli.calls) == 4


def test_resume_validation_does_not_enable_a_disabled_pulse_stage(cli, monkeypatch):
    monkeypatch.setattr(sys, "argv", [*sys.argv, "--skip-nse"])
    assert cli.main() == 0
    assert cli.calls == []
    assert CheckpointStore(cli.checkpoint).done_items("pulse") == set(HOSTS)
    assert not (cli.output / "pulse/raw.json").exists()


def _capture_report(cli, monkeypatch):
    seen: dict = {}
    monkeypatch.setattr(cli.sm, "build_reports", lambda **kwargs: seen.update(kwargs))
    return seen


def _legacy_nmap_xml(output):
    xml = output / "nmap" / "tcp" / "tcp_192.0.2.1.xml"
    xml.parent.mkdir(parents=True)
    xml.write_text('<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', encoding="utf-8")


def test_resuming_a_pre_548_run_keeps_its_report_on_the_nmap_xml(cli, monkeypatch):
    """A shadow run of the old release: nmap/*.xml and pulse artifacts, no
    REPORT_PRIMARY. The resume used to write the marker unconditionally and flip
    the report's services/OS to Pulse's -- not "read as before"."""
    seen = _capture_report(cli, monkeypatch)
    _legacy_nmap_xml(cli.output)

    assert cli.main() == 0

    assert not (cli.output / "pulse" / "REPORT_PRIMARY").exists()
    assert seen["report_primary"] is False
    assert seen["nmap_dir"] == cli.output / "nmap"


def test_resuming_a_pre_548_run_that_was_already_pulse_primary_stays_so(cli, monkeypatch):
    seen = _capture_report(cli, monkeypatch)
    _legacy_nmap_xml(cli.output)
    (cli.output / "pulse").mkdir(exist_ok=True)
    (cli.output / "pulse" / "REPORT_PRIMARY").write_text("pulse\n", encoding="utf-8")

    assert cli.main() == 0

    assert (cli.output / "pulse" / "REPORT_PRIMARY").exists()
    assert seen["report_primary"] is True


def test_a_run_with_no_nmap_xml_is_pulse_primary(cli, monkeypatch):
    seen = _capture_report(cli, monkeypatch)

    assert cli.main() == 0

    assert (cli.output / "pulse" / "REPORT_PRIMARY").exists()
    assert seen["report_primary"] is True


# ---------------------------------------------------------------------------
# The verification run's connect probe, as scanner.main wires it (#451)
# ---------------------------------------------------------------------------


def _reachability(cli, monkeypatch, tmp_path, *, enabled):
    """The config a verification overlay produces: the finding's ports
    explicit, one of them excluded by the tenant, the probe on; Pulse's
    cache complete, so nothing but the probe has anything to do."""
    from scanner import main as sm
    from scanner.pipeline import reachability

    config = sm._config_for_run(None)[0]
    ports_file = tmp_path / "ports.txt"
    ports_file.write_text("443,8443\n", encoding="utf-8")
    config.ports.custom_ports_file = str(ports_file)
    config.ports.exclude_ports = [8443]
    config.reachability.enabled = enabled
    config.reachability.attempt_interval_seconds = 0
    save_json(cli.output / "pulse/raw.json", _payload(HOSTS))
    seen = []
    monkeypatch.setattr(
        reachability, "_attempt", lambda host, port, timeout: seen.append((host, port)) or "refused"
    )
    return seen


def test_a_verification_run_probes_its_hosts_on_the_explicit_ports(cli, monkeypatch, tmp_path):
    """The run's own targets, on the ports it was sent to re-check, minus the
    tenant's exclusions: a probe that skipped or never ran leaves nothing an
    endpoint_unreachable closure could rest on, and one that ignored the
    exclusions would connect where the tenant said not to."""
    seen = _reachability(cli, monkeypatch, tmp_path, enabled=True)

    assert cli.main() == 0

    assert sorted(set(seen)) == [(host, 443) for host in HOSTS]
    record = json.loads((cli.output / "reachability.json").read_text(encoding="utf-8"))
    assert {(p["host"], p["port"], p["result"]) for p in record["probes"]} == {
        (host, 443, "refused") for host in HOSTS
    }
    assert CheckpointStore(cli.checkpoint).is_done("reachability")


def test_an_ordinary_run_makes_no_connect_probe(cli, monkeypatch, tmp_path):
    seen = _reachability(cli, monkeypatch, tmp_path, enabled=False)

    assert cli.main() == 0

    assert seen == []
    assert not (cli.output / "reachability.json").exists()


# ---------------------------------------------------------------------------
# Rhai plugins, as scanner.main wires them (#544)
# ---------------------------------------------------------------------------


@pytest.fixture
def plugins_on(cli, monkeypatch):
    """Plugins enabled in the config, ``pulse plugin check`` stubbed to accept."""
    from scanner.pipeline import pulse_plugins

    cli.config.service_probe.pulse.plugins = True
    monkeypatch.setattr(pulse_plugins, "check_plugin", lambda *args, **kwargs: None)
    return cli


def test_plugins_reach_pulse_on_the_default_pulse_backend(plugins_on):
    assert plugins_on.main() == 0
    assert plugins_on.commands
    for command in plugins_on.commands:
        # A staging directory of the accepted files, absolute: pulse runs elsewhere.
        assert Path(command[command.index("--script-dir") + 1]).is_absolute()


def test_the_config_switch_turns_plugins_off(plugins_on):
    plugins_on.config.service_probe.pulse.plugins = False
    assert plugins_on.main() == 0
    assert plugins_on.commands
    assert all("--script-dir" not in command for command in plugins_on.commands)


def test_a_per_host_rate_ceiling_keeps_plugins_off_end_to_end(plugins_on, monkeypatch):
    from scanner.pipeline.scan_policy import apply_policy
    from tests.test_scanner_scan_policy import _policy

    tightened = apply_policy(plugins_on.config, _policy(per_host_rate=25))
    monkeypatch.setattr(plugins_on.sm, "_config_for_run", lambda args: (tightened, "safe", "custom"))
    assert plugins_on.main() == 0
    assert plugins_on.commands
    assert all("--script-dir" not in command for command in plugins_on.commands)


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("OCTO_SERVICE_BACKEND", "nmap"),
        ("OCTO_SERVICE_BACKEND", "hybrid"),
        ("OCTO_PULSE_SHADOW", "1"),
    ],
)
def test_the_removed_nmap_environment_stops_the_run_before_any_stage(monkeypatch, variable, value):
    """#548: ``_config_for_run`` is the one door every run goes through, so a
    sensor started with the removed Nmap environment exits 2 there, with the
    replacement named, before discovery or ports have run."""
    from scanner import main as sm

    monkeypatch.setenv(variable, value)
    ns = SimpleNamespace(config="scanner/config/default.yaml", config_overlay=None, scan_policy=None,
                         mode=None, delta=False)
    with pytest.raises(sm._RunConfigError) as exc:
        sm._config_for_run(ns)
    assert variable in str(exc.value)
    assert "docs/nmap-migration.md" in str(exc.value)
