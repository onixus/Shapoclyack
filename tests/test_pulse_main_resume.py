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
        "profiles": {name: {"discover_rate": 10, "port_rate": 10, "top_ports": 100,
                             "nse_profile": "baseline"} for name in ("safe", "balanced", "fast")},
        "nse_profiles": {"baseline": {"scripts": "default,safe"}},
        "service_probe": {"backend": "pulse", "pulse": {"retry_settle_seconds": 0}},
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
        "enrich_discovery_hostnames", "fast_port_scan", "run_nse", "check_tls_posture",
        "fingerprint_hosts_sync", "capture_screenshots_sync", "run_nuclei_scan",
        "discover_related_domains", "check_credential_leaks", "send_alerts", "export_to_defectdojo",
    ):
        monkeypatch.setattr(sm, name, forbidden)
    monkeypatch.setattr(pp, "resolve_pulse_bin", lambda _: "fixture")
    monkeypatch.setattr(pp, "_pulse_available", lambda _: True)
    calls = []
    outcome = {"code": 0}

    def probe(command, **kwargs):
        hosts = Path(command[command.index("--targets-file") + 1]).read_text().splitlines()
        ports = [int(p) for p in command[command.index("-p") + 1].split(",")]
        disk = CheckpointStore(state / "checkpoint.json")
        assert not disk.is_done("pulse"), "stale coarse completion survived until replay"
        assert not set(hosts) & disk.done_items("pulse"), "unverified host was not invalidated"
        calls.extend((host, port) for host in hosts for port in ports)
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
                           calls=calls, outcome=outcome)


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


@pytest.mark.parametrize("disabled_by", ["skip-nse", "backend"])
def test_resume_validation_does_not_enable_a_disabled_pulse_stage(cli, monkeypatch, disabled_by):
    if disabled_by == "skip-nse":
        monkeypatch.setattr(sys, "argv", [*sys.argv, "--skip-nse"])
    else:
        monkeypatch.setenv("OCTO_SERVICE_BACKEND", "nmap")
    assert cli.main() == 0
    assert cli.calls == []
    assert CheckpointStore(cli.checkpoint).done_items("pulse") == set(HOSTS)
    assert not (cli.output / "pulse/raw.json").exists()
