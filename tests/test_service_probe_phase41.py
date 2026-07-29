"""Phase 4.1: Pulse default backend + profile pulse overrides."""

from __future__ import annotations

from pathlib import Path

from scanner.pipeline.config_schema import (
    PulseProbeConfig,
    ProfilePulseConfig,
    load_config,
    merge_pulse_config,
)
from scanner.pipeline.pulse_probe import write_pulse_artifacts
from scanner.pipeline.service_schema import ServiceRecord


def test_default_yaml_backend_is_pulse():
    cfg = load_config(
        __import__("yaml").safe_load(
            Path("scanner/config/default.yaml").read_text(encoding="utf-8")
        )
    )
    assert cfg.service_probe.backend == "pulse"
    assert "vuln_legacy" in cfg.nse_profiles
    assert cfg.profiles["balanced"].nse_profile == "vuln_legacy"
    assert cfg.profiles["safe"].pulse.concurrency == 300
    assert cfg.profiles["safe"].pulse.os_mode == "sinfp"
    assert cfg.profiles["balanced"].pulse.host_parallel == 16
    assert cfg.profiles["fast"].pulse.rate == 5000


def test_merge_pulse_config_overrides_only_set_fields():
    base = PulseProbeConfig(concurrency=500, rate=2000, os_mode="auto", host_parallel=8)
    ov = ProfilePulseConfig(concurrency=300, os_mode="sinfp")
    merged = merge_pulse_config(base, ov)
    assert merged.concurrency == 300
    assert merged.os_mode == "sinfp"
    assert merged.rate == 2000
    assert merged.host_parallel == 8
    assert merged.banner is True


def test_merge_pulse_config_none_override():
    base = PulseProbeConfig(concurrency=100)
    assert merge_pulse_config(base, None).concurrency == 100
    assert merge_pulse_config(base, ProfilePulseConfig()).concurrency == 100


def test_report_primary_marker_from_run_pulse_probe(tmp_path: Path):
    from scanner.pipeline.pulse_probe import run_pulse_probe

    # Empty open ports path still honors report_primary
    pulse_dir = run_pulse_probe(
        [],
        output_dir=tmp_path,
        report_primary=True,
    )
    assert (pulse_dir / "REPORT_PRIMARY").read_text(encoding="utf-8").strip() == "pulse"


def test_report_primary_false_no_marker(tmp_path: Path):
    from scanner.pipeline.pulse_probe import run_pulse_probe

    pulse_dir = run_pulse_probe([], output_dir=tmp_path, report_primary=False)
    assert not (pulse_dir / "REPORT_PRIMARY").exists()


def test_write_artifacts_still_works(tmp_path: Path):
    write_pulse_artifacts(
        tmp_path,
        [ServiceRecord(ip="10.0.0.1", port=443, service="https")],
        [],
        [],
    )
    assert (tmp_path / "services.json").exists()
