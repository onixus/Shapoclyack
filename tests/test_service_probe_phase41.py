"""Phase 4.1: Pulse default backend + profile pulse overrides."""

from __future__ import annotations

from pathlib import Path

from scanner.pipeline.config_schema import (
    PulseProbeConfig,
    ProfilePulseConfig,
    load_config,
    merge_pulse_config,
    resolve_service_probe_backend,
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


def test_profile_pulse_config_bounds_match_base():
    """ProfilePulseConfig hand-mirrors PulseProbeConfig's fields as Optional;
    this guards against the two silently drifting (a bound changed in one but
    not the other, or a field added to one and forgotten in the other)."""
    base_fields = PulseProbeConfig.model_fields
    override_fields = ProfilePulseConfig.model_fields
    # `bin` is intentionally not overridable per-profile.
    assert set(override_fields) == set(base_fields) - {"bin"}
    for name, override_field in override_fields.items():
        base_field = base_fields[name]

        def bounds(field):
            ge = le = None
            for meta in field.metadata:
                if hasattr(meta, "ge"):
                    ge = meta.ge
                if hasattr(meta, "le"):
                    le = meta.le
            return ge, le

        assert bounds(override_field) == bounds(base_field), (
            f"ProfilePulseConfig.{name} bounds {bounds(override_field)} != "
            f"PulseProbeConfig.{name} bounds {bounds(base_field)}"
        )


def test_resolve_service_probe_backend_precedence():
    # env wins over profile wins over YAML
    r = resolve_service_probe_backend(
        env_backend="nmap",
        profile_backend="hybrid",
        yaml_backend="pulse",
        yaml_shadow=False,
        env_shadow="",
        skip_nse=False,
    )
    assert r.backend == "nmap"
    assert r.run_nmap_nse is True
    assert r.run_pulse is False
    assert r.report_primary_pulse is False

    r = resolve_service_probe_backend(
        env_backend="",
        profile_backend="hybrid",
        yaml_backend="pulse",
        yaml_shadow=False,
        env_shadow="",
        skip_nse=False,
    )
    assert r.backend == "hybrid"
    assert r.run_pulse is True
    assert r.run_nmap_nse is True
    assert r.report_primary_pulse is True

    r = resolve_service_probe_backend(
        env_backend="",
        profile_backend=None,
        yaml_backend="pulse",
        yaml_shadow=False,
        env_shadow="",
        skip_nse=False,
    )
    assert r.backend == "pulse"


def test_resolve_service_probe_backend_shadow_forces_dual_run():
    r = resolve_service_probe_backend(
        env_backend="nmap",
        profile_backend=None,
        yaml_backend="pulse",
        yaml_shadow=True,
        env_shadow="",
        skip_nse=False,
    )
    assert r.backend == "nmap"
    assert r.shadow is True
    assert r.run_pulse is True
    assert r.run_nmap_nse is True
    # Shadow forces both stages to run, but report preference still follows
    # the resolved backend, not the shadow flag.
    assert r.report_primary_pulse is False


def test_resolve_service_probe_backend_skip_nse_disables_both():
    r = resolve_service_probe_backend(
        env_backend="",
        profile_backend=None,
        yaml_backend="hybrid",
        yaml_shadow=True,
        env_shadow="",
        skip_nse=True,
    )
    assert r.run_pulse is False
    assert r.run_nmap_nse is False


def test_resolve_service_probe_backend_unknown_falls_back_to_pulse():
    warnings: list[str] = []
    r = resolve_service_probe_backend(
        env_backend="bogus",
        profile_backend=None,
        yaml_backend="pulse",
        yaml_shadow=False,
        env_shadow="",
        skip_nse=False,
        warn=warnings.append,
    )
    assert r.backend == "pulse"
    assert warnings
