"""Phase 4.1: Pulse default backend + profile pulse overrides."""

from __future__ import annotations

from pathlib import Path

import pytest

from scanner.pipeline.config_schema import (
    ProfilePulseConfig,
    PulseProbeConfig,
    RemovedNmapSettingError,
    check_service_probe_env,
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
    assert cfg.profiles["safe"].pulse.concurrency == 300
    assert cfg.profiles["safe"].pulse.os_mode == "sinfp"
    assert cfg.profiles["balanced"].pulse.host_parallel == 16
    assert cfg.profiles["fast"].pulse.rate == 5000


def test_merge_pulse_config_overrides_only_set_fields():
    base = PulseProbeConfig(concurrency=500, rate=2000, os_mode="sinfp", host_parallel=8)
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


def test_resolve_service_probe_backend_is_pulse_unless_skipped():
    r = resolve_service_probe_backend(env_backend="", skip_nse=False)
    assert (r.backend, r.run_pulse, r.report_primary_pulse) == ("pulse", True, True)
    r = resolve_service_probe_backend(env_backend="pulse", env_shadow="0", skip_nse=False)
    assert r.backend == "pulse"
    # --skip-nse is the ports-only L1 switch: no probe, report preference unchanged.
    r = resolve_service_probe_backend(env_backend="", skip_nse=True)
    assert (r.run_pulse, r.report_primary_pulse) == (False, True)


@pytest.mark.parametrize("backend", ["nmap", "hybrid", "NMAP", " hybrid ", "bogus"])
def test_env_service_backend_other_than_pulse_is_refused(backend):
    """#548: it used to warn and fall back to pulse for an unknown value, and
    ran nmap for the known ones. Neither is possible now; silently running Pulse
    for ``nmap`` would hide that the operator's choice has no effect."""
    with pytest.raises(RemovedNmapSettingError) as exc:
        resolve_service_probe_backend(env_backend=backend, skip_nse=False)
    assert "OCTO_SERVICE_BACKEND" in str(exc.value)
    assert "docs/nmap-migration.md" in str(exc.value)
    with pytest.raises(RemovedNmapSettingError):
        check_service_probe_env(backend)


@pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
def test_env_pulse_shadow_is_refused(value):
    with pytest.raises(RemovedNmapSettingError) as exc:
        resolve_service_probe_backend(env_backend="", env_shadow=value, skip_nse=False)
    assert "OCTO_PULSE_SHADOW" in str(exc.value)


@pytest.mark.parametrize("value", ["", "0", "false", "off"])
def test_env_pulse_shadow_off_is_fine(value):
    check_service_probe_env("", value)


@pytest.mark.parametrize(
    ("variable", "value"),
    [("OCTO_SERVICE_BACKEND", "nmap"), ("OCTO_SERVICE_BACKEND", "hybrid"), ("OCTO_PULSE_SHADOW", "1")],
)
def test_validate_config_flag_refuses_the_removed_nmap_environment(monkeypatch, capsys, variable, value):
    """#548: ``--validate-config`` used to print "configuration OK" for a file
    plus an environment the real run refuses."""
    from scanner import exit_codes
    from scanner.main import _validate_config_only

    monkeypatch.setenv(variable, value)
    assert _validate_config_only(Path("scanner/config/default.yaml")) == exit_codes.CONFIG_ERROR
    err = capsys.readouterr().err
    assert variable in err and "docs/nmap-migration.md" in err


def test_validate_config_flag_is_fine_with_a_clean_environment(monkeypatch, capsys):
    from scanner import exit_codes
    from scanner.main import _validate_config_only

    monkeypatch.delenv("OCTO_SERVICE_BACKEND", raising=False)
    monkeypatch.delenv("OCTO_PULSE_SHADOW", raising=False)
    assert _validate_config_only(Path("scanner/config/default.yaml")) == exit_codes.SUCCESS
    assert "configuration OK" in capsys.readouterr().out
