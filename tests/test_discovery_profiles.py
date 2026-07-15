from __future__ import annotations

from scanner.pipeline.config_schema import (
    AppConfig,
    BatchingConfig,
    DiscoveryConfig,
    NseProfileConfig,
    ProfileConfig,
    RuntimeConfig,
)
from scanner.pipeline.discovery_profiles import (
    DISCOVERY_PROFILE_PRESETS,
    apply_discovery_profile,
    resolve_discovery_profile_name,
)


def _minimal_app(runtime_mode: str = "balanced", **discovery_overrides) -> AppConfig:
    profiles = {
        "safe": ProfileConfig(
            discover_rate=2000,
            port_rate=2000,
            top_ports=100,
            nse_profile="default",
        ),
        "balanced": ProfileConfig(
            discover_rate=4000,
            port_rate=4000,
            top_ports=100,
            nse_profile="default",
        ),
        "fast": ProfileConfig(
            discover_rate=8000,
            port_rate=8000,
            top_ports=100,
            nse_profile="default",
        ),
    }
    discovery = DiscoveryConfig(**discovery_overrides)
    return AppConfig(
        runtime=RuntimeConfig(mode=runtime_mode),
        profiles=profiles,
        batching=BatchingConfig(),
        discovery=discovery,
        nse_profiles={"default": NseProfileConfig(scripts="default")},
    )


def test_resolve_auto_maps_safe_to_thorough():
    cfg = _minimal_app(runtime_mode="safe")
    assert resolve_discovery_profile_name(cfg.discovery, "safe") == "thorough"


def test_resolve_auto_maps_fast_to_fast():
    cfg = _minimal_app(runtime_mode="fast")
    assert resolve_discovery_profile_name(cfg.discovery, "fast") == "fast"


def test_resolve_custom_returns_none():
    cfg = _minimal_app(profile="custom")
    assert resolve_discovery_profile_name(cfg.discovery, "balanced") is None


def test_apply_fast_profile_scales_rate_and_sets_coverage_skip():
    cfg = _minimal_app(runtime_mode="fast", profile="auto")
    applied = apply_discovery_profile(cfg, active_mode="fast")
    assert applied.profiles["fast"].discover_rate == 12_000
    assert applied.discovery.adaptive.min_coverage_pct == 95.0
    assert applied.discovery.verify.enabled is False
    assert applied.discovery.icmp.enabled is False
    assert applied.discovery.hostnames.reverse is False


def test_apply_thorough_profile_enables_verify_and_icmp():
    cfg = _minimal_app(runtime_mode="safe", profile="auto")
    applied = apply_discovery_profile(cfg, active_mode="safe")
    assert applied.profiles["safe"].discover_rate == 1500
    assert applied.discovery.verify.enabled is True
    assert applied.discovery.icmp.enabled is True
    assert applied.discovery.hostnames.reverse is True
    assert applied.discovery.adaptive.min_coverage_pct is None


def test_apply_balanced_profile_keeps_base_rate():
    cfg = _minimal_app(runtime_mode="balanced", profile="auto")
    applied = apply_discovery_profile(cfg, active_mode="balanced")
    assert applied.profiles["balanced"].discover_rate == 4000
    assert applied.discovery.adaptive.min_coverage_pct is None
    assert applied.discovery.verify.enabled is False


def test_apply_explicit_thorough_overrides_mode():
    cfg = _minimal_app(runtime_mode="fast", profile="thorough")
    applied = apply_discovery_profile(cfg, active_mode="fast")
    assert applied.discovery.verify.enabled is True
    assert applied.profiles["fast"].discover_rate == 6000


def test_custom_profile_does_not_mutate_config():
    cfg = _minimal_app(runtime_mode="balanced", profile="custom", icmp={"enabled": True})
    applied = apply_discovery_profile(cfg, active_mode="balanced")
    assert applied is cfg
    assert applied.discovery.icmp.enabled is True


def test_all_presets_defined():
    assert set(DISCOVERY_PROFILE_PRESETS) == {"fast", "balanced", "thorough"}
