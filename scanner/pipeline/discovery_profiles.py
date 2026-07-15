from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .config_schema import AppConfig, DiscoveryConfig

DiscoveryProfileName = Literal["fast", "balanced", "thorough"]
DiscoveryProfileSetting = Literal["auto", "fast", "balanced", "thorough", "custom"]

_MODE_TO_PROFILE: dict[str, DiscoveryProfileName] = {
    "fast": "fast",
    "balanced": "balanced",
    "safe": "thorough",
}


@dataclass(frozen=True)
class DiscoveryProfilePreset:
    rate_multiplier: float
    adaptive_enabled: bool
    adaptive_min_gap: int
    adaptive_min_coverage_pct: float | None
    verify_enabled: bool
    icmp_enabled: bool
    hostname_forward: bool
    hostname_reverse: bool


DISCOVERY_PROFILE_PRESETS: dict[DiscoveryProfileName, DiscoveryProfilePreset] = {
    "fast": DiscoveryProfilePreset(
        rate_multiplier=1.5,
        adaptive_enabled=True,
        adaptive_min_gap=1,
        adaptive_min_coverage_pct=95.0,
        verify_enabled=False,
        icmp_enabled=False,
        hostname_forward=True,
        hostname_reverse=False,
    ),
    "balanced": DiscoveryProfilePreset(
        rate_multiplier=1.0,
        adaptive_enabled=True,
        adaptive_min_gap=1,
        adaptive_min_coverage_pct=None,
        verify_enabled=False,
        icmp_enabled=False,
        hostname_forward=True,
        hostname_reverse=False,
    ),
    "thorough": DiscoveryProfilePreset(
        rate_multiplier=0.75,
        adaptive_enabled=True,
        adaptive_min_gap=1,
        adaptive_min_coverage_pct=None,
        verify_enabled=True,
        icmp_enabled=True,
        hostname_forward=True,
        hostname_reverse=True,
    ),
}


def resolve_discovery_profile_name(
    discovery: DiscoveryConfig,
    runtime_mode: str,
) -> DiscoveryProfileName | None:
    """Return preset name to apply, or None when profile is custom."""
    if discovery.profile == "custom":
        return None
    if discovery.profile != "auto":
        return discovery.profile
    return _MODE_TO_PROFILE.get(runtime_mode, "balanced")


def _scaled_rate(rate: int, multiplier: float) -> int:
    return max(1, min(100_000, int(rate * multiplier)))


def apply_discovery_profile(config: AppConfig, *, active_mode: str) -> AppConfig:
    """Merge mode-derived discovery presets into config (YAML base + preset overrides)."""
    preset_name = resolve_discovery_profile_name(config.discovery, active_mode)
    if preset_name is None:
        return config

    preset = DISCOVERY_PROFILE_PRESETS[preset_name]
    discovery = config.discovery.model_copy(deep=True)
    discovery.adaptive.enabled = preset.adaptive_enabled
    discovery.adaptive.min_gap = preset.adaptive_min_gap
    discovery.adaptive.min_coverage_pct = preset.adaptive_min_coverage_pct
    discovery.verify.enabled = preset.verify_enabled
    discovery.icmp.enabled = preset.icmp_enabled
    discovery.hostnames.forward = preset.hostname_forward
    discovery.hostnames.reverse = preset.hostname_reverse

    profiles = dict(config.profiles)
    active = profiles[active_mode].model_copy(deep=True)
    active.discover_rate = _scaled_rate(active.discover_rate, preset.rate_multiplier)
    profiles[active_mode] = active

    return config.model_copy(update={"discovery": discovery, "profiles": profiles})
