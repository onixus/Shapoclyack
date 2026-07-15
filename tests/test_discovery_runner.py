from __future__ import annotations

from scanner.pipeline.config_schema import (
    AdaptiveDiscoveryConfig,
    AppConfig,
    BatchingConfig,
    DiscoveryConfig,
    NseProfileConfig,
    ProfileConfig,
    RuntimeConfig,
)
from scanner.pipeline.discovery_runner import _discover_concurrency


def _minimal_config(**runtime_overrides) -> AppConfig:
    runtime = RuntimeConfig(discover_concurrency=4, **runtime_overrides)
    profiles = {
        "safe": ProfileConfig(
            discover_rate=1000,
            port_rate=1000,
            top_ports=100,
            nse_profile="default",
        ),
        "balanced": ProfileConfig(
            discover_rate=2000,
            port_rate=2000,
            top_ports=100,
            nse_profile="default",
        ),
        "fast": ProfileConfig(
            discover_rate=4000,
            port_rate=4000,
            top_ports=100,
            nse_profile="default",
        ),
    }
    return AppConfig(
        runtime=runtime,
        profiles=profiles,
        batching=BatchingConfig(enabled=True, ipv4_prefix=24),
        discovery=DiscoveryConfig(
            disjoint_batches=True,
            skip_known_alive=True,
            adaptive=AdaptiveDiscoveryConfig(enabled=True),
        ),
        nse_profiles={"default": NseProfileConfig(scripts="default")},
    )


def test_discover_concurrency_parallel_when_disjoint():
    config = _minimal_config()
    batches = [
        ("10.0.0.0/24", ["10.0.0.0/24"]),
        ("10.0.1.0/24", ["10.0.1.0/24"]),
    ]
    assert _discover_concurrency(config, batches, skip_known_alive=True) == 4
    assert _discover_concurrency(config, batches, skip_known_alive=False) == 4


def test_discover_concurrency_serial_when_overlapping_and_skip_known():
    config = _minimal_config()
    batches = [
        ("a", ["10.0.0.0/24"]),
        ("b", ["10.0.0.0/25"]),
    ]
    assert _discover_concurrency(config, batches, skip_known_alive=True) == 1


def test_discover_concurrency_parallel_when_overlapping_but_not_skip_known():
    config = _minimal_config()
    batches = [
        ("a", ["10.0.0.0/24"]),
        ("b", ["10.0.0.0/25"]),
    ]
    assert _discover_concurrency(config, batches, skip_known_alive=False) == 4


def test_wave2_uses_same_concurrency_rules_as_wave1_with_skip_known():
    config = _minimal_config()
    gap_batches = [
        ("10.0.2.0/24", ["10.0.2.0/24"]),
        ("10.0.3.0/24", ["10.0.3.0/24"]),
    ]
    assert _discover_concurrency(config, gap_batches, skip_known_alive=True) == 4
