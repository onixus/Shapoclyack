from __future__ import annotations

from datetime import UTC, datetime

import pytest

from scanner.pipeline.config_schema import load_config
from scanner.scheduler import build_scan_command, next_cron_time, parse_cron


def _minimal_config(**overrides: object) -> dict:
    base = {
        "runtime": {"mode": "balanced"},
        "profiles": {
            "safe": {
                "discover_rate": 1000,
                "port_rate": 1000,
                "top_ports": 100,
                "nmap_timing": "T3",
                "nse_profile": "baseline",
            },
            "balanced": {
                "discover_rate": 3000,
                "port_rate": 3000,
                "top_ports": 1000,
                "nmap_timing": "T4",
                "nse_profile": "baseline",
            },
            "fast": {
                "discover_rate": 7000,
                "port_rate": 7000,
                "top_ports": 1000,
                "nmap_timing": "T4",
                "nse_profile": "baseline",
            },
        },
        "nse_profiles": {"baseline": {"scripts": "default,safe"}},
    }
    base.update(overrides)
    return base


def test_parse_cron_supports_ranges_and_steps():
    minutes, hours, doms, months, dows = parse_cron("*/15 1-3 * * 1")
    assert minutes == {0, 15, 30, 45}
    assert hours == {1, 2, 3}
    assert 1 in dows
    assert len(doms) == 31
    assert len(months) == 12


def test_parse_cron_rejects_bad_expression():
    with pytest.raises(ValueError):
        parse_cron("0 2 *")


def test_next_cron_time_daily_at_two():
    after = datetime(2026, 7, 16, 1, 30, tzinfo=UTC)
    nxt = next_cron_time("0 2 * * *", after=after)
    assert nxt == datetime(2026, 7, 16, 2, 0, tzinfo=UTC)


def test_build_scan_command_flags():
    raw = _minimal_config(
        scheduler={
            "enabled": True,
            "mode": "fast",
            "delta": True,
            "skip_nse": True,
            "notify": True,
        }
    )
    cfg = load_config(raw)
    command = build_scan_command(cfg, "scanner/config/default.yaml")
    assert command[:4] == [command[0], "-m", "scanner.main", "--config"]
    assert "--mode" in command and "fast" in command
    assert "--delta" in command
    assert "--skip-nse" in command
    assert "--notify" in command
