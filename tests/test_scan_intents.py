"""Unit tests for scan intent resolution (product performance control)."""

from __future__ import annotations

import pytest

from api.services.scan_intents import merge_config_extras, resolve_scan_options


def test_legacy_flags_when_no_intent() -> None:
    r = resolve_scan_options(intent=None, mode="balanced", delta=True, skip_nse=True)
    assert r.intent is None
    assert r.delta is True
    assert r.skip_nse is True
    assert r.config_extra == {}
    assert r.mode == "balanced"


def test_inventory_forces_skip_nse_and_disables_nuclei() -> None:
    r = resolve_scan_options(intent="inventory", mode="fast", delta=True, skip_nse=False)
    assert r.intent == "inventory"
    assert r.skip_nse is True
    assert r.delta is True  # inventory may still use incremental discovery
    assert r.mode == "fast"
    assert r.config_extra["nuclei"]["enabled"] is False
    assert r.config_extra["profiles"]["fast"]["top_ports"] == 100


def test_vuln_sets_nuclei_floor() -> None:
    r = resolve_scan_options(intent="vuln", mode="balanced", delta=False, skip_nse=True)
    assert r.skip_nse is False  # intent owns the flag
    assert r.config_extra["nuclei"]["severities"] == ["critical", "high"]


def test_delta_intent_forces_delta_flag() -> None:
    r = resolve_scan_options(intent="delta", mode="safe", delta=False, skip_nse=False)
    assert r.delta is True
    assert r.skip_nse is False


def test_full_intent() -> None:
    r = resolve_scan_options(intent="full", mode="balanced", delta=False, skip_nse=False)
    assert r.intent == "full"
    assert "medium" in r.config_extra["nuclei"]["severities"]


def test_unknown_intent_raises() -> None:
    with pytest.raises(ValueError, match="intent must be"):
        resolve_scan_options(intent="turbo", mode="balanced", delta=False, skip_nse=False)


def test_mode_test_maps_to_balanced_cli() -> None:
    r = resolve_scan_options(intent="inventory", mode="test", delta=False, skip_nse=False)
    assert r.mode == "balanced"
    assert "balanced" in r.config_extra["profiles"]


def test_merge_config_extras() -> None:
    merged = merge_config_extras(
        {"nuclei": {"enabled": False}},
        {"discovery": {"ct": {"enabled": True}}},
        None,
    )
    assert merged == {
        "nuclei": {"enabled": False},
        "discovery": {"ct": {"enabled": True}},
    }
    assert merge_config_extras(None, {}) is None


def test_org_profile_intent() -> None:
    r = resolve_scan_options(intent="org_profile", mode="balanced", delta=False, skip_nse=True)
    assert r.intent == "org_profile"
    assert r.skip_nse is False
    assert r.config_extra["org_profile"]["ownership"]["enabled"] is True
    assert r.config_extra["org_profile"]["dns_hygiene"]["enabled"] is True
    assert r.config_extra["org_profile"]["mail_posture"]["enabled"] is True
    assert r.config_extra["org_profile"]["controls"]["enabled"] is True
    assert r.config_extra["fingerprint"]["enabled"] is True
    assert r.config_extra["tls_posture"]["enabled"] is True

