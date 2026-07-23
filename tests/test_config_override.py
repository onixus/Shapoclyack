from __future__ import annotations

import pytest

from api.services import config_override as cfg


def test_unflatten_nested():
    flat = {"nuclei.enabled": True, "profiles.safe.top_ports": 200}
    assert cfg.unflatten(flat) == {
        "nuclei": {"enabled": True},
        "profiles": {"safe": {"top_ports": 200}},
    }


def test_validate_accepts_whitelisted():
    data = cfg.unflatten(
        {
            "fingerprint.enabled": True,
            "nuclei.severities": ["critical", "high"],
            "profiles.balanced.nmap_timing": "T3",
            "profiles.fast.top_ports": 1000,
        }
    )
    assert cfg.validate_overrides(data) is data


def test_validate_rejects_unknown_path():
    with pytest.raises(ValueError, match="not an editable setting"):
        cfg.validate_overrides({"discovery": {"asn": {"enabled": True}}})


def test_validate_rejects_bad_types_and_ranges():
    with pytest.raises(ValueError, match="expected a boolean"):
        cfg.validate_overrides({"nuclei": {"enabled": "yes"}})
    with pytest.raises(ValueError, match="integer"):
        cfg.validate_overrides({"profiles": {"safe": {"top_ports": 0}}})
    with pytest.raises(ValueError, match="one of"):
        cfg.validate_overrides({"profiles": {"safe": {"nmap_timing": "T9"}}})
    with pytest.raises(ValueError, match="unknown severities"):
        cfg.validate_overrides({"nuclei": {"severities": ["nope"]}})


def test_deep_merge_via_effective_paths():
    base = {"nuclei": {"enabled": False, "severities": ["critical"]}, "profiles": {"safe": {"top_ports": 100}}}
    over = {"nuclei": {"enabled": True}, "profiles": {"safe": {"top_ports": 250}}}
    merged = cfg._deep_merge(base, over)
    assert merged["nuclei"]["enabled"] is True
    # untouched sibling keys are preserved
    assert merged["nuclei"]["severities"] == ["critical"]
    assert merged["profiles"]["safe"]["top_ports"] == 250
