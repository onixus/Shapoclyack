from __future__ import annotations

import pytest

from api.services import config_override as cfg


def test_unflatten_nested():
    flat = {"nuclei.enabled": True, "profiles.safe.top_ports": 1000}
    assert cfg.unflatten(flat) == {
        "nuclei": {"enabled": True},
        "profiles": {"safe": {"top_ports": 1000}},
    }


def test_validate_accepts_whitelisted():
    data = cfg.unflatten(
        {
            "fingerprint.enabled": True,
            "nuclei.severities": ["critical", "high"],
            "profiles.balanced.top_ports": 100,
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
    with pytest.raises(ValueError, match="one of"):
        cfg.validate_overrides({"profiles": {"safe": {"top_ports": 0}}})
    with pytest.raises(ValueError, match="unknown severities"):
        cfg.validate_overrides({"nuclei": {"severities": ["nope"]}})


def test_validate_rejects_top_ports_naabu_cannot_parse():
    """An in-range-looking count (500) is still not a naabu port set — it would
    abort every port batch of the run. The message names the two valid values."""
    with pytest.raises(ValueError, match=r"one of \[100, 1000\]"):
        cfg.validate_overrides({"profiles": {"safe": {"top_ports": 500}}})
    ok = {"profiles": {"safe": {"top_ports": 100}}}
    assert cfg.validate_overrides(ok) is ok


def test_validate_accepts_nuclei_performance_knobs():
    data = cfg.unflatten(
        {
            "nuclei.templates_dir": "/usr/share/nuclei-templates/http/cves",
            "nuclei.concurrency": 40,
            "nuclei.rate_limit": 400,
            "nuclei.timeout_seconds": 5,
            "nuclei.retries": 0,
        }
    )
    assert cfg.validate_overrides(data) is data


def test_validate_rejects_nuclei_performance_knobs_out_of_range():
    with pytest.raises(ValueError, match="integer"):
        cfg.validate_overrides({"nuclei": {"concurrency": 0}})
    with pytest.raises(ValueError, match="integer"):
        cfg.validate_overrides({"nuclei": {"rate_limit": 20_000}})
    with pytest.raises(ValueError, match="integer"):
        cfg.validate_overrides({"nuclei": {"timeout_seconds": 0}})
    with pytest.raises(ValueError, match="integer"):
        cfg.validate_overrides({"nuclei": {"retries": 6}})
    with pytest.raises(ValueError, match="non-empty string"):
        cfg.validate_overrides({"nuclei": {"templates_dir": ""}})
    with pytest.raises(ValueError, match="non-empty string"):
        cfg.validate_overrides({"nuclei": {"templates_dir": 123}})


def test_validate_accepts_service_probe_backend_pulse():
    data = cfg.unflatten({"service_probe.backend": "pulse"})
    assert cfg.validate_overrides(data) is data


@pytest.mark.parametrize("backend", ["nmap", "hybrid", "wireshark"])
def test_validate_rejects_every_service_probe_backend_but_pulse(backend):
    with pytest.raises(ValueError, match="one of"):
        cfg.validate_overrides({"service_probe": {"backend": backend}})


def test_validate_names_the_replacement_of_the_removed_nmap_settings():
    """#548: the console used to save these; the message says what happened to them."""
    with pytest.raises(ValueError, match=r"service_probe\.shadow: removed with the Nmap stage"):
        cfg.validate_overrides({"service_probe": {"shadow": True}})
    with pytest.raises(ValueError, match=r"nmap_timing: removed with the Nmap stage.*pulse\.rate"):
        cfg.validate_overrides({"profiles": {"safe": {"nmap_timing": "T3"}}})
    assert "profiles.safe.nmap_timing" not in cfg.EDITABLE_PATHS
    assert "service_probe.shadow" not in cfg.EDITABLE_PATHS


def test_deep_merge_via_effective_paths():
    base = {"nuclei": {"enabled": False, "severities": ["critical"]}, "profiles": {"safe": {"top_ports": 100}}}
    over = {"nuclei": {"enabled": True}, "profiles": {"safe": {"top_ports": 1000}}}
    merged = cfg._deep_merge(base, over)
    assert merged["nuclei"]["enabled"] is True
    # untouched sibling keys are preserved
    assert merged["nuclei"]["severities"] == ["critical"]
    assert merged["profiles"]["safe"]["top_ports"] == 1000


def test_validate_accepts_nvd_api_key():
    data = cfg.unflatten({"enrichment.cvss4.nvd_api_key": "  a-key  "})
    assert cfg.validate_overrides(data) is data
    with pytest.raises(ValueError, match="expected a string"):
        cfg.validate_overrides({"enrichment": {"cvss4": {"nvd_api_key": 1234}}})


def test_masked_secret_does_not_overwrite_the_stored_key():
    """The UI only ever sees the mask, so it echoes it back on unrelated edits.
    That must not replace the real key with a row of bullets."""
    stored = {"enrichment": {"cvss4": {"nvd_api_key": "real-key"}}}
    incoming = cfg.unflatten(
        {"enrichment.cvss4.nvd_api_key": cfg.SECRET_MASK, "nuclei.retries": 2}
    )
    out = cfg._restore_masked_secrets(stored, incoming)
    assert out["enrichment"]["cvss4"]["nvd_api_key"] == "real-key"
    assert out["nuclei"]["retries"] == 2


def test_masked_secret_with_nothing_stored_is_dropped_not_persisted():
    out = cfg._restore_masked_secrets({}, {"enrichment": {"cvss4": {"nvd_api_key": cfg.SECRET_MASK}}})
    assert out == {}


def test_empty_string_clears_the_stored_key():
    stored = {"enrichment": {"cvss4": {"nvd_api_key": "real-key"}}}
    out = cfg._restore_masked_secrets(stored, {"enrichment": {"cvss4": {"nvd_api_key": ""}}})
    assert out["enrichment"]["cvss4"]["nvd_api_key"] == ""


def test_profile_nuclei_override_merges_and_is_scoped():
    """profiles.<mode>.nuclei overrides the global block for that profile only.

    nuclei dominates wall-clock once ports are found, so a speed profile has to
    reach it. Only non-None fields apply; every other profile keeps the global
    values.
    """
    import yaml

    from scanner.pipeline.config_schema import load_config, merge_nuclei_config

    with open("scanner/config/default.yaml", encoding="utf-8") as handle:
        cfg = load_config(yaml.safe_load(handle))

    assert "test" in cfg.profiles, "test profile missing from default.yaml"

    merged = merge_nuclei_config(cfg.nuclei, cfg.profiles["test"].nuclei)
    assert merged.concurrency == 50
    assert merged.timeout_seconds == 5
    assert merged.overall_timeout_seconds == 300
    assert merged.severities == ["critical", "high"]
    # Not overridden by the profile — must fall through to the global value.
    assert merged.templates_dir == cfg.nuclei.templates_dir

    untouched = merge_nuclei_config(cfg.nuclei, cfg.profiles["balanced"].nuclei)
    assert untouched.model_dump() == cfg.nuclei.model_dump()


def test_screenshot_capture_is_not_an_editable_product_feature():
    assert "screenshots.enabled" not in cfg.EDITABLE_PATHS
    with pytest.raises(ValueError, match="screenshot capture is unsupported"):
        cfg.validate_overrides({"screenshots": {"enabled": True}})


def test_system_summary_does_not_advertise_legacy_screenshot_setting():
    from api.services.system_status import scan_config_summary

    summary = scan_config_summary(
        {"screenshots": {"enabled": True}}, {"screenshots.enabled": True}
    )
    assert "screenshots" not in summary["stages"]


def test_legacy_screenshot_override_does_not_block_unrelated_runs(monkeypatch):
    # Withdrawal of a UI control must not turn old saved overrides (including
    # false) into the removed-Nmap failure that stops every scan.
    monkeypatch.setattr(cfg, "get_overrides", lambda _settings: {"screenshots": {"enabled": False}})
    cfg.assert_runnable(None)


def _stored_row(monkeypatch, data: dict) -> None:
    """Serve ``data`` as the saved override row, as a pre-#367 install may hold it."""
    from contextlib import contextmanager
    from types import SimpleNamespace

    class _Session:
        def get(self, _model, _scope):
            return SimpleNamespace(data=data)

    @contextmanager
    def _get_session(_url):
        yield _Session()

    monkeypatch.setattr(cfg, "get_session", _get_session)


def test_stored_legacy_screenshot_enable_is_ignored_on_read(monkeypatch, tmp_path):
    from types import SimpleNamespace

    import yaml

    _stored_row(
        monkeypatch,
        {"screenshots": {"enabled": True, "concurrency": 2}, "fingerprint": {"enabled": False}},
    )
    base = tmp_path / "base.yaml"
    base.write_text(yaml.safe_dump({"screenshots": {"enabled": False}}), encoding="utf-8")
    settings = SimpleNamespace(postgres_url="unused", config_path=base, state_dir=tmp_path)

    overrides = cfg.get_overrides(settings)
    assert overrides == {"screenshots": {"concurrency": 2}, "fingerprint": {"enabled": False}}
    # Neither the local scan config nor a remote sensor's overlay re-enables capture.
    merged = yaml.safe_load(open(cfg.effective_config_path(settings, "job-1"), encoding="utf-8"))
    assert merged["screenshots"]["enabled"] is False
    assert "screenshots.enabled" not in cfg._flatten(cfg.agent_overlay(settings, None) or {})
