from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.pipeline.config_schema import (
    AppConfig,
    DiscoveryConfig,
    MailPostureConfig,
    format_validation_error,
    load_config,
)


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
        "nse_profiles": {
            "baseline": {"scripts": "default,safe"},
        },
    }
    base.update(overrides)
    return base


def test_load_config_accepts_minimal_valid():
    cfg = load_config(_minimal_config())
    assert cfg.runtime.mode == "balanced"
    assert cfg.profiles["safe"].top_ports == 100
    assert cfg.enrichment.cvss4.enabled is True
    assert cfg.enrichment.geoip.enabled is True
    assert "cvss4" in cfg.enrichment.cvss4.database
    assert "geoip" in cfg.enrichment.geoip.database


def test_load_config_accepts_enrichment_overrides():
    cfg = load_config(
        _minimal_config(
            enrichment={
                "cvss4": {"enabled": False, "database": "/tmp/cvss4.json"},
                "geoip": {"enabled": True, "database": "/tmp/GeoLite2-City.mmdb"},
            }
        )
    )
    assert cfg.enrichment.cvss4.enabled is False
    assert cfg.enrichment.cvss4.database == "/tmp/cvss4.json"
    assert cfg.enrichment.geoip.database.endswith("GeoLite2-City.mmdb")


def test_load_config_rejects_unknown_runtime_mode():
    raw = _minimal_config()
    raw["runtime"] = {"mode": "turbo"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_missing_nse_profile_ref():
    raw = _minimal_config()
    raw["profiles"]["balanced"]["nse_profile"] = "missing"
    with pytest.raises(ValidationError) as exc:
        load_config(raw)
    msg = format_validation_error(exc.value)
    assert "nse_profile" in msg


def test_load_config_rejects_invalid_ipv4_prefix():
    raw = _minimal_config()
    raw["batching"] = {"ipv4_prefix": 99}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_nse_timeout_above_ten_minutes():
    raw = _minimal_config()
    raw["runtime"] = {"nse_timeout_seconds": 601}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_invalid_batch_concurrency():
    raw = _minimal_config()
    raw["runtime"] = {"discover_concurrency": 0}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_load_config_rejects_invalid_port_protocol():
    raw = _minimal_config()
    raw["ports"] = {"protocol": "both"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_discovery_bench_yaml_parses():
    import yaml

    text = Path("scanner/config/discovery-bench.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.runtime.discover_concurrency == 8
    assert cfg.discovery.skip_discovery is False
    assert cfg.profiles["balanced"].discover_rate == 6000


def test_discovery_bench_realistic_yaml_parses():
    import yaml

    text = Path("scanner/config/discovery-bench-realistic.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.runtime.discover_concurrency == 2
    assert cfg.profiles["balanced"].discover_rate == 3000
    assert cfg.batching.max_targets_per_batch == 128
    assert cfg.discovery.adaptive.enabled is True
    assert cfg.discovery.verify.enabled is True
    assert cfg.discovery.hostnames.forward is True
    assert cfg.discovery.hostnames.reverse is False


def test_default_yaml_hostname_resolve():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.discovery.hostnames.forward is True
    assert cfg.discovery.hostnames.reverse is True


def test_default_yaml_icmp_disabled():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.discovery.icmp.enabled is False
    assert cfg.discovery.icmp.tool == "fping"
    assert cfg.discovery.icmp.timeout_ms == 500
    assert cfg.discovery.tcp_probe.enabled is False
    assert cfg.discovery.probe_order == ["icmp", "tcp", "naabu"]
    assert cfg.discovery.profile == "auto"
    assert cfg.discovery.seed_alive_file == ""
    assert cfg.discovery.delta.enabled is False
    assert cfg.discovery.delta.refresh_rate == 0.1


def test_probe_order_validation_rejects_unknown_step():
    with pytest.raises(ValidationError):
        DiscoveryConfig(probe_order=["icmp", "udp", "naabu"])


def test_default_yaml_adaptive_discovery():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.discovery.adaptive.enabled is True
    assert cfg.discovery.adaptive.wave2_rate == 2500
    assert cfg.discovery.disjoint_batches is True
    assert cfg.discovery.verify.enabled is True
    assert cfg.discovery.verify.rate == 1250
    assert cfg.batching.ipv4_prefix == 24
    assert cfg.batching.max_targets_per_batch == 1024
    assert cfg.runtime.skip_nse is False
    assert cfg.profiles["balanced"].discover_rate == 4000


def test_k8s_yaml_discovery_completeness_knobs():
    import yaml

    text = Path("k8s/shapoclyack/base/config/k8s.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.discovery.verify.enabled is True
    assert cfg.discovery.verify.rate == 1250
    assert cfg.discovery.adaptive.wave2_rate == 2500
    assert cfg.batching.ipv4_prefix == 24
    assert cfg.batching.max_targets_per_batch == 1024
    # Keep reverse DNS and vuln-offline — not bench-only settings.
    assert cfg.discovery.hostnames.reverse is True
    assert cfg.profiles["balanced"].nse_profile == "vuln-offline"


def test_default_yaml_parses():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.runtime.per_run_output is True
    assert cfg.runtime.nse_timeout_seconds == 600
    assert cfg.runtime.discover_concurrency == 4
    assert cfg.runtime.ports_concurrency == 4
    assert cfg.runtime.nse_hosts_per_scan == 1
    assert cfg.ports.protocol == "tcp"
    assert cfg.ports.udp_probes is True
    assert cfg.screenshots.enabled is False
    assert cfg.screenshots.max_targets == 50
    # org_profile M1 (#182): opt-in, and the registry-query caps stay in sync
    # with OwnershipConfig's defaults.
    assert cfg.org_profile.ownership.enabled is False
    assert cfg.org_profile.ownership.domains == []
    assert cfg.org_profile.ownership.max_domains == 50
    assert cfg.org_profile.ownership.timeout_seconds == 15
    assert cfg.org_profile.ownership.deadline_seconds == 300
    # org_profile M2 (#182): both stages opt-in, and AXFR -- the only active
    # check in the module -- stays off in the shipped config.
    assert cfg.org_profile.dns_hygiene.enabled is False
    assert cfg.org_profile.dns_hygiene.axfr_probe is False
    assert cfg.org_profile.dns_hygiene.max_domains == 50
    assert cfg.org_profile.dns_hygiene.deadline_seconds == 300
    assert cfg.org_profile.mail_posture.enabled is False
    assert cfg.org_profile.mail_posture.mta_sts_http is True
    assert cfg.org_profile.mail_posture.dkim_selectors == [
        "default",
        "google",
        "selector1",
        "selector2",
        "k1",
        "mail",
    ]


def test_default_yaml_phase1_sections():
    import yaml

    text = Path("scanner/config/default.yaml").read_text(encoding="utf-8")
    cfg = AppConfig.model_validate(yaml.safe_load(text))
    assert cfg.reporting.diff.enabled is True
    assert cfg.reporting.diff.markdown is True
    assert cfg.reporting.pdf_summary is True
    assert cfg.reporting.pdf_max_vulnerabilities == 40
    assert cfg.alerts.enabled is False
    assert cfg.alerts.min_severity == "high"
    assert cfg.alerts.slack.enabled is False
    assert cfg.alerts.telegram.enabled is False
    assert cfg.alerts.smtp.enabled is False
    assert cfg.alerts.smtp.host == "127.0.0.1"
    assert cfg.discovery.cloudflare.enabled is False
    assert cfg.discovery.ct.enabled is False
    assert cfg.discovery.ct.providers == ["crtsh"]
    assert cfg.defectdojo.enabled is False
    assert cfg.defectdojo.product_name == "Shapoclyack"
    assert cfg.defectdojo.min_severity == "high"
    assert cfg.scheduler.enabled is False
    assert cfg.scheduler.cron == "0 2 * * *"
    assert cfg.scheduler.mode is None
    assert cfg.scheduler.export_defectdojo is False


def test_defectdojo_min_severity_validation():
    raw = _minimal_config()
    raw["defectdojo"] = {"min_severity": "urgent"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_scheduler_cron_must_have_five_fields():
    raw = _minimal_config()
    raw["scheduler"] = {"cron": "0 2 *"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_alerts_min_severity_validation():
    raw = _minimal_config()
    raw["alerts"] = {"min_severity": "urgent"}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_screenshots_opt_in_defaults():
    cfg = load_config(_minimal_config())
    assert cfg.screenshots.enabled is False
    assert cfg.screenshots.max_targets == 50
    assert cfg.screenshots.concurrency == 4


def test_screenshots_rejects_invalid_port():
    raw = _minimal_config()
    raw["screenshots"] = {"enabled": True, "http_ports": [0]}
    with pytest.raises(ValidationError):
        load_config(raw)


def test_dkim_selectors_must_be_dns_labels():
    """A selector is interpolated into a query name and passed to dnsx."""
    for bad in ["not a label", "sel.ector", "x" * 64, "sel/../etc"]:
        with pytest.raises(ValidationError):
            MailPostureConfig(dkim_selectors=[bad])
    assert MailPostureConfig(dkim_selectors=["s1", "selector-2"]).dkim_selectors == [
        "s1",
        "selector-2",
    ]


def test_dkim_selector_list_is_capped():
    with pytest.raises(ValidationError):
        MailPostureConfig(dkim_selectors=[f"s{index}" for index in range(21)])


def test_validate_config_flag_accepts_the_shipped_default(capsys):
    """`--validate-config` is documented in getting-started.md; it has to work."""
    from scanner import exit_codes
    from scanner.main import _validate_config_only

    assert _validate_config_only(Path("scanner/config/default.yaml")) == exit_codes.SUCCESS
    assert "configuration OK" in capsys.readouterr().out


def test_validate_config_flag_reports_a_bad_file(tmp_path: Path, capsys):
    """A rejected config exits 2 and names the failing key. No stage is started."""
    from scanner import exit_codes
    from scanner.main import _validate_config_only

    bad = tmp_path / "bad.yaml"
    bad.write_text("runtime:\n  mode: nope\nprofiles: {}\nnse_profiles: {}\n", encoding="utf-8")
    assert _validate_config_only(bad) == exit_codes.CONFIG_ERROR
    assert "runtime.mode" in capsys.readouterr().err

    missing = tmp_path / "absent.yaml"
    assert _validate_config_only(missing) == exit_codes.CONFIG_ERROR
    assert "not found" in capsys.readouterr().err

    broken = tmp_path / "broken.yaml"
    broken.write_text("runtime: [\n", encoding="utf-8")
    assert _validate_config_only(broken) == exit_codes.CONFIG_ERROR
    assert "not valid YAML" in capsys.readouterr().err


def test_extend_web_ports_with_custom_adds_unknown_ports_to_both_schemes():
    from scanner.pipeline.config_schema import extend_web_ports_with_custom

    http, https = extend_web_ports_with_custom(
        [80, 8080], [443, 8443], {80, 443, 7443, 9000}
    )
    # Already-classified ports keep their single scheme; unknown custom ports
    # (7443, 9000) are added to both so nuclei/fingerprint probe http and https.
    assert http == [80, 8080, 7443, 9000]
    assert https == [443, 8443, 7443, 9000]


def test_extend_web_ports_with_custom_noop_when_all_known():
    from scanner.pipeline.config_schema import extend_web_ports_with_custom

    http, https = extend_web_ports_with_custom([80], [443], {80, 443})
    assert http == [80]
    assert https == [443]
    # No custom ports at all is also a no-op (default scan uses top-ports).
    assert extend_web_ports_with_custom([80], [443], set()) == ([80], [443])
