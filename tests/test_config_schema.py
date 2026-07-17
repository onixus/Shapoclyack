from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.pipeline.config_schema import AppConfig, DiscoveryConfig, format_validation_error, load_config


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

    text = Path("k8s/octo-man/base/config/k8s.yaml").read_text(encoding="utf-8")
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
    assert cfg.runtime.nse_hosts_per_scan == 8
    assert cfg.ports.protocol == "tcp"
    assert cfg.ports.udp_probes is True


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
    assert cfg.defectdojo.product_name == "Octo-man"
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
