"""Phase 4.2: vulnerability merge/dedupe across Pulse + Nuclei + NSE."""

from __future__ import annotations

from scanner.pipeline.report import _dedupe_vulnerabilities
from scanner.pipeline.service_schema import CveRecord, cves_to_extra_vulnerabilities


def test_dedupe_keeps_first_host_port_cve():
    rows = [
        {"host": "10.0.0.1", "port": "22", "cve": "CVE-2023-0001", "source": "pulse", "cvss": 7.5, "severity": "high"},
        {"host": "10.0.0.1", "port": "22", "cve": "cve-2023-0001", "source": "nuclei", "cvss": 9.0, "severity": "critical"},
        {"host": "10.0.0.1", "port": "443", "cve": "CVE-2023-0001", "source": "nuclei", "cvss": 5.0, "severity": "medium"},
    ]
    out = _dedupe_vulnerabilities(rows)
    assert len(out) == 2
    assert out[0]["source"] == "pulse"
    assert out[1]["port"] == "443"


def test_dedupe_non_cve_uses_script_id():
    rows = [
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "http-vuln-x", "severity": "unknown"},
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "http-vuln-x", "severity": "unknown"},
        {"host": "10.0.0.1", "port": "80", "cve": None, "script_id": "other", "severity": "unknown"},
    ]
    assert len(_dedupe_vulnerabilities(rows)) == 2


def test_pulse_cve_source_tag():
    rows = cves_to_extra_vulnerabilities(
        [
            CveRecord(
                cve_id="CVE-2024-1",
                ip="1.2.3.4",
                port=22,
                service="ssh",
                cvss=8.0,
                severity="HIGH",
                title="t",
                summary="s",
                match_reason="banner",
                source="local",
            )
        ]
    )
    assert rows[0]["source"] == "pulse"
    assert rows[0]["script_id"] == "pulse:local"


def test_default_nuclei_enabled():
    from pathlib import Path

    import yaml

    from scanner.pipeline.config_schema import NucleiConfig, load_config

    assert NucleiConfig().enabled is True
    cfg = load_config(yaml.safe_load(Path("scanner/config/default.yaml").read_text(encoding="utf-8")))
    assert cfg.nuclei.enabled is True
    assert cfg.service_probe.backend == "pulse"
    assert cfg.service_probe.pulse.cve is True
