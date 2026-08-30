"""Unit tests for org_profile M3 security controls matrix (EPIC #182)."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import ControlsConfig
from scanner.pipeline.controls import (
    evaluate_controls,
    format_controls_markdown,
    nist_risk_level,
)


def test_absence_of_data_never_yields_ok(tmp_path: Path):
    """Invariant: When no stages have run and no artifacts exist on disk,
    every control must be 'not_checked', never 'ok'."""
    summary = evaluate_controls(tmp_path, ControlsConfig(enabled=True))

    assert summary["overall_verdict"] == "not_checked"
    assert summary["overall_risk"] == "unassessed"
    assert len(summary["controls"]) == 6

    for item in summary["controls"]:
        assert item["status"] == "not_checked"
        assert item["risk_level"] == "unassessed"
        assert item["coverage"]["checked"] == 0


def test_nist_risk_matrix_table_i2():
    """Verify Table I-2 mappings verbatim."""
    # High likelihood x High impact -> High
    assert nist_risk_level("high", "high") == "high"
    # Very High likelihood x Critical (Very High) impact -> Very High
    assert nist_risk_level("very_high", "critical") == "very_high"
    # Very Low likelihood x High impact -> Low (NIST SP 800-30 Table I-2 is asymmetric)
    assert nist_risk_level("very_low", "high") == "low"
    # Very Low likelihood x Very Low impact -> Very Low
    assert nist_risk_level("very_low", "very_low") == "very_low"
    # Moderate likelihood x Medium impact -> Moderate
    assert nist_risk_level("moderate", "medium") == "moderate"
    # Unassessed / missing likelihood
    assert nist_risk_level(None, "medium") == "unassessed"


def test_evaluate_controls_mixed_posture(tmp_path: Path):
    # 1. DNS hygiene with 0 findings across 2 domains
    (tmp_path / "dns_hygiene.json").write_text(
        json.dumps({
            "status": "ok",
            "findings": [],
            "domains": {
                "example.com": {"status": "ok"},
                "example.org": {"status": "ok"},
            },
        }),
        encoding="utf-8",
    )

    # 2. Mail posture with 1 high finding
    (tmp_path / "mail_posture.json").write_text(
        json.dumps({
            "status": "findings",
            "findings": [
                {
                    "kind": "spf_missing",
                    "severity": "high",
                    "domain": "example.com",
                    "detail": "No SPF record found",
                }
            ],
            "domains": {
                "example.com": {"status": "findings"},
            },
        }),
        encoding="utf-8",
    )

    # 3. TLS posture with 1 medium finding
    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "findings": [
                {
                    "kind": "cert_expiring_soon",
                    "severity": "medium",
                    "host": "example.com",
                    "detail": "Expires in 5 days",
                }
            ],
            "targets": ["example.com:443"],
        }),
        encoding="utf-8",
    )

    # 4. Fingerprint with clean targets
    (tmp_path / "fingerprint.json").write_text(
        json.dumps({
            "targets": ["https://example.com"],
            "matches": {},
            "findings": [],
        }),
        encoding="utf-8",
    )

    summary = evaluate_controls(tmp_path, ControlsConfig(enabled=True))

    controls_by_id = {c["control"]: c for c in summary["controls"]}

    # DNS should be ok
    assert controls_by_id["dns_structure"]["status"] == "ok"
    assert controls_by_id["dns_structure"]["risk_level"] == "very_low"

    # Mail should be fail (1 high finding)
    assert controls_by_id["mail_protection"]["status"] == "fail"
    assert controls_by_id["mail_protection"]["risk_level"] == "high"

    # TLS should be weak (1 medium finding)
    assert controls_by_id["tls_certificates"]["status"] == "weak"
    assert controls_by_id["tls_certificates"]["risk_level"] == "moderate"

    # Web technologies should be ok
    assert controls_by_id["web_technologies"]["status"] == "ok"

    # Open services and credential leaks were not run -> not_checked
    assert controls_by_id["open_services"]["status"] == "not_checked"
    assert controls_by_id["credential_leaks"]["status"] == "not_checked"

    # Overall verdict has at least one fail
    assert summary["overall_verdict"] == "fail"
    assert summary["overall_risk"] == "high"

    # Check controls.json written to disk
    assert (tmp_path / "controls.json").exists()


def test_format_controls_markdown(tmp_path: Path):
    summary = {
        "overall_verdict": "fail",
        "overall_risk": "high",
        "controls": [
            {
                "control": "dns_structure",
                "title": "DNS структура",
                "status": "ok",
                "impact": "medium",
                "risk_level": "very_low",
                "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "why": "All 2 domains passed",
            }
        ],
    }

    lines = format_controls_markdown(summary)
    text = "\n".join(lines)

    assert "## Security Controls Matrix (org_profile)" in text
    assert "DNS структура" in text
    assert "`OK`" in text
    assert "Very Low" in text
