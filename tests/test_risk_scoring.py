"""Unit tests for risk scoring (mvp-1)."""

from __future__ import annotations

import json
from pathlib import Path

from api.services.risk_scoring import RiskScoring, reset_scorer_for_tests


def test_prefers_cvss4_over_cvss():
    scorer = RiskScoring()
    assert scorer.base_cvss({"cvss": 5.0, "cvss4": 9.8}) == 9.8
    assert scorer.base_cvss({"cvss": 7.5}) == 7.5


def test_cisa_decision_bands():
    scorer = RiskScoring(epss={"CVE-1": 0.2}, kev={"CVE-KEV"})
    assert (
        scorer.cisa_decision(base_cvss=9.5, epss=0.0, exploit_active=0) == "Act"
    )
    assert (
        scorer.cisa_decision(base_cvss=8.0, epss=0.0, exploit_active=1) == "Immediate"
    )
    assert (
        scorer.cisa_decision(base_cvss=5.0, epss=0.0, exploit_active=0) == "Attend"
    )
    assert (
        scorer.cisa_decision(base_cvss=1.0, epss=0.0, exploit_active=0) == "Track"
    )


def test_score_log4shell_with_overlays():
    scorer = RiskScoring(epss={"CVE-2021-44228": 0.97}, kev={"CVE-2021-44228"})
    scored = scorer.score_vulnerability(
        {
            "cve": "CVE-2021-44228",
            "cvss4": 10.0,
            "severity": "critical",
            "port": "8080",
        }
    )
    assert scored["base_cvss"] == 10.0
    assert scored["epss_score"] == 0.97
    assert scored["exploit_active"] == 1
    assert scored["asset_criticality"] == 4
    assert scored["cisa_decision"] == "Immediate"
    assert scored["contextual_score"] > 8.0
    assert scored["scoring_model_version"] == "mvp-1"


def test_high_value_port_raises_criticality():
    scorer = RiskScoring()
    scored = scorer.score_vulnerability(
        {"cve": "CVE-2018-15473", "cvss": 5.3, "severity": "medium", "port": "22"}
    )
    assert scored["asset_criticality"] >= 2


def test_overlay_loaders(tmp_path: Path):
    epss = tmp_path / "epss.json"
    epss.write_text(json.dumps({"entries": {"CVE-1": 0.5}}), encoding="utf-8")
    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({"entries": ["CVE-1"]}), encoding="utf-8")
    from api.services import risk_scoring as rs

    scorer = RiskScoring(epss=rs._load_cve_float_map(epss), kev=rs._load_kev_set(kev))
    assert scorer.epss_score("cve-1") == 0.5
    assert scorer.exploit_active("CVE-1") == 1
    reset_scorer_for_tests(None)
