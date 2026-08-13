"""Unit tests for risk scoring (nist-1)."""

from __future__ import annotations

import json
import os
import time
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
    assert (
        scorer.cisa_decision(base_cvss=3.0, epss=0.0, exploit_active=1) == "Act"
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
    assert scored["scoring_model_version"] == "nist-1"


def test_high_value_port_raises_criticality():
    scorer = RiskScoring()
    scored = scorer.score_vulnerability(
        {"cve": "CVE-2018-15473", "cvss": 5.3, "severity": "medium", "port": "22"}
    )
    assert scored["asset_criticality"] >= 2


def test_asset_criticality_override_wins_over_heuristic():
    scorer = RiskScoring()
    item = {"cve": "CVE-2018-15473", "cvss": 5.3, "severity": "medium", "port": "22"}
    # Without an override, the high-value-port heuristic would score >= 2.
    heuristic_only = scorer.score_vulnerability(item)
    assert heuristic_only["asset_criticality"] >= 2

    # An explicit business-context override of 0 wins outright.
    overridden = scorer.score_vulnerability(item, asset_criticality_override=0)
    assert overridden["asset_criticality"] == 0


def test_asset_criticality_override_clamped_to_0_4():
    scorer = RiskScoring()
    assert scorer.asset_criticality({}, 0.0, override=7) == 4
    assert scorer.asset_criticality({}, 0.0, override=-3) == 0
    assert scorer.asset_criticality({}, 0.0, override=2) == 2


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


def test_get_scorer_hot_reloads_on_mtime_change(tmp_path: Path, monkeypatch):
    """A refresh CronJob rewrites the overlay files on a shared volume; every
    replica's in-process scorer must pick up the change without a restart,
    but only after the TTL elapses (not on every call)."""
    from api.services import risk_scoring as rs

    # Set mtimes explicitly rather than relying on wall-clock deltas — some
    # filesystems (seen on CI) round mtime to whole seconds, so two writes a
    # few milliseconds apart can hash to the identical stat and never trip
    # the "did it change" check.
    base_time = 1_700_000_000.0
    reload_seconds = 1000
    epss = tmp_path / "epss.json"
    kev = tmp_path / "kev.json"
    epss.write_text(json.dumps({"entries": {"CVE-1": 0.1}}), encoding="utf-8")
    kev.write_text(json.dumps({"entries": []}), encoding="utf-8")
    os.utime(epss, (base_time, base_time))
    os.utime(kev, (base_time, base_time))
    monkeypatch.setenv("OCTO_EPSS_DATABASE", str(epss))
    monkeypatch.setenv("OCTO_KEV_DATABASE", str(kev))
    monkeypatch.setenv("OCTO_ENRICHMENT_RELOAD_SECONDS", str(reload_seconds))
    reset_scorer_for_tests(None)
    try:
        first = rs.get_scorer()
        assert first.epss_score("CVE-1") == 0.1

        epss.write_text(json.dumps({"entries": {"CVE-1": 0.9}}), encoding="utf-8")
        os.utime(epss, (base_time + 10, base_time + 10))

        # Still within the TTL window — must not re-read the file yet.
        assert rs.get_scorer().epss_score("CVE-1") == 0.1

        # Force the TTL gate open, relative to time.monotonic()'s own (platform-
        # defined, possibly small) epoch — NOT an absolute 0.0. monotonic()'s
        # reference point is arbitrary (e.g. CLOCK_MONOTONIC since boot on
        # Linux), so on a freshly booted CI container "now" itself can be
        # smaller than reload_seconds, making `now - 0.0 < reload_seconds`
        # true and leaving the gate closed — exactly what broke this test on
        # GitHub Actions after it passed locally.
        rs._SCORER_CHECKED_AT = time.monotonic() - (reload_seconds + 10)
        reloaded = rs.get_scorer()
        assert reloaded.epss_score("CVE-1") == 0.9
        assert reloaded is not first
    finally:
        reset_scorer_for_tests(None)


# --- scanner-supplied enrichment and confidence (nist-1) -------------------------


def test_scanner_epss_and_kev_beat_the_local_overlays():
    """Pulse ships real EPSS/KEV per finding; the committed overlays are seed
    stubs, so a finding that carries its own data must not be scored from an
    empty overlay."""
    scorer = RiskScoring()  # no overlays at all
    scored = scorer.score_vulnerability(
        {
            "cve": "CVE-2021-44228",
            "cvss4": 10.0,
            "severity": "critical",
            "port": "8080",
            "finding_class": "version_cve",
            "confidence": 90,
            "epss": 0.97,
            "in_kev": True,
        }
    )
    assert scored["epss_score"] == 0.97
    assert scored["exploit_active"] == 1
    assert scored["cisa_decision"] == "Immediate"
    assert "EPSS 0.970 (scanner)" in scored["risk_explanation"]
    assert "exploited in the wild" in scored["risk_explanation"]
    assert "cisa-kev(scanner)" in scored["risk_explanation"]


def test_overlay_still_used_when_the_finding_carries_nothing():
    scorer = RiskScoring(epss={"CVE-1": 0.5}, kev={"CVE-1"})
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss": 8.0, "severity": "high"})
    assert scored["epss_score"] == 0.5
    assert scored["exploit_active"] == 1
    assert "EPSS 0.500 (overlay)" in scored["risk_explanation"]


def test_unconfirmed_finding_is_discounted_and_capped_below_act():
    """An unverified keyword hit must not outrank a confirmed match or reach a
    decision that would page someone (GenDec docs/findings.md)."""
    scorer = RiskScoring()
    item = {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "critical",
        "port": "3389",
        "confidence": 40,
        "requires_confirmation": True,
        "finding_class": "keyword_cve",
    }
    unconfirmed = scorer.score_vulnerability(item)
    confirmed = scorer.score_vulnerability(
        {**item, "requires_confirmation": False, "finding_class": "version_cve", "confidence": 90}
    )

    assert confirmed["cisa_decision"] == "Act"
    assert unconfirmed["cisa_decision"] == "Attend"
    assert unconfirmed["contextual_score"] < confirmed["contextual_score"]
    assert "unconfirmed keyword_cve, scanner confidence 40%" in unconfirmed["risk_explanation"]
    assert "capped at Attend" in unconfirmed["risk_explanation"]


def test_exposure_finding_is_scored_without_a_cve():
    scorer = RiskScoring()
    scored = scorer.score_vulnerability(
        {
            "cve": "",
            "script_id": "pulse:exposure:445:eternalblue-smbv1-rce",
            "cvss": 5.0,
            "severity": "medium",
            "port": "445",
            "finding_class": "exposure",
            "confidence": 45,
            "requires_confirmation": True,
        }
    )
    assert scored["contextual_score"] > 0
    assert scored["cisa_decision"] in ("Track", "Attend")
    assert "unconfirmed exposure" in scored["risk_explanation"]


def test_confirmed_finding_explains_without_a_confidence_note():
    scorer = RiskScoring()
    scored = scorer.score_vulnerability(
        {"cve": "CVE-1", "cvss": 7.5, "severity": "high", "port": "443"}
    )
    explanation = scored["risk_explanation"]
    # Leads with the verdict, not the inputs: the reader is deciding whether to
    # act, and "Moderate risk = likelihood x impact" answers that before the
    # supporting numbers do.
    assert explanation.startswith("Moderate risk (NIST SP 800-30)")
    assert "CVSS 7.5" in explanation
    assert "asset criticality" in explanation
    assert "unconfirmed" not in explanation


def test_explanation_names_the_criticality_source():
    scorer = RiskScoring()
    item = {"cve": "CVE-1", "cvss": 7.5, "severity": "high", "port": "443"}
    assert "(heuristic)" in scorer.score_vulnerability(item)["risk_explanation"]
    overridden = scorer.score_vulnerability(item, asset_criticality_override=4)
    assert "asset criticality 4/4 (operator-set)" in overridden["risk_explanation"]
