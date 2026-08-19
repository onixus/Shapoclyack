"""The NIST SP 800-30 model (nist-1) and exploit maturity (#144).

These tests are written as claims about *behaviour an operator relies on*,
not about arithmetic. The three that matter most:

* a severe vulnerability nobody has ever demonstrated must not outrank a
  moderate one being exploited right now;
* asset criticality must be able to change the verdict, in both directions;
* "no exploit-intelligence source configured" must never be reported as
  "no exploit exists".
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest

from api.services import nist_risk
from api.services.exploit_evidence import (
    ATTACKED,
    PROOF_OF_CONCEPT,
    THEORETICAL,
    UNKNOWN,
    UNPROVEN,
    WEAPONIZED,
    ExploitEvidence,
)
from api.services.risk_scoring import (
    ATTACK_PATH_RAISE,
    COMPENSATING_CONTROL_DISCOUNT,
    EXTERNAL,
    FOOTHOLD,
    INTERNAL,
    LOCAL,
    UNKNOWN_EXPOSURE,
    RiskScoring,
    apply_attack_path,
    apply_compensating_control,
    apply_criticality,
    apply_network_exposure,
    cve_age_raise,
    epss_pct,
    exploitability_pct,
    impact_pct,
    index_cdn_waf,
    path_role,
    resolve_compensating_control,
    resolve_cve_age,
    resolve_network_exposure,
)
from api.services.risk_scoring import _parse_vector as parse_vector

# A "worst case" v4 vector: network, low complexity, no privileges or
# interaction, full impact on all three of C/I/A.
V4_WORST = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
# Local access, high privileges, user interaction, limited impact.
V4_AWKWARD = "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
V3_WORST = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

# A populated overlay, so "absent from the overlay" means "no public exploit
# known" rather than "nothing was configured".
POPULATED = ExploitEvidence(overlay={"CVE-OTHER-1": (WEAPONIZED, ("metasploit",))})


def _scorer(**kwargs) -> RiskScoring:
    kwargs.setdefault("exploits", POPULATED)
    return RiskScoring(**kwargs)


# ---------------------------------------------------------------------------
# The Table I-2 transcription
# ---------------------------------------------------------------------------


def test_risk_matrix_is_asymmetric_as_the_standard_defines_it():
    """The asymmetry is the reason the table is transcribed, not computed."""
    # Certain, but nothing of value at stake.
    assert nist_risk.risk_level(nist_risk.VERY_HIGH, nist_risk.VERY_LOW) == nist_risk.VERY_LOW
    # Catastrophic, but essentially impossible.
    assert nist_risk.risk_level(nist_risk.VERY_LOW, nist_risk.VERY_HIGH) == nist_risk.LOW
    assert nist_risk.risk_level(nist_risk.VERY_HIGH, nist_risk.VERY_HIGH) == nist_risk.VERY_HIGH
    assert nist_risk.risk_level(nist_risk.MODERATE, nist_risk.HIGH) == nist_risk.MODERATE


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (100, nist_risk.VERY_HIGH),
        (96, nist_risk.VERY_HIGH),
        (95, nist_risk.HIGH),
        (80, nist_risk.HIGH),
        (79, nist_risk.MODERATE),
        (21, nist_risk.MODERATE),
        (20, nist_risk.LOW),
        (5, nist_risk.LOW),
        (4, nist_risk.VERY_LOW),
        (0, nist_risk.VERY_LOW),
    ],
)
def test_semi_quantitative_bands_match_table_d2(score, expected):
    assert nist_risk.level_for(score) == expected


# ---------------------------------------------------------------------------
# CVSS vector → the two axes
# ---------------------------------------------------------------------------


def test_vector_parsing_drops_not_defined_metrics():
    parsed = parse_vector("CVSS:4.0/AV:N/AC:L/E:X/CR:X")
    assert parsed["AV"] == "N"
    assert "E" not in parsed  # X means "not defined", i.e. no information


def test_malformed_vector_degrades_instead_of_raising():
    assert parse_vector("not a vector at all") == {}
    assert parse_vector("") == {}


def test_exploitability_separates_reachable_from_awkward():
    reachable, source = exploitability_pct(parse_vector(V4_WORST), 10.0)
    awkward, _ = exploitability_pct(parse_vector(V4_AWKWARD), 10.0)
    assert source == "cvss-vector"
    assert reachable == 100.0
    assert awkward < 20.0


def test_v3_vector_is_not_penalised_for_lacking_attack_requirements():
    """AT is v4-only; treating its absence as 'requirements exist' would make
    every v3 finding look harder to exploit than its v4 equivalent."""
    v3, _ = exploitability_pct(parse_vector(V3_WORST), 10.0)
    v4, _ = exploitability_pct(parse_vector(V4_WORST), 10.0)
    assert v3 == v4 == 100.0


def test_missing_vector_falls_back_to_the_score_and_says_so():
    value, source = exploitability_pct({}, 10.0)
    assert source == "cvss-score"
    # Compressed toward the middle: an unknown vector is not evidence of easy
    # exploitation, so a perfect CVSS must not imply perfect reachability.
    assert value < 100.0


def test_impact_reads_v4_and_v3_metric_names():
    assert impact_pct(parse_vector(V4_WORST), 0.0)[0] == 100.0
    assert impact_pct(parse_vector(V3_WORST), 0.0)[0] == 100.0
    assert impact_pct(parse_vector(V4_AWKWARD), 0.0)[0] < 40.0


def test_epss_scaling_is_not_linear():
    """EPSS is extremely skewed; a linear rescale would flatten every real
    finding to nearly zero."""
    assert epss_pct(0.0005) < 1.0
    assert epss_pct(0.1) == pytest.approx(20.0)
    assert epss_pct(0.5) == 100.0
    assert epss_pct(0.99) == 100.0  # saturates rather than overflowing


# ---------------------------------------------------------------------------
# Asset criticality — the user-visible ask
# ---------------------------------------------------------------------------


def test_criticality_two_is_neutral():
    """An installation that never sets criticality gets the pure technical
    assessment, not a silent penalty."""
    assert apply_criticality(50.0, 2) == 50.0


def test_criticality_moves_impact_in_both_directions():
    assert apply_criticality(50.0, 4) == 70.0
    assert apply_criticality(50.0, 0) == 30.0


def test_criticality_changes_the_verdict_not_just_the_number():
    """The mvp-2 failure this replaces: criticality was worth 0.5 of 10 points,
    so it could never move a finding between levels."""
    scorer = _scorer(kev={"CVE-KEV-1"})
    item = {"cve": "CVE-KEV-1", "cvss4": 9.8, "cvss4_vector": V4_WORST}

    crown_jewel = scorer.score_vulnerability(item, asset_criticality_override=4)
    lab_box = scorer.score_vulnerability(item, asset_criticality_override=0)

    assert crown_jewel["risk_level"] == nist_risk.VERY_HIGH
    assert lab_box["risk_level"] != crown_jewel["risk_level"]
    assert crown_jewel["contextual_score"] > lab_box["contextual_score"]


def test_criticality_appears_in_the_explanation_with_its_direction():
    scorer = _scorer()
    # Mid-range impact metrics, so the shift has room to show. Against a vector
    # already at 100 the clamp applies and the explanation says "no shift",
    # which is the honest report rather than a claimed increase that did not
    # happen — asserted separately below.
    mid = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N"
    raised = scorer.score_vulnerability(
        {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": mid}, asset_criticality_override=4
    )
    lowered = scorer.score_vulnerability(
        {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": mid}, asset_criticality_override=0
    )

    assert "asset criticality 4/4 (operator-set) raised it" in raised["risk_explanation"]
    assert "asset criticality 0/4 (operator-set) lowered it" in lowered["risk_explanation"]


def test_criticality_at_the_impact_ceiling_reports_no_shift_rather_than_a_fake_one():
    scorer = _scorer()
    scored = scorer.score_vulnerability(
        {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": V4_WORST}, asset_criticality_override=4
    )
    assert "no shift" in scored["risk_explanation"]


# ---------------------------------------------------------------------------
# Exploit maturity — PoC or theory
# ---------------------------------------------------------------------------


def test_kev_is_attacked_and_reaches_very_high_likelihood():
    scorer = _scorer(kev={"CVE-KEV-1"})
    scored = scorer.score_vulnerability({"cve": "CVE-KEV-1", "cvss4": 9.8, "cvss4_vector": V4_WORST})
    assert scored["exploit_maturity"] == ATTACKED
    assert scored["likelihood"] == nist_risk.VERY_HIGH
    assert any("cisa-kev" in source for source in scored["exploit_evidence"])


def test_theoretical_finding_cannot_outrank_an_exploited_one():
    """The headline correction over mvp-2, where CVSS dominated the sum."""
    scorer = _scorer(kev={"CVE-EXPLOITED"}, epss={"CVE-EXPLOITED": 0.4})

    theoretical = scorer.score_vulnerability(
        {"cve": "CVE-THEORY", "cvss4": 10.0, "cvss4_vector": V4_WORST},
        asset_criticality_override=2,
    )
    exploited = scorer.score_vulnerability(
        # Deliberately milder: lower CVSS, weaker impact metrics.
        {"cve": "CVE-EXPLOITED", "cvss4": 5.0, "cvss4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N"},
        asset_criticality_override=2,
    )

    assert theoretical["exploit_maturity"] == THEORETICAL
    assert exploited["exploit_maturity"] == ATTACKED
    assert exploited["contextual_score"] > theoretical["contextual_score"]


def test_theoretical_is_capped_below_high_likelihood_despite_a_perfect_vector():
    scorer = _scorer()
    scored = scorer.score_vulnerability({"cve": "CVE-THEORY", "cvss4": 10.0, "cvss4_vector": V4_WORST})
    assert scored["likelihood"] in (nist_risk.VERY_LOW, nist_risk.LOW)


def test_a_matched_nuclei_template_is_proof_of_concept_verified_on_host():
    """A template that fired here is evidence about this finding, not about the
    CVE in the abstract."""
    scorer = _scorer()
    scored = scorer.score_vulnerability(
        {"cve": "CVE-1", "cvss4": 6.5, "cvss4_vector": V4_WORST, "template_id": "CVE-1"}
    )
    assert scored["exploit_maturity"] == PROOF_OF_CONCEPT
    assert scored["exploit_verified_on_host"] is True
    assert "nuclei-match" in scored["exploit_evidence"]


def test_corpus_only_template_is_labelled_differently_from_a_match():
    """A template's existence is weaker evidence than a template firing, and the
    two must be distinguishable by the reader."""
    scorer = RiskScoring(exploits=ExploitEvidence(nuclei_cves=frozenset({"CVE-1"})))
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss4": 6.5, "cvss4_vector": V4_WORST})
    assert scored["exploit_maturity"] == PROOF_OF_CONCEPT
    assert scored["exploit_evidence"] == ["nuclei-corpus"]
    assert scored["exploit_verified_on_host"] is False


def test_overlay_weaponized_outranks_a_proof_of_concept():
    scorer = RiskScoring(
        exploits=ExploitEvidence(
            overlay={"CVE-1": (WEAPONIZED, ("metasploit",))}, nuclei_cves=frozenset({"CVE-1"})
        )
    )
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss4": 6.5, "cvss4_vector": V4_WORST})
    assert scored["exploit_maturity"] == WEAPONIZED
    # Every source is kept, not just the winning one.
    assert set(scored["exploit_evidence"]) == {"metasploit", "nuclei-corpus"}


def test_high_epss_without_public_code_is_unproven_not_theoretical():
    scorer = _scorer(epss={"CVE-1": 0.35})
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": V4_WORST})
    assert scored["exploit_maturity"] == UNPROVEN


# ---------------------------------------------------------------------------
# Absence of evidence is not evidence of absence
# ---------------------------------------------------------------------------


def test_no_configured_source_reports_unknown_not_theoretical():
    """The dangerous failure mode: an un-enriched install rating its whole
    estate Low and calling that a clean bill of health."""
    scorer = RiskScoring(exploits=ExploitEvidence())  # nothing configured
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss4": 9.8, "cvss4_vector": V4_WORST})

    assert scored["exploit_maturity"] == UNKNOWN
    assert scored["exploit_evidence"] == ["no-exploit-source-configured"]
    # Not capped: the assessment falls back to reachability and EPSS rather
    # than pretending to a verdict it has no basis for.
    assert scored["risk_level"] in (nist_risk.HIGH, nist_risk.VERY_HIGH)
    assert "no exploit-intelligence source configured" in scored["risk_explanation"]


def test_populated_overlay_makes_absence_meaningful():
    """Same finding, same code path — the only difference is that a source
    exists and was silent about this CVE."""
    scorer = _scorer()
    scored = scorer.score_vulnerability({"cve": "CVE-1", "cvss4": 9.8, "cvss4_vector": V4_WORST})
    assert scored["exploit_maturity"] == THEORETICAL
    assert scored["risk_level"] in (nist_risk.VERY_LOW, nist_risk.LOW, nist_risk.MODERATE)


def test_kev_alone_does_not_count_as_a_source():
    """KEV can say 'yes exploited', never 'no exploit known', so it cannot make
    an absence meaningful."""
    assert ExploitEvidence().has_sources is False
    assert ExploitEvidence(nuclei_cves=frozenset({"CVE-X"})).has_sources is True


# ---------------------------------------------------------------------------
# Confidence, and backward compatibility
# ---------------------------------------------------------------------------


def test_unconfirmed_finding_is_discounted_even_when_kev_floors_it():
    """A hypothesis about an actively exploited CVE is still a hypothesis, so
    the discount has to survive the KEV floor rather than be erased by it."""
    scorer = _scorer(kev={"CVE-1"})
    base = {"cve": "CVE-1", "cvss4": 9.8, "cvss4_vector": V4_WORST}
    confirmed = scorer.score_vulnerability(base)
    unconfirmed = scorer.score_vulnerability(
        {**base, "finding_class": "keyword_cve", "confidence": 30, "requires_confirmation": True}
    )
    assert unconfirmed["likelihood_score"] < confirmed["likelihood_score"]
    assert unconfirmed["cisa_decision"] == "Attend"  # capped below Act


def test_every_mvp2_output_key_survives():
    """ClickHouse ingest and the UI read these by name; dropping one would be a
    silent column of nulls rather than an error."""
    scored = _scorer().score_vulnerability({"cve": "CVE-1", "cvss": 7.5})
    for key in (
        "base_cvss",
        "epss_score",
        "asset_criticality",
        "exploit_active",
        "cisa_decision",
        "contextual_score",
        "scoring_model_version",
        "risk_explanation",
    ):
        assert key in scored, key
    assert 0.0 <= scored["contextual_score"] <= 10.0


# ---------------------------------------------------------------------------
# Network exposure (#171) — this host, not the CVSS vector
# ---------------------------------------------------------------------------


def test_resolve_network_exposure_does_not_treat_a_public_ip_as_internet():
    """A routable address is not evidence the host is facing the internet."""
    assert resolve_network_exposure(host="8.8.8.8") == (UNKNOWN_EXPOSURE, "none")
    assert resolve_network_exposure(host="10.0.0.5") == (INTERNAL, "address-space")
    assert resolve_network_exposure(host="8.8.8.8", operator_exposure="internet") == (
        EXTERNAL,
        "operator-set",
    )
    assert resolve_network_exposure(host="8.8.8.8", operator_exposure="partner") == (
        UNKNOWN_EXPOSURE,
        "none",
    )
    assert resolve_network_exposure(host="10.0.0.5", explicit=EXTERNAL) == (EXTERNAL, "finding")


def test_same_finding_scores_differently_on_external_and_internal_hosts():
    scorer = _scorer()
    item = {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": V4_WORST}
    external = scorer.score_vulnerability({**item, "network_exposure": EXTERNAL})
    internal = scorer.score_vulnerability({**item, "network_exposure": INTERNAL})
    unknown = scorer.score_vulnerability(item)

    assert external["likelihood_score"] > unknown["likelihood_score"]
    assert internal["likelihood_score"] < unknown["likelihood_score"]
    assert external["likelihood"] != internal["likelihood"] or (
        external["likelihood_score"] != internal["likelihood_score"]
    )


def test_unknown_network_exposure_does_not_change_likelihood():
    scorer = _scorer()
    item = {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": V4_WORST}
    bare = scorer.score_vulnerability(item)
    marked = scorer.score_vulnerability({**item, "network_exposure": UNKNOWN_EXPOSURE})
    public = scorer.score_vulnerability({**item, "host": "8.8.8.8"})
    assert bare["likelihood_score"] == marked["likelihood_score"] == public["likelihood_score"]
    assert "network exposure unknown" in marked["risk_explanation"]


def test_network_exposure_explanation_names_the_source():
    scorer = _scorer()
    item = {"cve": "CVE-1", "cvss4": 7.0, "cvss4_vector": V4_WORST, "host": "10.1.2.3"}
    scored = scorer.score_vulnerability(item)
    assert scored["network_exposure"] == INTERNAL
    assert scored["network_exposure_source"] == "address-space"
    assert "network exposure internal (address-space) lowered likelihood" in scored["risk_explanation"]

    decided = scorer.score_vulnerability(
        {**item, "host": "8.8.8.8"}, operator_exposure="internet"
    )
    assert decided["network_exposure"] == EXTERNAL
    assert "network exposure external (operator-set) raised likelihood" in decided["risk_explanation"]


def test_apply_network_exposure_unknown_is_a_noop():
    assert apply_network_exposure(50.0, UNKNOWN_EXPOSURE) == 50.0
    assert apply_network_exposure(50.0, EXTERNAL) == 70.0
    assert apply_network_exposure(50.0, INTERNAL) == 30.0


# ---------------------------------------------------------------------------
# CVE age (#172) — raise-only, never a decay
# ---------------------------------------------------------------------------


def test_cve_age_raise_is_never_negative():
    assert cve_age_raise(None) == 0.0
    assert cve_age_raise(0.2) == 0.0
    assert cve_age_raise(2.0) == 4.0
    assert cve_age_raise(5.0) == 8.0
    assert cve_age_raise(20.0) == 12.0
    assert cve_age_raise(-3.0) == 0.0


def test_older_cve_is_not_scored_below_a_fresh_one_with_the_same_evidence():
    scorer = _scorer()
    item = {"cvss4": 7.0, "cvss4_vector": V4_WORST, "network_exposure": "unknown"}
    fresh = scorer.score_vulnerability({**item, "cve": "CVE-2026-0001", "cve_published": "2026-07-01"})
    old = scorer.score_vulnerability({**item, "cve": "CVE-2015-0001", "cve_published": "2015-01-15"})
    assert old["likelihood_score"] >= fresh["likelihood_score"]
    assert "raised likelihood" in old["risk_explanation"]
    assert "nvd-published" in old["risk_explanation"]


def test_cve_id_year_is_a_named_fallback_when_published_is_missing():
    years, source = resolve_cve_age(cve="CVE-2015-1234", published=None, now=datetime(2026, 8, 19, tzinfo=UTC))
    assert source == "cve-id"
    assert years == 11.0
    years_pub, source_pub = resolve_cve_age(
        cve="CVE-2015-1234", published="2015-03-01", now=datetime(2026, 8, 19, tzinfo=UTC)
    )
    assert source_pub == "nvd-published"
    assert years_pub > 10.0


def test_overlay_staleness_lists_only_old_present_files(tmp_path, monkeypatch):
    from api.services import risk_scoring as scoring

    fresh = tmp_path / "epss.json"
    fresh.write_text("{}", encoding="utf-8")
    missing = tmp_path / "nope.json"
    old = tmp_path / "exploit.json"
    old.write_text("{}", encoding="utf-8")
    os.utime(old, (0, 0))
    monkeypatch.setattr(
        scoring,
        "_overlay_paths",
        lambda: (fresh, missing, old),
    )
    stale = scoring.overlay_staleness()
    assert stale == [("exploit", stale[0][1])]
    assert stale[0][1] > scoring.ENRICHMENT_STALE_DAYS


# ---------------------------------------------------------------------------
# Compensating controls (#173) — observed on-path CDN/WAF, never "WAF = safe"
# ---------------------------------------------------------------------------


def test_index_cdn_waf_matches_the_same_host_port_only():
    index = index_cdn_waf(
        {
            "findings": [
                {"host": "8.8.8.8", "port": 443, "cdn_waf": ["cloudflare"], "cms_framework": ["wordpress"]},
                {"host": "8.8.8.8", "port": 80, "cdn_waf": [], "cms_framework": ["wordpress"]},
                {"host": "1.1.1.1", "port": 443, "cdn_waf": ["akamai"]},
            ]
        }
    )
    assert index[("8.8.8.8", 443)] == ("cloudflare",)
    assert ("8.8.8.8", 80) not in index
    assert index[("1.1.1.1", 443)] == ("akamai",)


def test_cms_alone_is_not_a_compensating_control():
    assert index_cdn_waf({"findings": [{"host": "8.8.8.8", "port": 443, "cms_framework": ["wordpress"]}]}) == {}
    assert resolve_compensating_control(cdn_waf=["wordpress"]) == ((), "none")


def test_unknown_cdn_waf_names_are_ignored():
    assert resolve_compensating_control(cdn_waf=["made-up-waf", "cloudflare"]) == (
        ("cloudflare",),
        "finding",
    )


def test_apply_compensating_control_is_one_discount_not_per_vendor():
    assert apply_compensating_control(50.0, ()) == 50.0
    assert apply_compensating_control(50.0, ("cloudflare",)) == 50.0 - COMPENSATING_CONTROL_DISCOUNT
    assert apply_compensating_control(50.0, ("cloudflare", "akamai")) == 50.0 - COMPENSATING_CONTROL_DISCOUNT


def test_on_path_waf_lowers_likelihood_and_is_named():
    scorer = _scorer()
    item = {
        "cve": "CVE-1",
        "cvss4": 7.0,
        "cvss4_vector": V4_WORST,
        "host": "8.8.8.8",
        "port": "443",
        "network_exposure": UNKNOWN_EXPOSURE,
    }
    bare = scorer.score_vulnerability(item)
    shielded = scorer.score_vulnerability({**item, "cdn_waf": ["cloudflare"]})
    other_port = scorer.score_vulnerability(
        item,
        cdn_waf_index={("8.8.8.8", 80): ("cloudflare",)},
    )
    on_path = scorer.score_vulnerability(
        item,
        cdn_waf_index={("8.8.8.8", 443): ("cloudflare",)},
    )

    assert shielded["likelihood_score"] == pytest.approx(
        bare["likelihood_score"] - COMPENSATING_CONTROL_DISCOUNT
    )
    assert on_path["likelihood_score"] == shielded["likelihood_score"]
    assert other_port["likelihood_score"] == bare["likelihood_score"]
    assert shielded["cdn_waf"] == ["cloudflare"]
    assert shielded["compensating_control_source"] == "finding"
    assert on_path["compensating_control_source"] == "fingerprint"
    assert "CDN/WAF cloudflare on this host:port (fingerprint)" in on_path["risk_explanation"]
    assert "not proof the vuln is blocked" in on_path["risk_explanation"]
    assert "CDN/WAF" not in bare["risk_explanation"]
    # A small named discount, not a qualitative "Cloudflare → minus a level" rule.
    assert shielded["likelihood"] == bare["likelihood"]


# ---------------------------------------------------------------------------
# Same-asset path (#173) — composition after P4.2, not a takeover model
# ---------------------------------------------------------------------------


def test_path_role_from_vector_and_exposure():
    assert path_role({"finding_class": "exposure"}) == FOOTHOLD
    assert path_role({"cvss4_vector": V4_WORST}) == FOOTHOLD
    assert path_role({"cvss4_vector": V4_AWKWARD}) == LOCAL
    assert path_role({"cvss4": 7.0}) == ""


def test_local_finding_is_raised_only_when_the_same_asset_has_a_foothold():
    scorer = _scorer()
    local = {
        "cve": "CVE-1",
        "cvss4": 7.0,
        "cvss4_vector": V4_AWKWARD,
        "network_exposure": UNKNOWN_EXPOSURE,
    }
    bare = scorer.score_vulnerability(local)
    chained = scorer.score_vulnerability(local, same_asset_foothold=True)
    assert chained["likelihood_score"] == pytest.approx(
        bare["likelihood_score"] + ATTACK_PATH_RAISE
    )
    assert chained["attack_path"] == "same-asset"
    assert "same-asset path" in chained["risk_explanation"]
    assert "not a modelled exploit chain" in chained["risk_explanation"]
    assert apply_attack_path(50.0, role=FOOTHOLD, has_foothold=True) == 50.0
    foothold = scorer.score_vulnerability(
        {"cve": "CVE-2", "cvss4": 7.0, "cvss4_vector": V4_WORST, "network_exposure": UNKNOWN_EXPOSURE},
        same_asset_foothold=True,
    )
    assert foothold["attack_path"] is None
    assert "same-asset path" not in foothold["risk_explanation"]
