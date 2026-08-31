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

    # 3. TLS posture with 1 medium issue, in the shape tls_posture.py emits:
    # one record per endpoint, severities nested inside ``issues``.
    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "targets_considered": 1,
            "checked_count": 1,
            "findings": [
                {
                    "host": "example.com",
                    "port": "443",
                    "cert": {"san": "DNS:example.com"},
                    "cipher_versions": [],
                    "issues": [
                        {
                            "kind": "cert_expiring_soon",
                            "severity": "medium",
                            "detail": "Expires in 5 days",
                        }
                    ],
                    "source": "nmap-nse",
                }
            ],
            "truncated": False,
            "skipped_reason": None,
        }),
        encoding="utf-8",
    )

    # 4. Fingerprint with a clean endpoint (no version banners), in the shape
    # fingerprint.py emits: per-endpoint records with no severity of their own.
    (tmp_path / "fingerprint.json").write_text(
        json.dumps({
            "targets_considered": 1,
            "checked_count": 1,
            "findings": [
                {
                    "host": "example.com",
                    "port": 443,
                    "scheme": "https",
                    "url": "https://example.com",
                    "http_status": 200,
                    "server": "",
                    "x_powered_by": "",
                    "cdn_waf": [],
                    "cms_framework": [],
                    "error": None,
                }
            ],
            "truncated": False,
            "skipped_reason": None,
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


def test_tls_severity_read_from_nested_issues(tmp_path: Path):
    """An expired certificate is a *critical* issue nested inside the endpoint
    record; reading a top-level ``severity`` that tls_posture never writes would
    grade the control WEAK instead of FAIL."""
    (tmp_path / "tls_posture.json").write_text(
        json.dumps({
            "targets_considered": 2,
            "checked_count": 2,
            "findings": [
                {
                    "host": "a.example.com",
                    "port": "443",
                    "issues": [{"kind": "cert_expired", "severity": "critical", "days": -3}],
                },
                {"host": "b.example.com", "port": "443", "issues": []},
            ],
            "skipped_reason": None,
        }),
        encoding="utf-8",
    )

    summary = evaluate_controls(tmp_path, ControlsConfig(enabled=True))
    tls = {c["control"]: c for c in summary["controls"]}["tls_certificates"]

    assert tls["status"] == "fail"
    assert tls["findings_by_severity"]["critical"] == 1
    assert tls["findings_by_severity"]["medium"] == 0
    assert tls["coverage"] == {"checked": 2, "total": 2}


def test_web_technologies_clean_endpoints_are_ok(tmp_path: Path):
    """A fingerprinted endpoint is not itself a finding; only a disclosed
    product/version banner is."""
    (tmp_path / "fingerprint.json").write_text(
        json.dumps({
            "targets_considered": 2,
            "checked_count": 2,
            "findings": [
                {"host": "a.example.com", "port": 443, "server": "", "x_powered_by": ""},
                {"host": "b.example.com", "port": 443, "server": "", "x_powered_by": ""},
            ],
            "skipped_reason": None,
        }),
        encoding="utf-8",
    )

    web = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "web_technologies"
    ]
    assert web["status"] == "ok"
    assert web["coverage"] == {"checked": 2, "total": 2}
    assert sum(web["findings_by_severity"].values()) == 0


def test_web_technologies_flags_version_banner(tmp_path: Path):
    (tmp_path / "fingerprint.json").write_text(
        json.dumps({
            "targets_considered": 1,
            "checked_count": 1,
            "findings": [
                {
                    "host": "a.example.com",
                    "port": 443,
                    "server": "nginx/1.24.0",
                    "x_powered_by": "PHP",
                }
            ],
            "skipped_reason": None,
        }),
        encoding="utf-8",
    )

    web = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "web_technologies"
    ]
    assert web["status"] == "weak"
    assert web["findings_by_severity"]["medium"] == 1  # nginx/1.24.0
    assert web["findings_by_severity"]["low"] == 1  # bare "PHP"


def test_domain_monitor_findings_are_read_from_nested_sections(tmp_path: Path):
    """domain_monitor.json has no top-level ``findings``; typosquat and
    dangling-CNAME findings live under their own sections."""
    (tmp_path / "domain_monitor.json").write_text(
        json.dumps({
            "seed_domains": ["example.com"],
            "typosquat": {
                "candidates_checked": 40,
                "findings": [
                    {
                        "kind": "typosquat_resolving",
                        "severity": "high",
                        "candidate": "exampIe.com",
                        "detail": "Resolves to 203.0.113.7",
                    }
                ],
            },
            "dangling_cname": {
                "checked": 12,
                "findings": [
                    {"kind": "dangling_cname", "severity": "medium", "fqdn": "old.example.com"}
                ],
            },
            "skipped_reason": None,
        }),
        encoding="utf-8",
    )

    dns = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "dns_structure"
    ]
    assert dns["status"] == "fail"
    assert dns["findings_by_severity"]["high"] == 1
    assert dns["findings_by_severity"]["medium"] == 1


def test_open_services_summary_alone_is_not_a_scan(tmp_path: Path):
    """summary.json is written on every run by the report stage, so its presence
    is not evidence that services were ever scanned -- the absence invariant
    must still hold."""
    (tmp_path / "summary.json").write_text(
        json.dumps({
            "total_targets": 3,
            "alive_hosts": 3,
            "open_host_port_pairs": 0,
            "nmap_open_services": 0,
        }),
        encoding="utf-8",
    )

    services = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "open_services"
    ]
    assert services["status"] == "not_checked"
    assert services["evidence"] == []


def test_open_services_ok_when_ports_were_actually_scanned(tmp_path: Path):
    (tmp_path / "open_ports.txt").write_text("198.51.100.1:443\n", encoding="utf-8")
    (tmp_path / "summary.json").write_text(
        json.dumps({"total_targets": 1, "alive_hosts": 1, "open_host_port_pairs": 1}),
        encoding="utf-8",
    )
    (tmp_path / "vulnerabilities.json").write_text("[]", encoding="utf-8")

    services = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "open_services"
    ]
    assert services["status"] == "ok"
    assert "open_ports.txt" not in services["evidence"] or (tmp_path / "open_ports.txt").exists()


def test_open_services_evidence_never_cites_absent_file(tmp_path: Path):
    """With only a vuln artifact on disk the evidence list must not claim
    open_ports.txt, which was confirmed absent."""
    (tmp_path / "vulnerabilities.json").write_text("[]", encoding="utf-8")

    services = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "open_services"
    ]
    assert "open_ports.txt" not in services["evidence"]
    assert services["evidence"] == ["vulnerabilities.json"]


def test_credential_leaks_unanswered_domains_are_not_coverage(tmp_path: Path):
    """An unauthorized HIBP key returns not_checked per domain; the critical-impact
    control must not report 'ok -- 0 breaches' off the back of that."""
    (tmp_path / "credential_leaks.json").write_text(
        json.dumps({
            "status": "not_checked",
            "provider": "hibp",
            "checked_domains": 0,
            "attempted_domains": 2,
            "total_domains": 2,
            "breaches_count": 0,
            "domains": {
                "example.com": {"status": "not_checked", "reason": "unauthorized"},
                "example.org": {"status": "not_checked", "reason": "unauthorized"},
            },
            "findings": [],
        }),
        encoding="utf-8",
    )

    leaks = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "credential_leaks"
    ]
    assert leaks["status"] == "not_checked"
    assert leaks["coverage"]["checked"] == 0


def test_credential_leaks_partial_coverage_is_reported(tmp_path: Path):
    (tmp_path / "credential_leaks.json").write_text(
        json.dumps({
            "status": "partial",
            "provider": "hibp",
            "checked_domains": 1,
            "total_domains": 2,
            "breaches_count": 0,
            "domains": {
                "example.com": {"status": "ok", "breaches_count": 0},
                "example.org": {"status": "not_checked", "reason": "rate_limited"},
            },
            "findings": [],
        }),
        encoding="utf-8",
    )

    leaks = {c["control"]: c for c in evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]}[
        "credential_leaks"
    ]
    assert leaks["status"] == "ok"
    assert leaks["coverage"] == {"checked": 1, "total": 2}
    assert "not covered" in leaks["why"]
