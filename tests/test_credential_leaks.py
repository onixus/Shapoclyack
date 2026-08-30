"""Unit tests for corporate credential leaks module (org_profile M5, EPIC #182)."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import CredentialLeaksConfig
from scanner.pipeline.controls import evaluate_controls, ControlsConfig
from scanner.pipeline.credential_leaks import (
    BreachDetail,
    LeakReport,
    MockLeakProvider,
    check_credential_leaks,
    mask_email,
)


def test_mask_email():
    assert mask_email("john.doe@example.com") == "j***@example.com"
    assert mask_email("alice@corp.net") == "a***@corp.net"
    assert mask_email("@domain.com") == "***@domain.com"
    assert mask_email("plain-user") == "plain-user"
    assert mask_email("") == ""


def test_stage_disabled_yields_not_checked(tmp_path: Path):
    config = CredentialLeaksConfig(enabled=False)
    result = check_credential_leaks(["example.com"], config, tmp_path)

    assert result["status"] == "not_checked"
    assert result["skipped_reason"] == "stage_disabled"
    assert result["breaches_count"] == 0

    saved = json.loads((tmp_path / "credential_leaks.json").read_text(encoding="utf-8"))
    assert saved["status"] == "not_checked"


def test_missing_api_key_yields_not_checked(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OCTO_HIBP_API_KEY", raising=False)
    monkeypatch.delenv("HIBP_API_KEY", raising=False)

    config = CredentialLeaksConfig(enabled=True, provider="hibp", api_key="")
    result = check_credential_leaks(["example.com"], config, tmp_path)

    assert result["status"] == "not_checked"
    assert result["skipped_reason"] == "no_api_key"

    # Invariant: absence of key never yields ok
    assert result["status"] != "ok"


def test_breach_detection_and_masked_artifacts(tmp_path: Path):
    mock_breach = BreachDetail(
        name="CorpLeak2023",
        title="Corporate Leak 2023",
        domain="example.com",
        breach_date="2023-05-10",
        added_date="2023-06-01",
        pwn_count=1000,
        description="Compromised credentials from employee portal.",
        data_classes=["Email addresses", "Passwords"],
        has_passwords=True,
        accounts=["ceo@example.com", "admin@example.com"],
    )

    provider = MockLeakProvider({
        "example.com": LeakReport(
            domain="example.com",
            status="fail",
            breaches=[mock_breach],
            total_accounts=2,
        )
    })

    config = CredentialLeaksConfig(enabled=True, provider="mock")
    result = check_credential_leaks(["example.com"], config, tmp_path, provider=provider)

    assert result["status"] == "fail"
    assert result["breaches_count"] == 1
    assert result["accounts_count"] == 2
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "critical"

    # Verify public artifact has masked identifiers
    public_file = tmp_path / "credential_leaks.json"
    assert public_file.exists()
    public_data = json.loads(public_file.read_text(encoding="utf-8"))
    b_data = public_data["domains"]["example.com"]["breaches"][0]
    assert b_data["masked_identifiers"] == ["c***@example.com", "a***@example.com"]
    assert "ceo@example.com" not in public_file.read_text(encoding="utf-8")

    # Verify restricted identifiers artifact has raw identifiers
    restricted_file = tmp_path / "credential_leaks_identifiers.json"
    assert restricted_file.exists()
    restricted_data = json.loads(restricted_file.read_text(encoding="utf-8"))
    assert restricted_data["domains"]["example.com"]["CorpLeak2023"] == ["ceo@example.com", "admin@example.com"]

    # Verify controls matrix integration
    controls_summary = evaluate_controls(tmp_path, ControlsConfig(enabled=True))
    c_map = {c["control"]: c for c in controls_summary["controls"]}
    assert c_map["credential_leaks"]["status"] == "fail"
    assert c_map["credential_leaks"]["risk_level"] in ("very_high", "high")
