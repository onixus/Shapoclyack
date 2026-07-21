from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.asn_discovery import discover_asn_ranges
from scanner.pipeline.config_schema import AsnDiscoveryConfig


def test_asn_disabled(tmp_path: Path):
    result = discover_asn_ranges(["example.com"], AsnDiscoveryConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "asn.disabled"
    assert (tmp_path / "asn_discovery.json").exists()


def test_asn_no_domains(tmp_path: Path):
    result = discover_asn_ranges([], AsnDiscoveryConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"


def test_asn_discovers_ranges(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._resolve_domain_ips",
        lambda domain, timeout: ["203.0.113.10"],
    )
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._lookup_asn_for_ip",
        lambda client, ip, timeout: "64500",
    )
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._announced_prefixes",
        lambda client, asn, timeout: ["203.0.113.0/24"],
    )

    result = discover_asn_ranges(
        ["example.com"], AsnDiscoveryConfig(enabled=True, max_total_ips=1000), tmp_path
    )

    assert result["skipped_reason"] is None
    assert result["seed_domains"] == ["example.com"]
    assert result["seed_ips"] == ["203.0.113.10"]
    assert result["asns"] == {"64500": {"prefixes": ["203.0.113.0/24"]}}
    assert result["ip_ranges"] == ["203.0.113.0/24"]
    assert result["truncated"] is False

    saved = json.loads((tmp_path / "asn_discovery.json").read_text(encoding="utf-8"))
    assert saved["ip_ranges"] == ["203.0.113.0/24"]
    ranges_txt = (tmp_path / "asn_ranges.txt").read_text(encoding="utf-8").splitlines()
    assert ranges_txt == ["203.0.113.0/24"]


def test_asn_truncates_at_max_total_ips(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._resolve_domain_ips",
        lambda domain, timeout: ["203.0.113.10"],
    )
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._lookup_asn_for_ip",
        lambda client, ip, timeout: "64500",
    )
    # A /16 (65536 IPs) blows past a small cap.
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._announced_prefixes",
        lambda client, asn, timeout: ["10.0.0.0/16"],
    )

    result = discover_asn_ranges(
        ["example.com"], AsnDiscoveryConfig(enabled=True, max_total_ips=100), tmp_path
    )

    assert result["truncated"] is True
    assert result["ip_ranges"] == []


def test_asn_skips_ip_lookup_failure(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._resolve_domain_ips",
        lambda domain, timeout: ["203.0.113.10"],
    )
    monkeypatch.setattr(
        "scanner.pipeline.asn_discovery._lookup_asn_for_ip",
        lambda client, ip, timeout: None,
    )
    result = discover_asn_ranges(["example.com"], AsnDiscoveryConfig(enabled=True), tmp_path)
    assert result["asns"] == {}
    assert result["ip_ranges"] == []
