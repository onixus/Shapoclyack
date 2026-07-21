from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import BruteForceSubdomainConfig, CertificateTransparencyConfig
from scanner.pipeline.hostnames import (
    base_domains_from_fqdns,
    discover_ct_subdomains_sync,
)


def test_base_domains_from_fqdns():
    assert base_domains_from_fqdns(["a.b.example.com", "x.example.com", "other.org"]) == [
        "example.com",
        "other.org",
    ]


def test_ct_disabled(tmp_path: Path):
    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(enabled=False),
        tmp_path,
    )
    assert result["skipped_reason"] == "ct.disabled"


def test_ct_discovers_and_dedupes(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.hostnames.query_crtsh",
        lambda domain, timeout: [
            "www.example.com",
            "API.Example.com.",
            "*.wild.example.com",
            "www.example.com",
            "other.org",
        ],
    )
    monkeypatch.setattr(
        "scanner.pipeline.hostnames.query_certspotter",
        lambda domain, timeout: ["mail.example.com", "www.example.com"],
    )

    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(
            enabled=True,
            providers=["crtsh", "certspotter"],
            max_subdomains=100,
        ),
        tmp_path,
    )
    assert result["subdomains"] == [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
    ]
    assert (tmp_path / "ct_subdomains.txt").exists()
    saved = json.loads((tmp_path / "ct_subdomains.json").read_text(encoding="utf-8"))
    assert saved["subdomains"] == result["subdomains"]


def test_ct_respects_max_subdomains(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.hostnames.query_crtsh",
        lambda domain, timeout: [f"h{i}.example.com" for i in range(20)],
    )
    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(enabled=True, providers=["crtsh"], max_subdomains=5),
        tmp_path,
    )
    assert len(result["subdomains"]) == 5
    assert result.get("truncated") is True


def test_otx_provider_merges_into_subdomains(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "scanner.pipeline.hostnames.query_crtsh",
        lambda domain, timeout: ["www.example.com"],
    )
    monkeypatch.setattr(
        "scanner.pipeline.hostnames.query_otx_passive_dns",
        lambda domain, timeout: ["passive.example.com", "www.example.com"],
    )
    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(enabled=True, providers=["crtsh", "otx"], max_subdomains=100),
        tmp_path,
    )
    assert result["subdomains"] == ["www.example.com", "passive.example.com"]
    assert result["by_provider"]["otx:example.com"] == ["passive.example.com", "www.example.com"]


def test_brute_force_disabled_by_default(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.hostnames.query_crtsh", lambda domain, timeout: [])
    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(enabled=True, providers=["crtsh"]),
        tmp_path,
    )
    assert "brute_force:example.com" not in result["by_provider"]


def test_brute_force_merges_resolved_candidates(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("scanner.pipeline.hostnames.query_crtsh", lambda domain, timeout: [])
    monkeypatch.setattr(
        "scanner.pipeline.hostnames._load_wordlist",
        lambda wordlist_file: ["www", "mail", "doesnotexist"],
    )

    def fake_resolves(candidate: str, timeout: int) -> bool:
        return candidate in {"www.example.com", "mail.example.com"}

    monkeypatch.setattr("scanner.pipeline.hostnames._resolves", fake_resolves)

    result = discover_ct_subdomains_sync(
        ["example.com"],
        CertificateTransparencyConfig(
            enabled=True,
            providers=["crtsh"],
            brute_force=BruteForceSubdomainConfig(enabled=True, max_candidates=10, concurrency=5),
        ),
        tmp_path,
    )
    assert sorted(result["by_provider"]["brute_force:example.com"]) == [
        "mail.example.com",
        "www.example.com",
    ]
    assert set(result["subdomains"]) == {"www.example.com", "mail.example.com"}
