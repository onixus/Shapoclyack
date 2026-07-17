from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import CertificateTransparencyConfig
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
