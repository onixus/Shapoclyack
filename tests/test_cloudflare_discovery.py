from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.config_schema import CloudflareDiscoveryConfig
from scanner.pipeline.discover import import_cloudflare_dns_targets


def test_cloudflare_disabled_skips(tmp_path: Path):
    result = import_cloudflare_dns_targets(CloudflareDiscoveryConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "cloudflare.disabled"
    assert result["fqdns"] == []


def test_cloudflare_missing_token(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("OCTO_CLOUDFLARE_API_TOKEN", raising=False)
    result = import_cloudflare_dns_targets(
        CloudflareDiscoveryConfig(enabled=True, api_token=""),
        tmp_path,
    )
    assert "missing" in (result["skipped_reason"] or "")


def test_cloudflare_import_unproxied_finding(tmp_path: Path, monkeypatch):
    zones = [{"id": "zid1", "name": "example.com"}]
    records = [
        {
            "type": "A",
            "name": "origin.example.com",
            "content": "203.0.113.10",
            "proxied": False,
        },
        {
            "type": "A",
            "name": "www.example.com",
            "content": "203.0.113.20",
            "proxied": True,
        },
        {
            "type": "CNAME",
            "name": "app.example.com",
            "content": "www.example.com",
            "proxied": True,
        },
    ]

    monkeypatch.setattr(
        "scanner.pipeline.discover.list_cloudflare_zones",
        lambda token, timeout: zones,
    )
    monkeypatch.setattr(
        "scanner.pipeline.discover.list_cloudflare_dns_records",
        lambda zone_id, token, timeout: records,
    )

    result = import_cloudflare_dns_targets(
        CloudflareDiscoveryConfig(
            enabled=True,
            api_token="test-token",
            zones=["example.com"],
            flag_unproxied_a=True,
        ),
        tmp_path,
    )
    assert "origin.example.com" in result["fqdns"]
    assert "www.example.com" in result["fqdns"]
    assert "203.0.113.10" in result["ips"]
    assert any(f["finding"] == "unproxied_a_record" for f in result["misconfigurations"])
    assert (tmp_path / "cloudflare_dns.json").exists()
    assert (tmp_path / "cloudflare_misconfig.json").exists()
    saved = json.loads((tmp_path / "cloudflare_misconfig.json").read_text(encoding="utf-8"))
    assert len(saved["findings"]) == 1
