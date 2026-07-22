from __future__ import annotations

import json
from pathlib import Path

import httpx

from scanner.pipeline.config_schema import FingerprintConfig
from scanner.pipeline.fingerprint import (
    _candidate_endpoints,
    _CDN_WAF_SIGNATURES,
    _CMS_FRAMEWORK_SIGNATURES,
    fingerprint_hosts_sync,
)


def test_fingerprint_disabled(tmp_path: Path):
    result = fingerprint_hosts_sync(
        ["10.0.0.1:80/tcp"], FingerprintConfig(enabled=False), tmp_path
    )
    assert result["skipped_reason"] == "fingerprint.disabled"
    assert (tmp_path / "fingerprint.json").exists()


def test_fingerprint_no_web_ports(tmp_path: Path):
    result = fingerprint_hosts_sync(
        ["10.0.0.1:22/tcp"], FingerprintConfig(enabled=True), tmp_path
    )
    assert result["skipped_reason"] == "no_web_ports"


def test_candidate_endpoints_filters_and_dedupes():
    open_ports = [
        "10.0.0.1:80/tcp",
        "10.0.0.1:80/tcp",  # duplicate
        "10.0.0.1:443/tcp",
        "10.0.0.2:22/tcp",  # not a web port
        "10.0.0.3:53/udp",  # udp, ignored
    ]
    candidates = _candidate_endpoints(open_ports, http_ports={80, 8080}, https_ports={443})
    assert candidates == [
        ("10.0.0.1", 80, "http"),
        ("10.0.0.1", 443, "https"),
    ]


def test_fingerprint_detects_cloudflare_and_wordpress(tmp_path: Path, monkeypatch):
    async def fake_fetch(client, url, timeout, max_bytes):
        headers = httpx.Headers(
            [
                ("Server", "cloudflare"),
                ("CF-RAY", "abc123"),
                ("Content-Type", "text/html"),
            ]
        )
        body = "<html><head></head><body>wp-content/themes/example</body></html>"
        return 200, headers, body

    monkeypatch.setattr("scanner.pipeline.fingerprint._fetch", fake_fetch)

    result = fingerprint_hosts_sync(
        ["203.0.113.10:443/tcp"],
        FingerprintConfig(enabled=True),
        tmp_path,
    )

    assert result["skipped_reason"] is None
    assert result["checked_count"] == 1
    finding = result["findings"][0]
    assert finding["http_status"] == 200
    assert finding["cdn_waf"] == ["cloudflare"]
    assert finding["cms_framework"] == ["wordpress"]

    saved = json.loads((tmp_path / "fingerprint.json").read_text(encoding="utf-8"))
    assert saved["findings"] == result["findings"]
    matches = (tmp_path / "fingerprint_matches.txt").read_text(encoding="utf-8").splitlines()
    assert matches == ["203.0.113.10:443:https:cloudflare,wordpress"]


def test_fingerprint_no_signal_omitted_from_matches_file(tmp_path: Path, monkeypatch):
    async def fake_fetch(client, url, timeout, max_bytes):
        return 200, httpx.Headers([("Server", "nginx")]), "<html>hello</html>"

    monkeypatch.setattr("scanner.pipeline.fingerprint._fetch", fake_fetch)

    result = fingerprint_hosts_sync(
        ["203.0.113.10:80/tcp"],
        FingerprintConfig(enabled=True),
        tmp_path,
    )

    assert result["findings"][0]["cdn_waf"] == []
    assert result["findings"][0]["cms_framework"] == []
    matches = (tmp_path / "fingerprint_matches.txt").read_text(encoding="utf-8").splitlines()
    assert matches == []


def test_fingerprint_fail_soft_on_request_error(tmp_path: Path, monkeypatch):
    async def failing_fetch(client, url, timeout, max_bytes):
        return None

    monkeypatch.setattr("scanner.pipeline.fingerprint._fetch", failing_fetch)

    result = fingerprint_hosts_sync(
        ["203.0.113.10:80/tcp"],
        FingerprintConfig(enabled=True),
        tmp_path,
    )

    finding = result["findings"][0]
    assert finding["error"] == "request_failed"
    assert finding["http_status"] is None
    assert finding["cdn_waf"] == []


def test_fingerprint_truncates_at_max_targets(tmp_path: Path, monkeypatch):
    async def fake_fetch(client, url, timeout, max_bytes):
        return 200, httpx.Headers([]), "<html></html>"

    monkeypatch.setattr("scanner.pipeline.fingerprint._fetch", fake_fetch)

    open_ports = [f"10.0.{i}.1:80/tcp" for i in range(5)]
    result = fingerprint_hosts_sync(
        open_ports,
        FingerprintConfig(enabled=True, max_targets=2),
        tmp_path,
    )

    assert result["targets_considered"] == 5
    assert result["truncated"] is True
    assert result["checked_count"] == 2


def test_signature_sets_are_non_empty_and_named():
    assert len(_CDN_WAF_SIGNATURES) >= 5
    assert len(_CMS_FRAMEWORK_SIGNATURES) >= 4
    names = [name for name, _ in _CDN_WAF_SIGNATURES] + [name for name, _ in _CMS_FRAMEWORK_SIGNATURES]
    assert len(names) == len(set(names))
