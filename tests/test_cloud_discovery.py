from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.cloud_discovery import (
    _azure_account_candidates,
    _bucket_candidates,
    _valid_azure_account_name,
    _valid_bucket_name,
    discover_cloud_buckets_sync,
)
from scanner.pipeline.config_schema import CloudDiscoveryConfig


def test_cloud_disabled(tmp_path: Path):
    result = discover_cloud_buckets_sync(["example.com"], CloudDiscoveryConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "cloud.disabled"
    assert (tmp_path / "cloud_discovery.json").exists()


def test_cloud_no_domains(tmp_path: Path):
    result = discover_cloud_buckets_sync([], CloudDiscoveryConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"


def test_cloud_discovers_public_and_private(tmp_path: Path, monkeypatch):
    async def fake_check_s3(client, name, timeout):
        if name == "acme":
            return {
                "provider": "s3",
                "name": "acme",
                "container": None,
                "url": f"https://{name}.s3.amazonaws.com/",
                "status": "public",
                "http_status": 200,
            }
        if name == "acme-backup":
            return {
                "provider": "s3",
                "name": "acme-backup",
                "container": None,
                "url": f"https://{name}.s3.amazonaws.com/",
                "status": "private",
                "http_status": 403,
            }
        return None

    async def fake_check_gcs(client, name, timeout):
        return None

    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_s3", fake_check_s3)
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_gcs", fake_check_gcs)

    result = discover_cloud_buckets_sync(
        ["acme.com"],
        CloudDiscoveryConfig(enabled=True, providers=["s3", "gcs"], max_candidates=50),
        tmp_path,
    )

    assert result["skipped_reason"] is None
    assert result["org_tokens"] == ["acme"]
    names = {f["name"] for f in result["findings"]}
    assert {"acme", "acme-backup"} <= names
    assert [f["name"] for f in result["public_findings"]] == ["acme"]

    saved = json.loads((tmp_path / "cloud_discovery.json").read_text(encoding="utf-8"))
    assert saved["public_findings"] == result["public_findings"]
    public_txt = (tmp_path / "cloud_discovery_public.txt").read_text(encoding="utf-8").splitlines()
    assert public_txt == ["s3:acme:https://acme.s3.amazonaws.com/"]


def test_cloud_truncates_at_max_candidates(tmp_path: Path, monkeypatch):
    async def always_none(client, name, timeout):
        return None

    monkeypatch.setattr(
        "scanner.pipeline.cloud_discovery._load_wordlist",
        lambda wordlist_file: [f"w{i}" for i in range(50)],
    )
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_s3", always_none)
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_gcs", always_none)

    result = discover_cloud_buckets_sync(
        ["acme.com"],
        CloudDiscoveryConfig(enabled=True, providers=["s3"], max_candidates=5),
        tmp_path,
    )

    assert result["truncated"] is True
    assert result["candidates_generated"] <= 5


def test_cloud_fail_soft_on_http_error(tmp_path: Path, monkeypatch):
    async def failing_check(client, name, timeout):
        return None

    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_s3", failing_check)
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_gcs", failing_check)

    result = discover_cloud_buckets_sync(
        ["acme.com"],
        CloudDiscoveryConfig(enabled=True, providers=["s3", "gcs"], max_candidates=20),
        tmp_path,
    )

    assert result["findings"] == []
    assert result["public_findings"] == []


def test_cloud_azure_two_step(tmp_path: Path, monkeypatch):
    async def fake_account(name, timeout):
        return name == "acme"

    async def fake_container(client, account, container, timeout):
        assert account == "acme"  # only called for the resolved account
        if container == "backup":
            return {
                "provider": "azure",
                "name": account,
                "container": container,
                "url": "https://acme.blob.core.windows.net/backup?restype=container",
                "status": "public",
                "http_status": 200,
            }
        return None

    monkeypatch.setattr(
        "scanner.pipeline.cloud_discovery._load_wordlist", lambda wordlist_file: ["backup", "data"]
    )
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_azure_account", fake_account)
    monkeypatch.setattr("scanner.pipeline.cloud_discovery._check_azure_container", fake_container)

    result = discover_cloud_buckets_sync(
        ["acme.com"],
        CloudDiscoveryConfig(enabled=True, providers=["azure"], max_candidates=20),
        tmp_path,
    )

    assert len(result["public_findings"]) == 1
    assert result["public_findings"][0]["name"] == "acme"
    assert result["public_findings"][0]["container"] == "backup"


def test_bucket_candidates_respect_naming_rules():
    assert _valid_bucket_name("ab") is False  # too short
    assert _valid_bucket_name("-abc") is False  # leading hyphen
    assert _valid_bucket_name("abc-def") is True
    assert _valid_azure_account_name("ab") is False
    assert _valid_azure_account_name("abc-def") is False  # hyphen not allowed
    assert _valid_azure_account_name("abcdef") is True

    bucket_names = _bucket_candidates(["acme"], ["backup"], max_candidates=10)
    assert all(_valid_bucket_name(n) for n in bucket_names)
    assert "acme" in bucket_names

    azure_names = _azure_account_candidates(["acme"], ["backup"], max_candidates=10)
    assert all(_valid_azure_account_name(n) for n in azure_names)
    assert all("-" not in n for n in azure_names)
