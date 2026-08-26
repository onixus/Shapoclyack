"""Tenant-uploaded brute-force wordlists (Phase 8.2, UI-managed).

Covers the three layers the feature spans: the service's normalization and
tenant isolation, the HTTP upload/list/delete edge with its size and tenant
guards, and the scan-start wiring that turns a selected wordlist into a
job-scoped config override enabling the right brute-force stage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from api.schemas import StartScanRequest
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.services import wordlists
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    # Scans need an approved scan scope since #226; see tests/conftest.py.
    approve_scan_scope(s)
    wordlists.configure(s)
    return s


# --- service: normalization -------------------------------------------------


def test_normalize_matches_scanner_wordlist_shape():
    """Lowercased, trimmed, comments and blanks dropped, de-duplicated in
    first-seen order — the exact shape hostnames._load_wordlist expects."""
    body, count = wordlists.normalize(
        "WWW\n# a comment\n  api \n\nwww\nMail\n", max_words=100
    )
    assert body == "www\napi\nmail"
    assert count == 3


def test_normalize_rejects_empty():
    with pytest.raises(ValueError):
        wordlists.normalize("# only comments\n\n   \n", max_words=100)


def test_normalize_enforces_word_cap(settings: Settings):
    with pytest.raises(ValueError):
        wordlists.normalize("a\nb\nc\nd", max_words=3)


# --- service: CRUD + tenant isolation --------------------------------------


def test_create_stores_metadata_not_secrets(settings: Settings):
    info = wordlists.create_wordlist(
        tenant_id="default", name="subs", kind="subdomain", raw_content="www\napi\n"
    )
    assert info["line_count"] == 2
    assert info["sha256"]
    assert "content" not in info  # body never leaves the service in metadata


def test_reupload_same_name_updates_in_place(settings: Settings):
    first = wordlists.create_wordlist(
        tenant_id="default", name="subs", kind="subdomain", raw_content="www\n"
    )
    second = wordlists.create_wordlist(
        tenant_id="default", name="subs", kind="subdomain", raw_content="www\napi\ndev\n"
    )
    assert first["wordlist_id"] == second["wordlist_id"]
    assert second["line_count"] == 3
    assert len(wordlists.list_wordlists("default")) == 1


def test_get_for_scan_is_tenant_scoped(settings: Settings):
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    info = wordlists.create_wordlist(
        tenant_id="ten_a", name="subs", kind="subdomain", raw_content="www\napi\n"
    )
    # Right tenant sees body + provenance; a different tenant sees nothing.
    resolved = wordlists.get_for_scan(info["wordlist_id"], tenant_id="ten_a")
    assert resolved is not None
    assert resolved.kind == "subdomain"
    assert resolved.content == "www\napi"
    assert resolved.name == "subs"
    assert resolved.wordlist_id == info["wordlist_id"]
    assert wordlists.get_for_scan(info["wordlist_id"], tenant_id="default") is None


def test_unknown_kind_rejected(settings: Settings):
    with pytest.raises(ValueError):
        wordlists.create_wordlist(
            tenant_id="default", name="x", kind="not-a-kind", raw_content="a\n"
        )


# --- HTTP edge --------------------------------------------------------------


def test_upload_list_get_delete_roundtrip(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")

    created = client.post(
        "/api/wordlists",
        files={"file": ("subs.txt", b"www\napi\n# c\nwww\n")},
        data={"kind": "subdomain", "name": "my-subs"},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["name"] == "my-subs"
    assert body["line_count"] == 2  # deduped
    wid = body["wordlist_id"]

    listed = client.get("/api/wordlists", headers=headers)
    assert listed.status_code == 200
    assert [w["wordlist_id"] for w in listed.json()] == [wid]

    got = client.get(f"/api/wordlists/{wid}", headers=headers)
    assert got.status_code == 200 and got.json()["sha256"]

    deleted = client.delete(f"/api/wordlists/{wid}", headers=headers)
    assert deleted.status_code == 204
    assert client.get("/api/wordlists", headers=headers).json() == []


def test_upload_over_size_cap_is_413(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, wordlist_max_body_bytes=32)
    resp = client.post(
        "/api/wordlists",
        files={"file": ("big.txt", b"x" * 100)},
        data={"kind": "subdomain"},
        headers=auth_headers(client, "operator"),
    )
    assert resp.status_code == 413


def test_upload_non_utf8_is_422(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/wordlists",
        files={"file": ("bin.txt", b"\xff\xfe\x00bad")},
        data={"kind": "subdomain", "name": "x"},
        headers=auth_headers(client, "operator"),
    )
    assert resp.status_code == 422


def test_viewer_cannot_upload(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    resp = client.post(
        "/api/wordlists",
        files={"file": ("subs.txt", b"www\n")},
        data={"kind": "subdomain", "name": "x"},
        headers=auth_headers(client, "viewer"),
    )
    assert resp.status_code == 403


def test_other_tenants_wordlist_is_404(tmp_path, monkeypatch):
    """A tenant-scoped user must not reach another tenant's wordlist by id.

    (A platform admin deliberately can — same cross-tenant view webhooks and
    schedules give one; the isolation guarantee is for tenant-confined users,
    which the default ``operator`` account is, confined to ``default``.)"""
    client = configured_client(tmp_path, monkeypatch)
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    created = client.post(
        "/api/wordlists?tenant_id=ten_a",
        files={"file": ("subs.txt", b"www\n")},
        data={"kind": "subdomain", "name": "x"},
        headers=auth_headers(client, "admin"),
    )
    assert created.status_code == 201, created.text
    wid = created.json()["wordlist_id"]
    # The operator is confined to the default tenant and cannot see ten_a's list.
    resp = client.get(f"/api/wordlists/{wid}", headers=auth_headers(client, "operator"))
    assert resp.status_code == 404


# --- scan-start wiring ------------------------------------------------------


class _FakeThread:
    """Stand-in so a local start_scan does not actually launch the scanner."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    def start(self) -> None:
        pass


def _config_path_from(job) -> Path:
    command = job.command
    return Path(command[command.index("--config") + 1])


def test_subdomain_wordlist_enables_brute_force_in_effective_config(settings, monkeypatch):
    monkeypatch.setattr("api.services.jobs.threading.Thread", _FakeThread)
    info = wordlists.create_wordlist(
        tenant_id="default", name="subs", kind="subdomain", raw_content="www\napi\n"
    )
    job = jobs_service.start_scan(
        settings,
        StartScanRequest(mode="balanced", wordlist_id=info["wordlist_id"]),
        username="admin",
    )
    cfg = yaml.safe_load(_config_path_from(job).read_text())
    assert cfg["discovery"]["ct"]["enabled"] is True
    assert cfg["discovery"]["ct"]["brute_force"]["enabled"] is True
    materialized = Path(cfg["discovery"]["ct"]["brute_force"]["wordlist_file"])
    assert materialized.read_text().split() == ["www", "api"]


def test_bucket_wordlist_enables_cloud_discovery(settings, monkeypatch):
    monkeypatch.setattr("api.services.jobs.threading.Thread", _FakeThread)
    info = wordlists.create_wordlist(
        tenant_id="default", name="buckets", kind="bucket", raw_content="assets\nbackup\n"
    )
    job = jobs_service.start_scan(
        settings,
        StartScanRequest(mode="balanced", wordlist_id=info["wordlist_id"]),
        username="admin",
    )
    cfg = yaml.safe_load(_config_path_from(job).read_text())
    assert cfg["discovery"]["cloud"]["enabled"] is True
    assert Path(cfg["discovery"]["cloud"]["wordlist_file"]).read_text().split() == ["assets", "backup"]


def test_unknown_wordlist_id_fails_the_scan(settings, monkeypatch):
    monkeypatch.setattr("api.services.jobs.threading.Thread", _FakeThread)
    with pytest.raises(ValueError):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", wordlist_id="does-not-exist"),
            username="admin",
        )


def test_wordlist_rejected_in_agent_mode(settings, monkeypatch):
    monkeypatch.setattr("api.services.jobs.threading.Thread", _FakeThread)
    settings.job_execution_mode = "agent"
    info = wordlists.create_wordlist(
        tenant_id="default", name="subs", kind="subdomain", raw_content="www\n"
    )
    with pytest.raises(ValueError, match="local execution"):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", wordlist_id=info["wordlist_id"]),
            username="admin",
        )
