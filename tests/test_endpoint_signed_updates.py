"""A publisher envelope stays byte-bound and survives upload/heartbeat unchanged."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from api.services import endpoint_agent_mgmt as management
from tests.conftest import auth_headers, requires_postgres
from tests.test_endpoint_agent_management import (
    BUILD,
    PLATFORM,
    _agent_token,
    _envelope,
    _setup,
)


def _legacy_release():
    """Represent a row uploaded before the unsigned-release prohibition."""
    from api.db import models
    from api.db.engine import get_session
    from tests.conftest import POSTGRES_URL

    with get_session(POSTGRES_URL) as session:
        session.add(
            models.EndpointAgentRelease(
                version="0.5.0",
                platform=PLATFORM,
                package_kind="binary",
                sha256=hashlib.sha256(BUILD).hexdigest(),
                size_bytes=len(BUILD),
                content=BUILD,
                signed_manifest=None,
                uploaded_at=management._now(),
            )
        )


def _validate(envelope):
    return management.validate_signed_manifest(
        envelope,
        version="0.5.0",
        platform=PLATFORM,
        digest=hashlib.sha256(BUILD).hexdigest(),
        size_bytes=len(BUILD),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("version", "0.1.0"),
        ("platform", "different-platform"),
        ("sha256", "00" * 32),
        ("size_bytes", len(BUILD) + 1),
        ("size_bytes", True),
        ("sequence", -1),
        ("sequence", 2**64),
        ("expires_at", 0),
        ("schema", 2),
        ("package_kind", "binary"),
        ("package_kind", []),
        ("key_id", "../publisher"),
    ],
)
def test_invalid_or_unbound_manifest_is_rejected(field, value):
    with pytest.raises(management.ReleaseError):
        _validate(_envelope(**{field: value}))


def test_envelope_is_preserved_and_not_mutable_by_its_caller():
    envelope = _envelope()
    preserved = _validate(envelope)
    assert preserved == envelope
    envelope["manifest"]["sequence"] = 0
    assert preserved["manifest"]["sequence"] == 7
    with pytest.raises(management.ReleaseError):
        _validate({**preserved, "extra": "unsigned policy field"})
    with pytest.raises(management.ReleaseError):
        _validate({**preserved, "signature": "not-ed25519"})


@requires_postgres
def test_signed_upload_negotiation_and_heartbeat_preserve_envelope(
    tmp_path, monkeypatch
):
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "p0-agent")
    registered = client.post(
        "/api/agent/register",
        json=dict(
            agent_id="p0-agent",
            hostname="host",
            version="0.4.0",
            agent_kind="endpoint",
            capabilities=["signed_updates"],
        ),
        headers=headers,
    )
    assert registered.json()["inventory_schema_version"] == 2
    admin = auth_headers(client, username="admin")
    _legacy_release()
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    beat = client.post(
        "/api/agent/heartbeat",
        json=dict(agent_id="p0-agent", platform=PLATFORM),
        headers=headers,
    )
    assert beat.status_code == 200
    assert beat.json()["managed_update"] is None
    assert "requires a signed" in beat.json()["managed_update_blocked"]

    envelope = _envelope()
    uploaded = client.post(
        "/api/endpoint/agent/releases",
        headers=admin,
        data=dict(
            version="0.5.0", platform=PLATFORM, signed_manifest=json.dumps(envelope)
        ),
        files={"binary": ("lariska.msi", BUILD, "application/octet-stream")},
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["signed_manifest"] == envelope
    beat = client.post(
        "/api/agent/heartbeat",
        json=dict(agent_id="p0-agent", platform=PLATFORM),
        headers=headers,
    ).json()
    assert beat["inventory_schema_version"] == 2
    assert beat["managed_update"]["signed_manifest"] == envelope
    downloaded = client.get(beat["managed_update"]["url"], headers=headers)
    assert downloaded.content == BUILD

    mismatch = copy.deepcopy(envelope)
    mismatch["manifest"]["size_bytes"] += 1
    refused = client.post(
        "/api/endpoint/agent/releases",
        headers=admin,
        data=dict(
            version="0.5.0", platform=PLATFORM, signed_manifest=json.dumps(mismatch)
        ),
        files={"binary": ("lariska.msi", BUILD, "application/octet-stream")},
    )
    assert refused.status_code == 422
    assert management.list_releases()[0]["signed_manifest"] == envelope


@requires_postgres
def test_unsigned_legacy_fleet_and_signed_replacement_policy(tmp_path, monkeypatch):
    _, _, _ = _setup(tmp_path, monkeypatch)
    _legacy_release()
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    legacy = management.plan_for_agent(
        tenant_id="acme", agent_id="old", current_version="0.4.0", platform=PLATFORM
    )
    assert legacy.update is None
    assert "unsigned executable updates are disabled" in legacy.update_blocked
    management.store_release(
        version="0.5.0", platform=PLATFORM, content=BUILD, signed_manifest=_envelope()
    )
    with pytest.raises(management.ReleaseError, match="unsigned"):
        management.store_release(version="0.5.0", platform=PLATFORM, content=BUILD)
    with pytest.raises(management.ReleaseError, match="backwards"):
        management.store_release(
            version="0.5.0",
            platform=PLATFORM,
            content=BUILD,
            signed_manifest=_envelope(sequence=6),
        )
    changed = BUILD + b"different"
    with pytest.raises(management.ReleaseError, match="newer"):
        management.store_release(
            version="0.5.0",
            platform=PLATFORM,
            content=changed,
            signed_manifest=_envelope(changed),
        )


def test_cross_repository_manifest_canonicalization_and_real_signature():
    from pathlib import Path
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    fixture = json.loads((Path(__file__).parent / "fixtures/endpoint_signed_manifest_v1.json").read_text())
    envelope = fixture["signed_manifest"]
    manifest = envelope["manifest"]
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert canonical == fixture["canonical_utf8"]
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(fixture["public_key"])).verify(
        bytes.fromhex(envelope["signature"]), canonical.encode("utf-8"))
    validated = management.validate_signed_manifest(envelope, version=manifest["version"],
        platform=manifest["platform"], digest=hashlib.sha256(b"package").hexdigest(), size_bytes=7)
    assert validated == envelope


@requires_postgres
def test_legacy_agent_is_not_offered_a_native_package(tmp_path, monkeypatch):
    _, client, key = _setup(tmp_path, monkeypatch)
    headers = _agent_token(client, key, "legacy-agent")
    registered = client.post(
        "/api/agent/register",
        json=dict(
            agent_id="legacy-agent",
            hostname="legacy-host",
            version="0.4.0",
            agent_kind="endpoint",
            capabilities=["self_update"],
        ),
        headers=headers,
    )
    assert registered.status_code == 200, registered.text
    management.store_release(
        version="0.5.0", platform=PLATFORM, content=BUILD, signed_manifest=_envelope()
    )
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    beat = client.post(
        "/api/agent/heartbeat",
        json=dict(agent_id="legacy-agent", platform=PLATFORM),
        headers=headers,
    )
    assert beat.status_code == 200, beat.text
    assert beat.json()["managed_update"] is None
    assert "signed native update support" in beat.json()["managed_update_blocked"]


@pytest.mark.parametrize("envelope", [None, {}])
def test_unsigned_upload_is_refused_before_storage(envelope):
    with pytest.raises(management.ReleaseError):
        management.store_release(
            version="0.5.0",
            platform=PLATFORM,
            content=BUILD,
            signed_manifest=envelope,
        )


@requires_postgres
@pytest.mark.parametrize("signed_updates", [False, True])
def test_old_unsigned_row_cannot_be_offered_or_downloaded(
    tmp_path, monkeypatch, signed_updates
):
    settings, client, key = _setup(tmp_path, monkeypatch)
    _legacy_release()
    headers = _agent_token(client, key, "old-row")
    registration = client.post(
        "/api/agent/register",
        headers=headers,
        json=dict(
            agent_id="old-row",
            hostname="host",
            agent_kind="endpoint",
            version="0.4.0",
            platform=PLATFORM,
            signed_updates=signed_updates,
        ),
    )
    assert registration.status_code == 200, registration.text
    management.set_policy(
        tenant_id="acme",
        agent_id=None,
        desired_version="0.5.0",
        settings={"inventory_interval_secs": 900},
    )
    # Both an explicit declaration and an omitted heartbeat declaration must
    # preserve the refusal after registration (which returns AgentInfo only).
    for declaration in ({"signed_updates": signed_updates}, {}):
        response = client.post(
            "/api/agent/heartbeat",
            headers=headers,
            json=dict(
                agent_id="old-row",
                hostname="host",
                agent_kind="endpoint",
                version="0.4.0",
                platform=PLATFORM,
                **declaration,
            ),
        )
        assert response.status_code == 200, response.text
        assert response.json()["managed_update"] is None
        assert response.json()["managed_update_blocked"]
        assert response.json()["managed_settings"] == {"inventory_interval_secs": 900}

    base = f"/api/endpoint/agent/releases/0.5.0/{PLATFORM}/download"
    for suffix in ("", "?package_kind=binary"):
        blocked = client.get(base + suffix, headers=headers)
        assert blocked.status_code == 409, blocked.text
        assert "unsigned executable updates are disabled" in blocked.json()["detail"]
        assert BUILD not in blocked.content

    admin = auth_headers(client, username="admin")
    for form in ({}, {"signed_manifest": "null"}):
        upload = client.post(
            "/api/endpoint/agent/releases",
            headers=admin,
            data={"version": "0.6.0", "platform": PLATFORM, **form},
            files={"binary": ("lariska.exe", BUILD, "application/octet-stream")},
        )
        assert upload.status_code == 422, upload.text
        assert "unsigned executable updates are disabled" in upload.json()["detail"]
    # Retain old rows for investigation and the existing audited deletion path.
    from tests.test_tenant_lifecycle import _audit

    assert _audit(settings, "endpoint_agent.release.upload") == []
    listed = client.get("/api/endpoint/agent/releases", headers=admin).json()
    assert len(listed) == 1 and listed[0]["package_kind"] == "binary"
    deleted = client.delete(base.removesuffix("/download"), headers=admin)
    assert deleted.status_code == 204, deleted.text
    assert management.list_releases() == []
    assert (
        _audit(settings, "endpoint_agent.release.delete")[-1].before["package_kind"]
        == "binary"
    )


@requires_postgres
@pytest.mark.parametrize("prefix", ["/api", "/api/v1"])
@pytest.mark.parametrize(
    "declaration", [{}, {"signed_updates": False}, {"capabilities": ["self_update"]}]
)
def test_cached_legacy_url_requires_native_capability_after_release_promotion(
    tmp_path, monkeypatch, prefix, declaration
):
    _, client, key = _setup(tmp_path, monkeypatch)
    _legacy_release()
    headers = _agent_token(client, key, "cached-legacy")
    registration = dict(
        agent_id="cached-legacy",
        hostname="host",
        agent_kind="endpoint",
        version="0.4.0",
        platform=PLATFORM,
    )

    def register(**fields):
        response = client.post(
            "/api/agent/register", headers=headers, json={**registration, **fields}
        )
        assert response.status_code == 200, response.text

    register(**declaration)
    # A pre-upgrade heartbeat can retain this unqualified URL and digest.
    # Promotion retires the binary row but the API checks envelope shape, not
    # publisher trust: unchanged executable bytes can have a native envelope.
    admin = auth_headers(client, username="admin")
    uploaded = client.post(
        "/api/endpoint/agent/releases",
        headers=admin,
        data=dict(
            version="0.5.0",
            platform=PLATFORM,
            signed_manifest=json.dumps(_envelope()),
        ),
        files={"binary": ("lariska.msi", BUILD, "application/octet-stream")},
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["sha256"] == hashlib.sha256(BUILD).hexdigest()
    base = f"{prefix}/endpoint/agent/releases/0.5.0/{PLATFORM}/download"

    def refused():
        for suffix in ("", "?package_kind=msi"):
            response = client.get(base + suffix, headers=headers)
            assert response.status_code == 409, response.text
            assert "signed native update support" in response.json()["detail"]
            assert BUILD not in response.content

    refused()
    register(signed_updates=True)
    for suffix in ("", "?package_kind=msi"):
        response = client.get(base + suffix, headers=headers)
        assert response.status_code == 200, response.text
        assert response.content == BUILD
    heartbeat = client.post(
        "/api/agent/heartbeat", headers=headers,
        json=dict(agent_id="cached-legacy", platform=PLATFORM, signed_updates=False),
    )
    assert heartbeat.status_code == 200, heartbeat.text
    refused()
    register(signed_updates=True)
    # A rolled-back endpoint retains its token and URL but loses native trust.
    register(**declaration)
    refused()
    # Endpoint identities cannot demote themselves into the scanning fleet.
    # Use a distinct scanner identity to check the download kind boundary.
    headers = _agent_token(client, key, "scanner-download")
    register(agent_id="scanner-download", agent_kind="scanner", signed_updates=True)
    refused()
