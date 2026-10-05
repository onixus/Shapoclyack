"""A publisher envelope stays byte-bound and survives upload/heartbeat unchanged."""

from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest

from api.services import endpoint_agent_mgmt as management
from tests.conftest import auth_headers, requires_postgres
from tests.test_endpoint_agent_management import BUILD, PLATFORM, _agent_token, _setup


def _envelope(content=BUILD, **overrides):
    manifest = dict(
        schema=1,
        key_id="test-publisher",
        version="0.5.0",
        platform=PLATFORM,
        package_kind="msi",
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        expires_at=int(time.time()) + 3600,
        sequence=7,
    )
    manifest.update(overrides)
    return dict(manifest=manifest, signature="ab" * 64)


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
    unsigned = management.store_release(
        version="0.5.0", platform=PLATFORM, content=BUILD
    )
    assert unsigned["signed_manifest"] is None
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
    management.store_release(version="0.5.0", platform=PLATFORM, content=BUILD)
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    legacy = management.plan_for_agent(
        tenant_id="acme", agent_id="old", current_version="0.4.0", platform=PLATFORM
    )
    assert legacy.update is not None
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
