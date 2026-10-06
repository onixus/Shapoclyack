"""The real Lariska wire protocol and DEB/RPM release isolation."""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from api.schemas import AgentHeartbeatRequest, AgentRegisterRequest
from api.services.agents import _reported_capabilities
from api.services import endpoint_agent_mgmt as management
from tests.conftest import auth_headers, requires_postgres
from tests.test_endpoint_agent_management import _agent_token, _setup
from tests.test_endpoint_signed_updates import _envelope

LINUX = "x86_64-unknown-linux-gnu"


def test_lariska_boolean_survives_validation_and_capability_rollback():
    for model in (AgentRegisterRequest, AgentHeartbeatRequest):
        request = model.model_validate(dict(agent_id="lariska", signed_updates=True))
        assert request.signed_updates is True
        assert _reported_capabilities(request.capabilities, request.signed_updates) == [
            "signed_updates"
        ]
    assert _reported_capabilities(None, True, ["self_update"]) == [
        "self_update",
        "signed_updates",
    ]
    assert _reported_capabilities(None, False, ["self_update", "signed_updates"]) == [
        "self_update"
    ]
    assert _reported_capabilities(None, None, ["signed_updates"]) == ["signed_updates"]
    assert _reported_capabilities([], None, ["signed_updates"]) == []
    assert _reported_capabilities(["signed_updates"], False) == []


def _upload(client, headers, kind, content):
    envelope = _envelope(content, platform=LINUX, package_kind=kind)
    response = client.post(
        "/api/endpoint/agent/releases",
        headers=headers,
        data=dict(
            version="0.5.0", platform=LINUX, signed_manifest=json.dumps(envelope)
        ),
        files={"binary": (f"lariska.{kind}", content, "application/octet-stream")},
    )
    assert response.status_code == 201, response.text
    assert response.json()["signed_manifest"] == envelope
    return envelope


def _register(client, key, agent_id):
    headers = _agent_token(client, key, agent_id)
    response = client.post(
        "/api/agent/register",
        headers=headers,
        json=dict(
            agent_id=agent_id,
            hostname=agent_id,
            version="0.4.0",
            agent_kind="endpoint",
            signed_updates=True,
            inventory_schema_versions=[1, 2],
        ),
    )
    assert response.status_code == 200, response.text
    assert "signed_updates" in response.json()["capabilities"]
    return headers


def _inventory(client, headers, agent_id, sources):
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    response = client.post(
        "/api/endpoint/inventory",
        headers=headers,
        json=dict(
            schema_version=2,
            snapshot_id=f"snapshot-{agent_id}",
            agent_id=agent_id,
            hostname=agent_id,
            agent_version="0.4.0",
            collected_at=now,
            os_family="linux",
            software=[],
            sources=[
                dict(
                    source=source,
                    status=status,
                    collected_at=now,
                    collector_version="0.4.0",
                )
                for source, status in sources
            ],
        ),
    )
    assert response.status_code == 201, response.text


def _heartbeat(client, headers, agent_id, **extra):
    response = client.post(
        "/api/agent/heartbeat",
        headers=headers,
        json=dict(
            agent_id=agent_id,
            platform=LINUX,
            signed_updates=True,
            inventory_schema_versions=[1, 2],
            **extra,
        ),
    )
    assert response.status_code == 200, response.text
    return response.json()


@requires_postgres
def test_real_boolean_protocol_offers_both_linux_installers_and_exact_downloads(
    tmp_path, monkeypatch
):
    _, client, key = _setup(tmp_path, monkeypatch)
    admin = auth_headers(client, username="admin")
    envelopes = {
        kind: _upload(client, admin, kind, kind.encode()) for kind in ("deb", "rpm")
    }
    assert {row["package_kind"] for row in management.list_releases()} == {"deb", "rpm"}
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    for kind, source, inactive in (("deb", "dpkg", "rpm"), ("rpm", "rpm", "dpkg")):
        agent_id = f"host-{kind}"
        headers = _register(client, key, agent_id)
        _inventory(
            client,
            headers,
            agent_id,
            [(source, "complete"), (inactive, "not_applicable")],
        )
        update = _heartbeat(client, headers, agent_id)["managed_update"]
        assert update["signed_manifest"] == envelopes[kind]
        assert update["url"].endswith(f"package_kind={kind}")
        downloaded = client.get(update["url"], headers=headers)
        assert downloaded.status_code == 200
        assert downloaded.content == kind.encode()
        assert (
            downloaded.headers["X-Content-SHA256"]
            == hashlib.sha256(kind.encode()).hexdigest()
        )
        # Downgrading capability is authoritative on heartbeat and on restart.
        beat = client.post(
            "/api/agent/heartbeat",
            headers=headers,
            json=dict(agent_id=agent_id, platform=LINUX, signed_updates=False),
        ).json()
        assert "signed_updates" not in beat["capabilities"]
        assert beat["managed_update"] is None
        assert (
            client.post(
                "/api/agent/register",
                headers=headers,
                json=dict(
                    agent_id=agent_id, agent_kind="endpoint", signed_updates=False
                ),
            ).json()["capabilities"]
            == []
        )


@requires_postgres
def test_unknown_or_ambiguous_installer_requires_an_explicit_report(
    tmp_path, monkeypatch
):
    _, client, key = _setup(tmp_path, monkeypatch)
    for kind in ("deb", "rpm"):
        _upload(client, auth_headers(client, username="admin"), kind, kind.encode())
    management.set_policy(tenant_id="acme", agent_id=None, desired_version="0.5.0")
    headers = _register(client, key, "ambiguous")
    assert _heartbeat(client, headers, "ambiguous")["managed_update"] is None
    _inventory(
        client, headers, "ambiguous", [("dpkg", "complete"), ("rpm", "complete")]
    )
    assert _heartbeat(client, headers, "ambiguous")["managed_update"] is None
    assert (
        _heartbeat(client, headers, "ambiguous", package_kind="msi")["managed_update"]
        is None
    )
    update = _heartbeat(client, headers, "ambiguous", package_kind="rpm")[
        "managed_update"
    ]
    assert update["signed_manifest"]["manifest"]["package_kind"] == "rpm"


@requires_postgres
def test_variant_sequences_and_deletion_cannot_overwrite_another_installer(
    tmp_path, monkeypatch
):
    _, client, key = _setup(tmp_path, monkeypatch)
    admin = auth_headers(client, username="admin")
    for kind in ("deb", "rpm"):
        _upload(client, admin, kind, kind.encode())
    with pytest.raises(management.ReleaseError, match="newer"):
        management.store_release(
            version="0.5.0",
            platform=LINUX,
            content=b"changed rpm",
            signed_manifest=_envelope(
                b"changed rpm", platform=LINUX, package_kind="rpm"
            ),
        )
    with pytest.raises(management.ReleaseError, match="unsigned"):
        management.store_release(version="0.5.0", platform=LINUX, content=b"unsigned")
    headers = _register(client, key, "download")
    base = f"/api/endpoint/agent/releases/0.5.0/{LINUX}"
    assert client.get(base + "/download", headers=headers).status_code == 409
    assert client.delete(base, headers=admin).status_code == 409
    assert len(management.list_releases()) == 2
    assert client.delete(base + "?package_kind=deb", headers=admin).status_code == 204
    assert (
        management.get_release_bytes(
            version="0.5.0", platform=LINUX, package_kind="deb"
        )
        is None
    )
    assert (
        management.get_release_bytes(
            version="0.5.0", platform=LINUX, package_kind="rpm"
        )[0]
        == b"rpm"
    )


@requires_postgres
def test_concurrent_uploads_preserve_native_promotion_and_sequence_floor(
    tmp_path, monkeypatch
):
    _setup(tmp_path, monkeypatch)
    barrier = threading.Barrier(3)

    def upload(kind):
        barrier.wait(timeout=10)
        content = kind.encode()
        try:
            management.store_release(
                version="0.5.0",
                platform=LINUX,
                content=content,
                signed_manifest=None
                if kind == "binary"
                else _envelope(content, platform=LINUX, package_kind=kind),
            )
        except management.ReleaseError:
            if kind != "binary":
                raise

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(upload, ("binary", "deb", "rpm")))
    assert {row["package_kind"] for row in management.list_releases()} == {"deb", "rpm"}

    barrier = threading.Barrier(2)

    def replace(sequence):
        barrier.wait(timeout=10)
        content = f"rpm-{sequence}".encode()
        try:
            management.store_release(
                version="0.5.0",
                platform=LINUX,
                content=content,
                signed_manifest=_envelope(
                    content, platform=LINUX, package_kind="rpm", sequence=sequence
                ),
            )
        except management.ReleaseError:
            if sequence != 8:
                raise

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(replace, (8, 9)))
    rows = {row["package_kind"]: row for row in management.list_releases()}
    assert rows["rpm"]["signed_manifest"]["manifest"]["sequence"] == 9
    assert rows["deb"]["signed_manifest"]["manifest"]["sequence"] == 7
