"""TASK 3/4: /api/v1/auth/exchange + ingest gateway subject helpers."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.core.security import DEFAULT_EXCHANGE_TTL_MINUTES, decode_jwt
from api.services import nats_bus
from api.services import results_ingest
from api.settings import Settings
from tests.conftest import configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


# Agent-mode, JWT-only: no legacy OCTO_AGENT_TOKEN fallback.
SETTINGS = {"job_execution_mode": "agent", "agent_token": "", "agent_jwt_expire_minutes": 120}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def test_v1_auth_exchange_returns_tenant_and_agent_claims(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin-change-me"},
    ).json()["access_token"]
    client.post(
        "/api/tenants",
        headers={"Authorization": f"Bearer {admin}"},
        json={"name": "Gate", "tenant_id": "ten_gate"},
    )
    key = client.post(
        "/api/tenants/ten_gate/provisioning-keys",
        headers={"Authorization": f"Bearer {admin}"},
        json={},
    ).json()["key"]

    exchanged = client.post(
        "/api/v1/auth/exchange",
        json={"provisioning_key": key, "agent_id": "edge-42"},
    )
    assert exchanged.status_code == 200
    body = exchanged.json()
    assert body["tenant_id"] == "ten_gate"
    assert body["agent_id"] == "edge-42"
    assert body["expires_in"] == DEFAULT_EXCHANGE_TTL_MINUTES * 60

    claims = decode_jwt(body["access_token"], secret="test-secret")
    assert claims["typ"] == "agent"
    assert claims["tenant_id"] == "ten_gate"
    assert claims["agent_id"] == "edge-42"


def test_ingest_results_subject_and_gateway_payload(tmp_path):
    assert nats_bus.ingest_results_subject("ten_acme") == "ingest.results.ten_acme"
    # A tenant id that is not a valid subject token is hashed into the reserved
    # h_ namespace, not folded character-by-character into a neighbour's
    # subject: the old mapping sent "ten/../x" and a literal "ten____x" to the
    # same place, so an ACL scoped to one tenant received the other's results.
    unsafe = nats_bus.ingest_results_subject("ten/../x")
    assert unsafe.startswith("ingest.results.h_")
    assert unsafe != nats_bus.ingest_results_subject("ten____x")

    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b'{"ok":true}\n'
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    archive = buf.getvalue()

    nats_bus.reset_bus_for_tests()
    meta = results_ingest.publish_raw_results(
        nats_url="",
        job_id="j1",
        run_id="r1",
        agent_id="a1",
        exit_code=0,
        archive_bytes=archive,
        tenant_id="ten_gate",
    )
    assert meta["published"] is False
    assert meta["subject"] == "ingest.results.ten_gate"
    assert meta["tenant_id"] == "ten_gate"
