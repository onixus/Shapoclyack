"""Overlap rotation and source restrictions at the authenticated boundary (#323)."""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import service_tokens, workflow_events
from tests.conftest import auth_headers, bearer, configured_client, make_settings, requires_postgres


def test_cidrs_canonicalise_and_reject_bad_policy():
    assert service_tokens.normalise_cidrs(["192.0.2.5/24", "192.0.2.0/24", "::1"]) == ["192.0.2.0/24", "::1/128"]
    for bad in (["invalid"], [""]):
        with pytest.raises(ValueError):
            service_tokens.normalise_cidrs(bad)
    assert service_tokens.client_allowed(["192.0.2.0/24"], "192.0.2.8")
    assert service_tokens.client_allowed(["192.0.2.0/24"], "::ffff:192.0.2.8")
    assert not service_tokens.client_allowed(["192.0.2.0/24"], "unknown")
    assert not service_tokens.client_allowed(["192.0.2.0/24"], None)
    assert not service_tokens.client_allowed(["192.0.2.0/24"], "198.51.100.1")
    assert service_tokens.client_allowed([], None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    return client, settings, auth_headers(client, "admin")


def issue(env, **kwargs):
    client, settings, admin = env
    response = client.post("/api/tenants/default/service-tokens", headers=admin,
                           json={"name": "pipeline", "scopes": ["runs:read"], **kwargs})
    assert response.status_code == 201, response.text
    return response.json()


@requires_postgres
def test_rotation_overlap_preserves_limits_and_expires_old_secret(env):
    client, settings, admin = env
    old = issue(env, allowed_cidrs=["192.0.2.0/24"], expiry_notice_days=3)
    path = f"/api/tenants/default/service-tokens/{old['token_id']}/rotate"
    rotated = client.post(path, headers=admin, json={"grace_seconds": 300})
    assert rotated.status_code == 201, rotated.text
    new = rotated.json()
    assert new["rotated_from_id"] == old["token_id"]
    assert new["allowed_cidrs"] == old["allowed_cidrs"]
    assert new["scopes"] == old["scopes"]
    assert new["role"] == old["role"]
    assert new["expiry_notice_days"] == 3
    for token in (old, new):
        assert service_tokens.verify_token(settings, token["token"], client_ip="192.0.2.1")
        assert service_tokens.verify_token(settings, token["token"], client_ip="198.51.100.1") is None
    assert client.post(path, headers=admin, json={}).status_code == 422
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ServiceToken, old["token_id"])
        row.rotation_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    assert service_tokens.verify_token(settings, old["token"], client_ip="192.0.2.1") is None
    assert service_tokens.verify_token(settings, new["token"], client_ip="192.0.2.1")
    listed = client.get("/api/tenants/default/service-tokens", headers=admin).text
    assert old["token"] not in listed and new["token"] not in listed
    with get_session(settings.postgres_url) as session:
        audits = session.execute(select(models.AuditEvent).where(models.AuditEvent.action == "service_token.rotate")).scalars().all()
        assert len(audits) == 1
        assert old["token"] not in str(audits[0].after)
        assert new["token"] not in str(audits[0].after)


@requires_postgres
def test_rotation_zero_grace_and_tenant_boundary(env):
    client, settings, admin = env
    old = issue(env)
    other = client.post("/api/tenants", headers=admin, json={"name": "Other"}).json()["tenant_id"]
    assert client.post(f"/api/tenants/{other}/service-tokens/{old['token_id']}/rotate", headers=admin, json={}).status_code == 404
    path = f"/api/tenants/default/service-tokens/{old['token_id']}/rotate"
    assert client.post(path, headers=auth_headers(client, "operator"), json={}).status_code == 403
    assert client.post(path, headers=admin, json={"grace_seconds": -1}).status_code == 422
    assert client.post(path, headers=admin, json={"grace_seconds": 604801}).status_code == 422
    assert client.post(path, headers=admin, json={"grace_seconds": 0}).status_code == 201
    assert service_tokens.verify_token(settings, old["token"]) is None


@requires_postgres
def test_forwarding_header_cannot_bypass_source_restriction(env):
    client, settings, _admin = env
    token = issue(env, allowed_cidrs=["192.0.2.0/24"])["token"]
    headers = {**bearer(token), "x-forwarded-for": "192.0.2.7"}
    direct = TestClient(client.app, client=("198.51.100.1", 1234))
    assert direct.get("/api/runs", headers=headers).status_code == 401
    allowed = TestClient(client.app, client=("192.0.2.9", 1234))
    assert allowed.get("/api/runs", headers=bearer(token)).status_code == 200
    settings.trusted_proxies = ["10.0.0.0/24"]
    proxy = TestClient(client.app, client=("10.0.0.2", 1234))
    assert proxy.get("/api/runs", headers=headers).status_code == 200
    headers["x-forwarded-for"] = "192.0.2.7, 198.51.100.1"
    assert proxy.get("/api/runs", headers=headers).status_code == 401
    assert proxy.get("/api/runs", headers=bearer(token)).status_code == 401


@requires_postgres
def test_expiry_notification_is_due_once_and_omits_secrets(env, monkeypatch):
    client, settings, admin = env
    created = issue(env, expires_in_days=5, expiry_notice_days=7)
    issue(env, expires_in_days=5, expiry_notice_days=0)
    issue(env, expires_in_days=10, expiry_notice_days=7)
    emitted = []
    def capture(_settings, kind, **kwargs):
        emitted.append((kind, kwargs))
        return True, False
    monkeypatch.setattr(workflow_events, "_emit", capture)
    now = datetime.now(UTC)
    assert service_tokens.notify_expiring(settings, tenant_id="default", now=now) == 1
    assert service_tokens.notify_expiring(settings, tenant_id="default", now=now) == 0
    assert len(emitted) == 1
    assert emitted[0][0] == "service_token_expiring"
    assert emitted[0][1]["subject_id"] == created["token_id"]
    assert created["token"] not in str(emitted)
    client.post(f"/api/tenants/default/service-tokens/{created['token_id']}/revoke", headers=admin)
    assert service_tokens.notify_expiring(settings, tenant_id="default", now=now) == 0


@requires_postgres
def test_rotation_cannot_delegate_a_stronger_role_and_revoked_is_refused(env):
    _client, settings, _admin = env
    old = issue(env, role="admin")
    with pytest.raises(PermissionError):
        service_tokens.rotate_token(settings, token_id=old["token_id"], tenant_id="default",
                                    issuer_role="token-admin")
    service_tokens.revoke_token(settings, token_id=old["token_id"], tenant_id="default")
    with pytest.raises(ValueError, match="active"):
        service_tokens.rotate_token(settings, token_id=old["token_id"], tenant_id="default",
                                    issuer_role="admin", issuer_is_platform_admin=True)


@requires_postgres
def test_concurrent_rotation_creates_only_one_replacement(env):
    from concurrent.futures import ThreadPoolExecutor

    _client, settings, _admin = env
    old = issue(env)
    def rotate():
        try:
            return service_tokens.rotate_token(settings, token_id=old["token_id"],
                tenant_id="default", issuer_role="admin", issuer_is_platform_admin=True)
        except ValueError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: rotate(), range(2)))
    assert sum(result is not None for result in results) == 1
    with get_session(settings.postgres_url) as session:
        replacements = session.execute(select(models.ServiceToken).where(
            models.ServiceToken.rotated_from_id == old["token_id"])).scalars().all()
        assert len(replacements) == 1


@requires_postgres
def test_expiry_worker_queues_a_tenant_webhook_once(env):
    from api.services.integrations import webhooks
    from api.services.sla_escalation import SlaEscalationWorker

    _client, settings, _admin = env
    created = issue(env, expires_in_days=2)
    webhooks.create_subscription(tenant_id="default", name="expiry", created_by="admin",
        url="https://receiver.example/hook", event_kinds=["service_token_expiring"])
    worker = SlaEscalationWorker(settings=settings)
    now = datetime.now(UTC)
    worker.tick(now=now)
    worker.tick(now=now + timedelta(minutes=1))
    with get_session(settings.postgres_url) as session:
        deliveries = session.execute(select(models.WebhookDelivery).where(
            models.WebhookDelivery.event_kind == "service_token_expiring")).scalars().all()
        assert len(deliveries) == 1
        assert deliveries[0].tenant_id == "default"
        assert created["token"] not in str(deliveries[0].payload)
        assert deliveries[0].payload["event"]["data"]["token_id"] == created["token_id"]


@requires_postgres
def test_listener_recorded_socket_peer_wins_over_rewritten_asgi_client(env):
    from fastapi import HTTPException
    from starlette.requests import Request
    from api.auth import _authenticate_service_token
    from api.core.client_cert import SOCKET_PEER_STATE_KEY

    _client, settings, _admin = env
    token = issue(env, allowed_cidrs=["192.0.2.0/24"])["token"]
    request = Request({"type": "http", "method": "GET", "path": "/api/runs",
        "headers": [(b"x-forwarded-for", b"192.0.2.8")],
        "client": ("192.0.2.8", 443),
        "state": {SOCKET_PEER_STATE_KEY: "198.51.100.2"}})
    with pytest.raises(HTTPException) as error:
        _authenticate_service_token(request, settings, token)
    assert error.value.status_code == 401
