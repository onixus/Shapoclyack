"""Unit tests for service_tokens service (Sprint 1 IAM)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from api.db.engine import get_session
from api.db.models import ServiceToken, Tenant
from api.services import service_tokens as st_service
from api.settings import load_settings


@pytest.fixture(autouse=True)
def _setup_test_tenant():
    settings = load_settings()
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        tenant = session.get(Tenant, "test-tenant")
        if not tenant:
            session.add(Tenant(tenant_id="test-tenant", name="Test Tenant", status="active", created_at=now))



def test_create_and_authenticate_service_token():
    metadata, raw_token = st_service.create_token(
        tenant_id="test-tenant",
        name="CI Deployment Key",
        role="operator",
        scopes=["scans:read", "scans:write"],
        expires_days=30,
        created_by="admin",
    )

    assert raw_token.startswith("shk_")
    assert metadata["name"] == "CI Deployment Key"
    assert metadata["tenant_id"] == "test-tenant"
    assert metadata["role"] == "operator"
    assert "scans:write" in metadata["scopes"]
    assert metadata["is_active"] is True

    # Authenticate with valid token
    principal = st_service.authenticate_token(raw_token)
    assert principal is not None
    assert principal["token_id"] == metadata["id"]
    assert principal["tenant_id"] == "test-tenant"
    assert principal["role"] == "operator"
    assert principal["scopes"] == ["scans:read", "scans:write"]


def test_authenticate_invalid_token():
    assert st_service.authenticate_token("") is None
    assert st_service.authenticate_token("invalid_token") is None
    assert st_service.authenticate_token("shk_nonexistent_secrettokenvaluehere12345") is None


def test_revoke_service_token():
    metadata, raw_token = st_service.create_token(
        tenant_id="test-tenant",
        name="To Revoke",
        role="viewer",
        scopes=["assets:read"],
    )

    token_id = metadata["id"]
    assert st_service.authenticate_token(raw_token) is not None

    # Revoke
    revoked = st_service.revoke_token("test-tenant", token_id)
    assert revoked is True

    # Subsequent auth must fail
    assert st_service.authenticate_token(raw_token) is None

    # Second revoke returns False
    assert st_service.revoke_token("test-tenant", token_id) is False


def test_expired_service_token():
    from uuid import uuid4

    settings = load_settings()
    now = datetime.now(UTC)
    expired_time = now - timedelta(days=1)

    full_token, prefix, _ = st_service.generate_raw_token()
    token_hash = st_service.pwd_context.hash(full_token)

    with get_session(settings.postgres_url) as session:
        token_obj = ServiceToken(
            id=f"tok_exp_{uuid4().hex[:12]}",
            name="Expired Key",
            key_prefix=prefix,
            key_hash=token_hash,
            tenant_id="test-tenant",
            role="viewer",
            scopes=["assets:read"],
            created_at=now - timedelta(days=10),
            expires_at=expired_time,
        )
        session.add(token_obj)
        session.commit()

    # Expired token cannot authenticate
    assert st_service.authenticate_token(full_token) is None


def test_list_service_tokens():
    t_list = st_service.list_tokens("test-tenant")
    initial_count = len(t_list)

    st_service.create_token(
        tenant_id="test-tenant",
        name="List Test Token",
        role="viewer",
        scopes=["reports:read"],
    )

    updated_list = st_service.list_tokens("test-tenant")
    assert len(updated_list) == initial_count + 1
    assert any(t["name"] == "List Test Token" for t in updated_list)
