"""Auth helpers for agent JWT exchange (Phase 2). Human login stays in api.auth."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from api.services import tenants as tenants_service
from api.settings import Settings

AGENT_TOKEN_TYP = "agent"


def create_agent_access_token(
    settings: Settings,
    *,
    tenant_id: str,
    key_id: str,
    agent_id: str | None = None,
) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.agent_jwt_expire_minutes)
    payload = {
        "sub": agent_id or key_id,
        "typ": AGENT_TOKEN_TYP,
        "tenant_id": tenant_id,
        "key_id": key_id,
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def exchange_provisioning_key(settings: Settings, provisioning_key: str) -> dict[str, object]:
    """Validate provisioning key and return agent JWT + metadata."""
    resolved = tenants_service.resolve_provisioning_key(provisioning_key.strip())
    if resolved is None:
        raise PermissionError("Invalid or revoked provisioning key")
    token = create_agent_access_token(
        settings,
        tenant_id=str(resolved["tenant_id"]),
        key_id=str(resolved["key_id"]),
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "tenant_id": resolved["tenant_id"],
        "key_id": resolved["key_id"],
        "expires_in": settings.agent_jwt_expire_minutes * 60,
    }
