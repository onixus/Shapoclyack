"""Auth helpers for agent JWT exchange (Phase 2). Human login stays in api.auth."""

from __future__ import annotations

import uuid

from api.core import security as core_security
from api.services import tenants as tenants_service
from api.settings import Settings

AGENT_TOKEN_TYP = core_security.AGENT_TOKEN_TYP


def create_agent_access_token(
    settings: Settings,
    *,
    tenant_id: str,
    key_id: str,
    agent_id: str | None = None,
    expires_minutes: int | None = None,
) -> str:
    resolved_agent_id = (agent_id or "").strip() or f"agent_{uuid.uuid4().hex[:12]}"
    ttl = expires_minutes if expires_minutes is not None else settings.agent_jwt_expire_minutes
    return core_security.create_agent_exchange_token(
        tenant_id=tenant_id,
        agent_id=resolved_agent_id,
        key_id=key_id,
        expires_minutes=ttl,
        secret=settings.jwt_secret,
    )


def exchange_provisioning_key(
    settings: Settings,
    provisioning_key: str,
    *,
    agent_id: str | None = None,
    expires_minutes: int | None = None,
) -> dict[str, object]:
    """Validate provisioning key and return agent JWT + metadata."""
    resolved = tenants_service.resolve_provisioning_key(provisioning_key.strip())
    if resolved is None:
        raise PermissionError("Invalid or revoked provisioning key")
    resolved_agent_id = (agent_id or "").strip() or f"agent_{uuid.uuid4().hex[:12]}"
    ttl = expires_minutes if expires_minutes is not None else settings.agent_jwt_expire_minutes
    token = create_agent_access_token(
        settings,
        tenant_id=str(resolved["tenant_id"]),
        key_id=str(resolved["key_id"]),
        agent_id=resolved_agent_id,
        expires_minutes=ttl,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "tenant_id": resolved["tenant_id"],
        "key_id": resolved["key_id"],
        "agent_id": resolved_agent_id,
        "expires_in": ttl * 60,
    }
