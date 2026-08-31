"""Service tokens (scoped API keys) service for non-interactive integrations (Sprint 1 IAM)."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from passlib.context import CryptContext
from sqlalchemy import select, update

from api.db.engine import get_session
from api.db.models import ServiceToken
from api.settings import Settings, load_settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

TOKEN_PREFIX = "shk"

CANONICAL_SCOPES = [
    "scans:read",
    "scans:write",
    "assets:read",
    "assets:write",
    "vulns:read",
    "vulns:write",
    "leaks:read",
    "tokens:manage",
    "system:read",
    "reports:read",
]


def _get_url(settings: Settings | None = None) -> str:
    if settings is not None:
        return settings.postgres_url
    return load_settings().postgres_url


def generate_raw_token() -> tuple[str, str, str]:
    """Generate a token returning (full_token, prefix, secret).

    Format: shk_<8_char_prefix>_<32_char_secret>
    """
    prefix = secrets.token_hex(4)  # 8 chars
    secret = secrets.token_urlsafe(24)  # ~32 chars
    full_token = f"{TOKEN_PREFIX}_{prefix}_{secret}"
    return full_token, prefix, secret


def create_token(
    tenant_id: str,
    name: str,
    role: str = "viewer",
    scopes: list[str] | None = None,
    expires_days: int | None = 90,
    created_by: str | None = None,
    settings: Settings | None = None,
) -> tuple[dict[str, Any], str]:
    """Create a new service token. Returns (token_metadata, plaintext_token)."""
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("Token name cannot be empty")
    if len(clean_name) > 128:
        raise ValueError("Token name exceeds 128 characters")

    valid_roles = {"viewer", "operator", "admin"}
    clean_role = (role or "viewer").strip().lower()
    if clean_role not in valid_roles:
        raise ValueError(f"Invalid role '{role}'. Must be one of {valid_roles}")

    clean_scopes = []
    if scopes:
        for s in scopes:
            s_clean = s.strip().lower()
            if s_clean:
                clean_scopes.append(s_clean)
    # Deduplicate while preserving order
    clean_scopes = list(dict.fromkeys(clean_scopes))

    full_token, prefix, _ = generate_raw_token()
    token_hash = pwd_context.hash(full_token)
    token_id = f"tok_{uuid4().hex[:16]}"
    now = datetime.now(UTC)
    expires_at = now + timedelta(days=expires_days) if expires_days and expires_days > 0 else None

    with get_session(_get_url(settings)) as session:
        token_obj = ServiceToken(
            id=token_id,
            name=clean_name,
            key_prefix=prefix,
            key_hash=token_hash,
            tenant_id=tenant_id,
            role=clean_role,
            scopes=clean_scopes,
            created_at=now,
            created_by=created_by,
            expires_at=expires_at,
            last_used_at=None,
            revoked_at=None,
        )
        session.add(token_obj)
        session.commit()

        metadata = {
            "id": token_id,
            "name": clean_name,
            "key_prefix": prefix,
            "tenant_id": tenant_id,
            "role": clean_role,
            "scopes": clean_scopes,
            "created_at": now.isoformat(),
            "created_by": created_by,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "last_used_at": None,
            "revoked_at": None,
            "is_active": True,
        }
        return metadata, full_token


def authenticate_token(token_str: str, settings: Settings | None = None) -> dict[str, Any] | None:
    """Validate a bearer token string.

    Returns dict payload if valid and active, else None.
    """
    if not token_str or not token_str.startswith(f"{TOKEN_PREFIX}_"):
        return None

    parts = token_str.split("_")
    if len(parts) < 3:
        return None

    prefix = parts[1]
    now = datetime.now(UTC)

    with get_session(_get_url(settings)) as session:
        candidates = session.scalars(
            select(ServiceToken).where(
                ServiceToken.key_prefix == prefix,
                ServiceToken.revoked_at.is_(None),
            )
        ).all()

        matching_token: ServiceToken | None = None
        for candidate in candidates:
            if pwd_context.verify(token_str, candidate.key_hash):
                matching_token = candidate
                break

        if not matching_token:
            return None

        # Expiry check
        exp = matching_token.expires_at
        if exp is not None:
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if exp < now:
                logger.info("Service token %s is expired", matching_token.id)
                return None

        # Update last_used_at
        session.execute(
            update(ServiceToken)
            .where(ServiceToken.id == matching_token.id)
            .values(last_used_at=now)
        )
        session.commit()

        return {
            "token_id": matching_token.id,
            "name": matching_token.name,
            "tenant_id": matching_token.tenant_id,
            "role": matching_token.role,
            "scopes": matching_token.scopes or [],
            "created_by": matching_token.created_by,
        }


def list_tokens(tenant_id: str, settings: Settings | None = None) -> list[dict[str, Any]]:
    """List all tokens for a tenant."""
    now = datetime.now(UTC)
    with get_session(_get_url(settings)) as session:
        rows = session.scalars(
            select(ServiceToken)
            .where(ServiceToken.tenant_id == tenant_id)
            .order_by(ServiceToken.created_at.desc())
        ).all()

        results = []
        for row in rows:
            exp = row.expires_at
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            is_active = (row.revoked_at is None) and (exp is None or exp > now)
            results.append(
                {
                    "id": row.id,
                    "name": row.name,
                    "key_prefix": row.key_prefix,
                    "tenant_id": row.tenant_id,
                    "role": row.role,
                    "scopes": row.scopes or [],
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                    "created_by": row.created_by,
                    "expires_at": row.expires_at.isoformat() if row.expires_at else None,
                    "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None,
                    "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
                    "is_active": is_active,
                }
            )
        return results


def revoke_token(tenant_id: str, token_id: str, settings: Settings | None = None) -> bool:
    """Revoke a token by setting revoked_at timestamp."""
    now = datetime.now(UTC)
    with get_session(_get_url(settings)) as session:
        token = session.scalar(
            select(ServiceToken).where(
                ServiceToken.tenant_id == tenant_id,
                ServiceToken.id == token_id,
            )
        )
        if not token or token.revoked_at is not None:
            return False
        token.revoked_at = now
        session.commit()
        return True

