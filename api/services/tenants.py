"""Tenant registry + provisioning keys (Phase 2 MSSP), Postgres-backed (Phase 7).

Public function signatures are unchanged from the pre-Phase-7 JSON-backed
implementation on purpose — api/app.py, api/routes/auth.py, api/services/auth.py
and api/services/jobs.py call these without modification.

Unlike nats_url/clickhouse_url elsewhere in this codebase, Postgres is NOT an
opt-in sidecar here: the tenant store lives on it, so ``load_tenants`` raises
if ``settings.postgres_url`` is empty rather than silently disabling anything.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

from passlib.context import CryptContext
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DEFAULT_TENANT_ID = "default"

_settings: Settings | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _lookup_prefix(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()[:16]


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "tenants_service.configure()/load_tenants() not called"
    return _settings


def _tenant_to_dict(row: models.Tenant) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "name": row.name,
        "status": row.status,
        "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
    }


def _key_to_dict(row: models.ProvisioningKey, *, include_hash: bool = False) -> dict[str, Any]:
    out = {
        "key_id": row.key_id,
        "tenant_id": row.tenant_id,
        "label": row.label,
        "created_at": row.created_at.isoformat().replace("+00:00", "Z"),
        "revoked_at": row.revoked_at.isoformat().replace("+00:00", "Z") if row.revoked_at else None,
        "last_used_at": row.last_used_at.isoformat().replace("+00:00", "Z") if row.last_used_at else None,
    }
    if include_hash:
        out["key_hash"] = row.key_hash
    return out


def load_tenants(settings: Settings) -> None:
    """Configure the DB session factory and ensure the seeded default tenant exists.

    Fails fast (raises) if ``settings.postgres_url`` is empty — Postgres is a
    hard requirement once tenants live here, unlike the opt-in NATS/ClickHouse
    sidecars elsewhere in api/settings.py.
    """
    configure(settings)
    if not settings.postgres_url.strip():
        raise RuntimeError(
            "OCTO_POSTGRES_URL is required: the tenant store is Postgres-backed "
            "(Phase 7). Set it to a reachable Postgres instance with migrations "
            "applied (alembic -c api/db/alembic.ini upgrade head)."
        )
    with get_session(settings.postgres_url) as session:
        existing = session.get(models.Tenant, DEFAULT_TENANT_ID)
        if existing is None:
            session.add(
                models.Tenant(
                    tenant_id=DEFAULT_TENANT_ID,
                    name="Default",
                    status="active",
                    created_at=_now(),
                )
            )


def reset_for_tests() -> None:
    """Clear tenants/provisioning_keys tables (test isolation only)."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        # Children before parents (FK constraints): identifiers/tags -> assets
        # -> provisioning_keys -> tenants.
        session.query(models.AssetIdentifier).delete()
        session.query(models.AssetTag).delete()
        session.query(models.Asset).delete()
        session.query(models.ProvisioningKey).delete()
        session.query(models.Tenant).delete()


def list_tenants() -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(select(models.Tenant)).scalars().all()
    items = [_tenant_to_dict(row) for row in rows]
    items.sort(key=lambda t: str(t.get("name") or t.get("tenant_id")).lower())
    return items


def get_tenant(tenant_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Tenant, tenant_id)
        return _tenant_to_dict(row) if row else None


def create_tenant(*, name: str, tenant_id: str | None = None) -> dict[str, Any]:
    settings = _require_settings()
    name = name.strip()
    if not name:
        raise ValueError("tenant name required")
    tid = (tenant_id or "").strip() or f"ten_{uuid.uuid4().hex[:12]}"
    with get_session(settings.postgres_url) as session:
        if session.get(models.Tenant, tid) is not None:
            raise ValueError(f"tenant_id already exists: {tid}")
        row = models.Tenant(tenant_id=tid, name=name, status="active", created_at=_now())
        session.add(row)
        session.flush()
        return _tenant_to_dict(row)


def create_provisioning_key(*, tenant_id: str, label: str = "") -> dict[str, Any]:
    """Mint a provisioning key. Returns record including one-time ``key`` plaintext."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        tenant = session.get(models.Tenant, tenant_id)
        if tenant is None:
            raise LookupError("tenant not found")
        if tenant.status != "active":
            raise ValueError("tenant is not active")
        key_id = f"pk_{uuid.uuid4().hex[:16]}"
        plaintext = f"octo-pk-{secrets.token_urlsafe(32)}"
        row = models.ProvisioningKey(
            key_id=key_id,
            tenant_id=tenant_id,
            label=label.strip(),
            key_hash=pwd_context.hash(plaintext),
            key_lookup=_lookup_prefix(plaintext),
            created_at=_now(),
        )
        session.add(row)
        session.flush()
        out = _key_to_dict(row)
        out["key"] = plaintext
        return out


def list_provisioning_keys(tenant_id: str | None = None) -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.ProvisioningKey)
        if tenant_id:
            stmt = stmt.where(models.ProvisioningKey.tenant_id == tenant_id)
        rows = session.execute(stmt).scalars().all()
    items = [_key_to_dict(row) for row in rows]
    items.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    return items


def revoke_provisioning_key(key_id: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ProvisioningKey, key_id)
        if row is None:
            return None
        row.revoked_at = _now()
        session.flush()
        return _key_to_dict(row)


def resolve_provisioning_key(plaintext: str) -> dict[str, Any] | None:
    """Find the active key matching plaintext; update last_used_at.

    O(1) lookup via the indexed ``key_lookup`` prefix (sha256(plaintext)[:16])
    instead of bcrypt-verifying every stored key — ``key_lookup`` is not a
    verifier (an attacker with DB read access already has key_hash too), just
    a non-secret index to narrow the candidate row before the real bcrypt
    check.
    """
    settings = _require_settings()
    lookup = _lookup_prefix(plaintext)
    with get_session(settings.postgres_url) as session:
        candidates = session.execute(
            select(models.ProvisioningKey).where(
                models.ProvisioningKey.key_lookup == lookup,
                models.ProvisioningKey.revoked_at.is_(None),
            )
        ).scalars().all()
        for row in candidates:
            if not pwd_context.verify(plaintext, row.key_hash):
                continue
            tenant = session.get(models.Tenant, row.tenant_id)
            if tenant is None or tenant.status != "active":
                return None
            row.last_used_at = _now()
            session.flush()
            return {"key_id": row.key_id, "tenant_id": row.tenant_id, "label": row.label}
    return None
