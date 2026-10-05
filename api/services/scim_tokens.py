"""SCIM tokens: the credential a provisioning client presents (#316).

A token is ``octo_scim_<16 hex>_<43 url-safe chars>`` — the same construction
as a service token (``api/services/service_tokens.py``): a public, indexed
prefix and a secret stored only as a bcrypt hash, so the plaintext exists once,
in the create response.

It is a credential type of its own rather than a service token with a scope,
because the two are bounded in opposite directions. A service token is pinned
to one tenant and may never reach ``users`` or ``tenants``; a provisioning
client creates accounts and grants memberships, which is precisely that. So
``/scim/v2`` accepts this token and nothing else, and every other route refuses
it — a console JWT, a service token and a SCIM token cannot stand in for each
other anywhere.

**What a token may manage is part of the token**, and the service holds every
SCIM call to it (``api/services/scim.py``):

* ``tenant_ids`` — the tenants whose memberships it writes. An account it may
  deactivate or re-enable must hold no membership outside them, and is never a
  platform admin; the global role is out of its reach entirely, because the
  global role acts in every tenant.
* ``all_tenants`` — every tenant, the global role (below ``admin``) and the
  lifecycle of every IdP-managed account.
* ``grant_platform_admin`` — only with ``all_tenants``: a group mapped to the
  global ``admin`` role takes effect through SCIM. Off unless an administrator
  asks for it by name, so a leaked provisioning token is not a way to mint an
  admin.

Issued by a platform admin only, behind a step-up (``api/routes/scim_tokens.py``).
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select

from api.auth import pwd_context
from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import tenants as tenants_service
from api.settings import Settings

logger = logging.getLogger(__name__)

TOKEN_SCHEME = "octo_scim"
_PREFIX_BYTES = 8
_SECRET_BYTES = 32
_TOKEN_RE = re.compile(
    rf"^{TOKEN_SCHEME}_([0-9a-f]{{{_PREFIX_BYTES * 2}}})_([A-Za-z0-9_-]{{16,}})$"
)


_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "scim_tokens.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.isoformat().replace("+00:00", "Z") if aware else None


def status_of(row: models.ScimToken) -> str:
    if row.revoked_at is not None:
        return "revoked"
    expires = _aware(row.expires_at)
    if expires is not None and expires <= _now():
        return "expired"
    return "active"


def _to_dict(row: models.ScimToken) -> dict[str, Any]:
    """Public shape. There is no code path here that returns secret material."""
    return {
        "token_id": row.token_id,
        "name": row.name,
        "token_prefix": row.token_prefix,
        "tenant_ids": sorted(row.tenant_ids or []),
        "all_tenants": bool(row.all_tenants),
        "grant_platform_admin": bool(row.grant_platform_admin),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "last_used_at": _iso(row.last_used_at),
        "revoked_at": _iso(row.revoked_at),
        "status": status_of(row),
    }


def _new_token() -> tuple[str, str]:
    prefix = f"{TOKEN_SCHEME}_{secrets.token_bytes(_PREFIX_BYTES).hex()}"
    return f"{prefix}_{secrets.token_urlsafe(_SECRET_BYTES)}", prefix


def create_token(
    settings: Settings | None = None,
    *,
    name: str,
    tenant_ids: list[str] | None,
    all_tenants: bool = False,
    grant_platform_admin: bool = False,
    created_by: str | None = None,
    expires_in_days: int | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Mint one token. The returned dict carries ``token`` — the only time it exists.

    ``tenant_ids`` and ``all_tenants`` are exclusive and one of them is
    required: a token bound to nothing is a mistake, and reading an empty list
    as "everything" would make that mistake the most powerful credential the
    installation has. Lifetime bounds are the service tokens' own settings.
    """
    resolved = settings or _require_settings()
    cleaned_name = (name or "").strip()
    if not cleaned_name:
        raise ValueError("name must not be empty")
    if len(cleaned_name) > 128:
        raise ValueError("name must be at most 128 characters")
    bound = sorted({str(tenant).strip() for tenant in (tenant_ids or []) if str(tenant).strip()})
    if all_tenants and bound:
        raise ValueError("tenant_ids and all_tenants are exclusive")
    if not all_tenants and not bound:
        raise ValueError("name the tenants this token manages, or set all_tenants")
    if grant_platform_admin and not all_tenants:
        raise ValueError("grant_platform_admin requires all_tenants")
    for tenant_id in bound:
        if tenants_service.get_tenant(tenant_id) is None:
            raise LookupError(f"tenant not found: {tenant_id}")

    default_ttl = max(1, resolved.service_token_default_ttl_days)
    max_ttl = max(1, resolved.service_token_max_ttl_days)
    ttl_days = default_ttl if expires_in_days is None else int(expires_in_days)
    if ttl_days < 1:
        raise ValueError("expires_in_days must be at least 1")
    if ttl_days > max_ttl:
        raise ValueError(f"expires_in_days must be at most {max_ttl}")

    plaintext, prefix = _new_token()
    now = _now()
    with get_session(resolved.postgres_url) as session:
        row = models.ScimToken(
            token_id=f"scim_{secrets.token_hex(8)}",
            name=cleaned_name,
            token_prefix=prefix,
            token_hash=pwd_context.hash(plaintext),
            tenant_ids=bound,
            all_tenants=bool(all_tenants),
            grant_platform_admin=bool(grant_platform_admin),
            created_by=created_by,
            created_at=now,
            expires_at=now + timedelta(days=ttl_days),
        )
        session.add(row)
        session.flush()
        out = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_SCIM_TOKEN_CREATE,
            resource_type="scim_token",
            resource_id=row.token_id,
            after=out,
        )
    out["token"] = plaintext
    return out


def list_tokens(settings: Settings | None = None) -> list[dict[str, Any]]:
    resolved = settings or _require_settings()
    with get_session(resolved.postgres_url) as session:
        rows = session.execute(select(models.ScimToken)).scalars().all()
        items = [_to_dict(row) for row in rows]
    items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return items


def revoke_token(
    settings: Settings | None = None,
    *,
    token_id: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Revoke one token. Idempotent — re-revoking keeps the original timestamp."""
    resolved = settings or _require_settings()
    with get_session(resolved.postgres_url) as session:
        row = session.get(models.ScimToken, token_id)
        if row is None:
            return None
        was_revoked = row.revoked_at is not None
        if not was_revoked:
            row.revoked_at = _now()
            session.flush()
        revoked = _to_dict(row)
        if not was_revoked:
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_SCIM_TOKEN_REVOKE,
                resource_type="scim_token",
                resource_id=token_id,
                after=revoked,
            )
        return revoked


@dataclass(frozen=True)
class ScimPrincipal:
    """An authenticated SCIM token. Carries no secret material."""

    token_id: str
    name: str
    tenant_ids: frozenset[str]
    all_tenants: bool
    grant_platform_admin: bool

    @property
    def actor(self) -> str:
        """What the audit trail names. Never a console account's name."""
        return f"scim-token:{self.name}"[:128]

    @property
    def created_by_marker(self) -> str:
        """``users.created_by`` of an account this token created."""
        return f"scim:{self.token_id}"


def looks_like_scim_token(candidate: str) -> bool:
    """Cheap shape test used to route a bearer credential, never to authorize."""
    return _TOKEN_RE.match(candidate.strip()) is not None


def verify_token(settings: Settings | None, plaintext: str) -> ScimPrincipal | None:
    """Authenticate a presented token, or return None for every failure.

    One indexed lookup on the prefix and one bcrypt verification, exactly as
    :func:`api.services.service_tokens.verify_token`, and the same single
    answer for unknown, revoked and expired.
    """
    resolved = settings or _require_settings()
    candidate = plaintext.strip()
    match = _TOKEN_RE.match(candidate)
    if match is None:
        return None
    prefix = f"{TOKEN_SCHEME}_{match.group(1)}"

    with get_session(resolved.postgres_url) as session:
        row = session.execute(
            select(models.ScimToken).where(models.ScimToken.token_prefix == prefix)
        ).scalar_one_or_none()
        if row is None or not hmac.compare_digest(row.token_prefix, prefix):
            return None
        if row.revoked_at is not None:
            return None
        expires = _aware(row.expires_at)
        if expires is None or expires <= _now():
            return None
        try:
            if not pwd_context.verify(candidate, row.token_hash):
                return None
        except ValueError:
            logger.warning(
                "SCIM token %s has an unusable hash and cannot authenticate; revoke it.",
                row.token_id,
            )
            return None
        interval = max(0, resolved.service_token_last_used_interval_seconds)
        now = _now()
        last = _aware(row.last_used_at)
        if last is None or not interval or (now - last) >= timedelta(seconds=interval):
            row.last_used_at = now
            session.flush()
        return ScimPrincipal(
            token_id=row.token_id,
            name=row.name,
            tenant_ids=frozenset(row.tenant_ids or []),
            all_tenants=bool(row.all_tenants),
            grant_platform_admin=bool(row.grant_platform_admin),
        )


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.ScimToken).delete()
