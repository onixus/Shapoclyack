"""Service tokens: non-interactive API credentials, scoped to one tenant.

ROADMAP Track E, "No SSO": alongside no federated login, the platform had no
credential for a machine. Integrations were therefore run under a human's
password — which cannot be scoped, cannot be given an expiry, and cannot be
revoked without locking a person out.

A token is ``octo_st_<16 hex>_<43 url-safe chars>``. The first two segments are
the **prefix**: non-secret, unique, indexed, and shown in the console so an
admin can recognise a credential they can no longer read. The last segment is
the secret, stored only as a bcrypt hash through the same passlib context as
console passwords and provisioning keys — the plaintext exists once, in the
creation response, and is unrecoverable afterwards.

Authorization is two independent limits, and a request must pass both:

* the token's **role** inside its tenant, which is the ceiling. A token can
  never do more than that role, and no membership row raises it — the
  principal is built from the token, not from a user.
* its **scopes**, ``resource:action`` grants that narrow the role further.
  ``resource`` is the first path segment under ``/api`` (``runs``, ``assets``,
  ``vulnerabilities``…); ``action`` is ``read`` for a safe method and ``write``
  for anything else. ``*`` matches either half, so ``runs:*`` and ``*:read``
  are both expressible and ``*`` is "everything this role allows".

Scope names are *not* validated against a route table on purpose: routers are
registered conditionally (webhooks, endpoint inventory), so a closed list would
turn a disabled feature into an unissuable token. Unknown scopes simply match
nothing.
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
from api.services import tenants as tenants_service
from api.settings import Settings

logger = logging.getLogger(__name__)

TOKEN_SCHEME = "octo_st"
_PREFIX_BYTES = 8
_SECRET_BYTES = 32
_TOKEN_RE = re.compile(rf"^{TOKEN_SCHEME}_([0-9a-f]{{{_PREFIX_BYTES * 2}}})_([A-Za-z0-9_-]{{16,}})$")

VALID_ROLES = ("viewer", "operator", "admin")
# Methods that only read. Everything else counts as a write for scope purposes,
# including the ones a route may implement as a read: erring toward "write" can
# only ever refuse a request, never admit one.
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Resources a service token may never reach, whatever its role or scopes.
# Identity and tenancy administration is the boundary: a token that can create
# users, rotate passwords, grant memberships, widen a scan scope or mint
# further tokens is a token that can outlive and out-scope its own revocation.
# ``tenants`` is in the list for that last reason — every route under it is
# administrative, and a token is already pinned to one tenant, so the read
# side of it has nothing to tell one.
FORBIDDEN_RESOURCES = frozenset({"auth", "users", "tenants"})

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "service_tokens.configure() not called"
    return _settings


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime | None) -> datetime | None:
    """Timestamps read back from SQLite come without a tzinfo; treat them as UTC."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _iso(value: datetime | None) -> str | None:
    aware = _aware(value)
    return aware.isoformat().replace("+00:00", "Z") if aware else None


def _to_dict(row: models.ServiceToken) -> dict[str, Any]:
    """Public shape. There is no code path here that returns secret material."""
    return {
        "token_id": row.token_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "token_prefix": row.token_prefix,
        "scopes": parse_scopes(row.scopes),
        "role": row.role,
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "last_used_at": _iso(row.last_used_at),
        "revoked_at": _iso(row.revoked_at),
        "status": status_of(row),
    }


def status_of(row: models.ServiceToken) -> str:
    if row.revoked_at is not None:
        return "revoked"
    expires = _aware(row.expires_at)
    if expires is not None and expires <= _now():
        return "expired"
    return "active"


# --------------------------------------------------------------------------- #
# Scopes
# --------------------------------------------------------------------------- #

_SCOPE_RE = re.compile(r"^(\*|[a-z0-9][a-z0-9_-]{0,63}):(\*|read|write)$")


def parse_scopes(raw: str | None) -> list[str]:
    return [part for part in (raw or "").split() if part]


def normalise_scopes(scopes: list[str] | None) -> str:
    """Validate and canonicalise a scope list into its stored form.

    An empty list is refused rather than read as "everything": a token created
    with no scopes by accident would otherwise be the most powerful one the
    installation has. ``["*"]`` is how an admin says "everything this role
    allows", and it has to be typed.
    """
    cleaned: list[str] = []
    for scope in scopes or []:
        value = str(scope).strip().lower()
        if not value:
            continue
        if value == "*":
            cleaned.append("*")
            continue
        if not _SCOPE_RE.match(value):
            raise ValueError(
                f"invalid scope {scope!r}: expected '*' or 'resource:action' where "
                "action is read, write or *"
            )
        cleaned.append(value)
    if not cleaned:
        raise ValueError("at least one scope is required (use '*' for every resource)")
    # Sorted and de-duplicated so two equivalent requests store the same string.
    return " ".join(sorted(set(cleaned)))


def resource_for_path(path: str) -> str:
    """First path segment under ``/api``, which is the resource a scope names."""
    parts = [part for part in path.split("/") if part]
    if parts and parts[0] == "api":
        parts = parts[1:]
    return parts[0].lower() if parts else ""


def action_for_method(method: str) -> str:
    return "read" if method.upper() in READ_METHODS else "write"


def scope_allows(scopes: list[str], *, resource: str, action: str) -> bool:
    for scope in scopes:
        if scope == "*":
            return True
        head, _, tail = scope.partition(":")
        if head not in ("*", resource):
            continue
        if tail in ("*", action):
            return True
    return False


# --------------------------------------------------------------------------- #
# Issue / list / revoke
# --------------------------------------------------------------------------- #


def _new_token() -> tuple[str, str]:
    """``(plaintext, prefix)``. The prefix is public; the rest never leaves here."""
    prefix = f"{TOKEN_SCHEME}_{secrets.token_bytes(_PREFIX_BYTES).hex()}"
    return f"{prefix}_{secrets.token_urlsafe(_SECRET_BYTES)}", prefix


def create_token(
    settings: Settings | None = None,
    *,
    tenant_id: str,
    name: str,
    scopes: list[str],
    role: str = "viewer",
    created_by: str | None = None,
    expires_in_days: int | None = None,
) -> dict[str, Any]:
    """Mint one token. The returned dict carries ``token`` — the only time it exists."""
    resolved = settings or _require_settings()
    role = (role or "viewer").strip().lower()
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {', '.join(VALID_ROLES)}")
    cleaned_name = (name or "").strip()
    if not cleaned_name:
        raise ValueError("name must not be empty")
    if len(cleaned_name) > 128:
        raise ValueError("name must be at most 128 characters")
    scope_text = normalise_scopes(scopes)

    default_ttl = max(1, resolved.service_token_default_ttl_days)
    max_ttl = max(1, resolved.service_token_max_ttl_days)
    ttl_days = default_ttl if expires_in_days is None else int(expires_in_days)
    if ttl_days < 1:
        raise ValueError("expires_in_days must be at least 1")
    if ttl_days > max_ttl:
        raise ValueError(f"expires_in_days must be at most {max_ttl}")

    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError("tenant not found")

    plaintext, prefix = _new_token()
    now = _now()
    with get_session(resolved.postgres_url) as session:
        row = models.ServiceToken(
            token_id=f"st_{secrets.token_hex(8)}",
            tenant_id=tenant_id,
            name=cleaned_name,
            token_prefix=prefix,
            token_hash=pwd_context.hash(plaintext),
            scopes=scope_text,
            role=role,
            created_by=created_by,
            created_at=now,
            expires_at=now + timedelta(days=ttl_days),
        )
        session.add(row)
        session.flush()
        out = _to_dict(row)
    out["token"] = plaintext
    return out


def list_tokens(
    settings: Settings | None = None, *, tenant_id: str | None = None
) -> list[dict[str, Any]]:
    resolved = settings or _require_settings()
    with get_session(resolved.postgres_url) as session:
        stmt = select(models.ServiceToken)
        if tenant_id:
            stmt = stmt.where(models.ServiceToken.tenant_id == tenant_id)
        rows = session.execute(stmt).scalars().all()
        items = [_to_dict(row) for row in rows]
    items.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return items


def revoke_token(
    settings: Settings | None = None, *, token_id: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    """Revoke one token. Idempotent — re-revoking keeps the original timestamp."""
    resolved = settings or _require_settings()
    with get_session(resolved.postgres_url) as session:
        row = session.get(models.ServiceToken, token_id)
        if row is None or (tenant_id is not None and row.tenant_id != tenant_id):
            return None
        if row.revoked_at is None:
            row.revoked_at = _now()
            session.flush()
        return _to_dict(row)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ServiceTokenPrincipal:
    """An authenticated service token. Carries no secret material."""

    token_id: str
    tenant_id: str
    name: str
    role: str
    scopes: tuple[str, ...]

    @property
    def username(self) -> str:
        """What the audit trail and the tenant resolver see. Never a real user.

        Prefixed so a service token can never be mistaken for — or collide with
        — a console account in ``auth_events`` or in a membership row.
        """
        return f"service-token:{self.name}"[:128]

    def allows(self, *, resource: str, action: str) -> bool:
        if resource in FORBIDDEN_RESOURCES:
            return False
        return scope_allows(list(self.scopes), resource=resource, action=action)


def looks_like_service_token(candidate: str) -> bool:
    """Cheap shape test used to route a bearer credential, never to authorize."""
    return _TOKEN_RE.match(candidate.strip()) is not None


def verify_token(settings: Settings | None, plaintext: str) -> ServiceTokenPrincipal | None:
    """Authenticate a presented token, or return None.

    One indexed lookup on the public prefix, then one bcrypt verification — the
    same shape as ``resolve_provisioning_key``, and for the same reason: a scan
    that bcrypt-checks every issued token turns authentication into work
    proportional to how many tokens the installation has.

    Returns None for every failure — unknown, revoked, expired, tenant gone —
    because the caller answers all of them with the same 401. Distinguishing
    them would tell the presenter of a guessed token which half was right.
    """
    resolved = settings or _require_settings()
    candidate = plaintext.strip()
    match = _TOKEN_RE.match(candidate)
    if match is None:
        return None
    prefix = f"{TOKEN_SCHEME}_{match.group(1)}"

    with get_session(resolved.postgres_url) as session:
        row = session.execute(
            select(models.ServiceToken).where(models.ServiceToken.token_prefix == prefix)
        ).scalar_one_or_none()
        if row is None:
            return None
        # The prefix came out of an indexed equality lookup, so this compares
        # equal by construction; it is here so the one comparison this function
        # makes on attacker-supplied bytes is constant-time regardless of how
        # the lookup is implemented later.
        if not hmac.compare_digest(row.token_prefix, prefix):
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
            # An unusable stored hash, exactly as users.authenticate handles it:
            # refuse, and say so once in the log rather than 500 on every call.
            logger.warning(
                "Service token %s has an unusable hash and cannot authenticate; revoke it.",
                row.token_id,
            )
            return None

        tenant = tenants_service.get_tenant(row.tenant_id)
        if tenant is None or tenant.get("status") != "active":
            return None

        _touch(session, row, resolved)
        return ServiceTokenPrincipal(
            token_id=row.token_id,
            tenant_id=row.tenant_id,
            name=row.name,
            role=row.role,
            scopes=tuple(parse_scopes(row.scopes)),
        )


def _touch(session, row: models.ServiceToken, settings: Settings) -> None:
    """Record use, at most once per configured interval.

    A token driving a busy integration would otherwise make every request a
    write to the same row — contention on the hottest row in this table, for a
    field nobody reads at that resolution. The interval is what makes
    ``last_used_at`` cheap enough to keep.
    """
    interval = max(0, settings.service_token_last_used_interval_seconds)
    now = _now()
    last = _aware(row.last_used_at)
    if last is not None and interval and (now - last) < timedelta(seconds=interval):
        return
    row.last_used_at = now
    session.flush()


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.ServiceToken).delete()
