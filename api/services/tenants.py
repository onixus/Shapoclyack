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
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from passlib.context import CryptContext
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.settings import Settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DEFAULT_TENANT_ID = "default"

# See _validate_tenant_id: the id doubles as a NATS subject token.
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_RESERVED_TENANT_PREFIX = "h_"

_settings: Settings | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def _lookup_prefix(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()[:16]


# How far ahead of a key's expiry the list starts flagging it. Two weeks is
# long enough to schedule minting a replacement and re-running the installer
# on the hosts that use it, and short enough that the flag still means
# something when it appears.
KEY_EXPIRY_WARNING_DAYS = 14


def _aware(dt: datetime | None) -> datetime | None:
    """Read a stored timestamp back as an aware UTC one.

    The column is a naive ``DateTime`` and different rows reach it by different
    routes (an alembic default, this module's aware ``_now``, a backend that
    drops the offset), so comparing one against ``now`` without normalising
    raises ``TypeError`` on whichever half happens to be naive.
    """
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _is_expired(row: models.ProvisioningKey, *, now: datetime | None = None) -> bool:
    """Whether the key is past ``expires_at``. A NULL expiry never is."""
    expires_at = _aware(row.expires_at)
    return expires_at is not None and expires_at <= (now or _now())


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


def _iso(dt: datetime | None) -> str | None:
    """Serialise a stored timestamp as UTC with an explicit ``Z``.

    ``.isoformat().replace("+00:00", "Z")`` used to be written out per field,
    which silently produced two different formats for the same column: the
    aware value this module writes came back ``…Z`` while the same row read
    from the database came back naive and unsuffixed. A consumer that parses
    the second one — ``new Date(...)`` in the console, for one — reads it in
    the viewer's local zone.
    """
    aware = _aware(dt)
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z") if aware else None


def _key_to_dict(row: models.ProvisioningKey, *, include_hash: bool = False) -> dict[str, Any]:
    out = {
        "key_id": row.key_id,
        "tenant_id": row.tenant_id,
        "label": row.label,
        "created_at": _iso(row.created_at),
        "revoked_at": _iso(row.revoked_at),
        "last_used_at": _iso(row.last_used_at),
        "expires_at": _iso(row.expires_at),
        # A key that is already expired, or already revoked, is not "expiring
        # soon" — it is done, and flagging it as a deadline would send an
        # operator to rotate something that has stopped working either way.
        "expires_soon": (
            row.revoked_at is None
            and row.expires_at is not None
            and not _is_expired(row)
            and _aware(row.expires_at) <= _now() + timedelta(days=KEY_EXPIRY_WARNING_DAYS)
        ),
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
        # Children before parents (FK constraints): identifiers/tags -> assets;
        # jobs/agents/scan_schedules/provisioning_keys -> tenants;
        # endpoint_* -> assets/tenants.
        session.query(models.Job).delete()
        session.query(models.Agent).delete()
        session.query(models.EndpointSoftwareChange).delete()
        session.query(models.EndpointSoftwareItem).delete()
        session.query(models.EndpointInventorySnapshot).delete()
        session.query(models.EndpointIdentifier).delete()
        session.query(models.EndpointDevice).delete()
        session.query(models.AssetIdentifier).delete()
        session.query(models.AssetTag).delete()
        session.query(models.Asset).delete()
        session.query(models.ScanSchedule).delete()
        session.query(models.WebhookDelivery).delete()
        session.query(models.WebhookSubscription).delete()
        session.query(models.Wordlist).delete()
        session.query(models.ProvisioningKey).delete()
        session.query(models.ServiceToken).delete()
        session.query(models.TenantQuota).delete()
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


def require_active(tenant_id: str) -> None:
    """Raise ``PermissionError`` unless this tenant is still active (#318).

    Suspending a tenant used to reach its machines only: an agent could not
    exchange a provisioning key and a key could not be minted, while every
    person in the tenant kept scanning, editing and downloading exactly as
    before. This is the same check for the human side, called once per request
    from :func:`api.auth.resolve_tenant_principal`.

    A tenant row that has gone missing is *not* an error here: the platform has
    always let a caller with no memberships act in ``default``, and an
    installation whose default row was never created would otherwise stop
    serving. Whether a named tenant exists is the route's 404 to raise, not
    this function's 403.
    """
    row = get_tenant(tenant_id)
    if row is not None and row["status"] != "active":
        raise PermissionError(f"Tenant {tenant_id} is {row['status']}")


def _validate_tenant_id(tid: str) -> None:
    """Constrain tenant ids to what a NATS subject token can carry verbatim.

    The id is a *routing* identifier, not just a key: it becomes a token in
    ``ingest.results.{tenant_id}`` and ``events.asset.{tenant_id}.{kind}``.
    Accepting arbitrary text meant two distinguishable tenants could share one
    subject (``acme.eu`` and ``acme_eu``), so a subscription or NATS ACL scoped
    to one of them would also receive the other's messages. Rejecting at
    creation is the cheap half of that fix; nats_bus encodes the ids that
    predate this check.

    ``h_`` is reserved as the prefix of that encoded form, so a literal id can
    never be mistaken for an encoded one.
    """
    if not _TENANT_ID_RE.match(tid):
        raise ValueError(
            "tenant_id must be 1-64 characters of A-Z, a-z, 0-9, '-' or '_' "
            "and start with an alphanumeric"
        )
    if tid.startswith(_RESERVED_TENANT_PREFIX):
        raise ValueError(f"tenant_id must not start with {_RESERVED_TENANT_PREFIX!r} (reserved)")


def create_tenant(*, name: str, tenant_id: str | None = None) -> dict[str, Any]:
    settings = _require_settings()
    name = name.strip()
    if not name:
        raise ValueError("tenant name required")
    tid = (tenant_id or "").strip() or f"ten_{uuid.uuid4().hex[:12]}"
    _validate_tenant_id(tid)
    with get_session(settings.postgres_url) as session:
        if session.get(models.Tenant, tid) is not None:
            raise ValueError(f"tenant_id already exists: {tid}")
        row = models.Tenant(tenant_id=tid, name=name, status="active", created_at=_now())
        session.add(row)
        session.flush()
        return _tenant_to_dict(row)


def create_provisioning_key(
    *, tenant_id: str, label: str = "", audit: "audit_service.AuditContext | None" = None
) -> dict[str, Any]:
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
        created_at = _now()
        # 0 (or a negative value someone typed) means perpetual, which is what
        # every key predating #308 already is. The TTL applies at mint time
        # only: changing the setting does not move the expiry of a key that has
        # already been handed to an installer.
        ttl_days = max(0, settings.provisioning_key_ttl_days)
        row = models.ProvisioningKey(
            key_id=key_id,
            tenant_id=tenant_id,
            label=label.strip(),
            key_hash=pwd_context.hash(plaintext),
            key_lookup=_lookup_prefix(plaintext),
            created_at=created_at,
            expires_at=created_at + timedelta(days=ttl_days) if ttl_days else None,
        )
        session.add(row)
        session.flush()
        out = _key_to_dict(row)
        # Recorded before the plaintext is attached below: a key that registers
        # agents into this tenant is exactly what must not end up in a table
        # every tenant admin can read (#327).
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_PROVISIONING_KEY_CREATE,
            resource_type="provisioning_key",
            resource_id=key_id,
            tenant_id=tenant_id,
            after=out,
        )
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


def revoke_provisioning_key(
    key_id: str, *, audit: "audit_service.AuditContext | None" = None
) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ProvisioningKey, key_id)
        if row is None:
            return None
        row.revoked_at = _now()
        session.flush()
        revoked = _key_to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_PROVISIONING_KEY_REVOKE,
            resource_type="provisioning_key",
            resource_id=key_id,
            tenant_id=row.tenant_id,
            after=revoked,
        )
        return revoked


def provisioning_key_state(key_id: str) -> str:
    """``active`` | ``revoked`` | ``expired`` | ``unknown`` for one key (#308).

    Read on every authenticated agent request so a revoked or expired key stops
    the JWTs already minted from it, rather than leaving them good for the
    remainder of their two hours. One primary-key lookup, the same shape the
    service-token path already pays.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ProvisioningKey, key_id)
        if row is None:
            return "unknown"
        if row.revoked_at is not None:
            return "revoked"
        if _is_expired(row):
            return "expired"
        return "active"


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
            if _is_expired(row):
                # Same ``None`` as an unknown or revoked key: the route turns
                # every one of them into the one 401 message, so presenting a
                # guessed key learns nothing about which half was wrong.
                return None
            tenant = session.get(models.Tenant, row.tenant_id)
            if tenant is None or tenant.status != "active":
                return None
            row.last_used_at = _now()
            session.flush()
            return {"key_id": row.key_id, "tenant_id": row.tenant_id, "label": row.label}
    return None
