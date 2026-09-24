"""Legal hold: a tenant whose data nothing may delete until it is released (#332).

A hold is one row in ``tenant_legal_holds``. While it exists:

* **no reaper deletes the tenant's data.** Every retention sweep builds its
  plan through :func:`api.services.retention_policy.load_plan`, which reads
  :func:`held_tenants` and gives a held tenant a window of "keep"; the audit
  trail's prune functions skip the tenant in the database itself (migration
  0065), so an older retention image cannot delete it either;
* **the tenant cannot be deleted.** The row's foreign key to ``tenants`` is
  ``ON DELETE RESTRICT``, so a ``DELETE FROM tenants`` fails in Postgres for a
  held tenant whatever code issued it;
* **its console accounts cannot be erased** (``api.services.data_subject``):
  GDPR Art. 17(3)(e) exempts data needed for legal claims, and the mapping from
  a username to a person is exactly what a claim may turn on.

What it does *not* stop is an operator's explicit, audited deletion of one
object — a report, a wordlist, an asset. A hold suspends automated disposition
and purge; it is not a lock on the console.

**The contract tenant deletion is built on (#325).** Purging a tenant must, in
one transaction and before anything irreversible (artifact deletion included):

1. ``SELECT … FROM tenants WHERE tenant_id = :t FOR UPDATE`` — the row lock that
   :func:`place_hold` also takes, so a hold and a purge of the same tenant are
   serialised rather than interleaved;
2. :func:`assert_not_on_hold` with that session — raises :class:`LegalHoldActive`
   (a ``PermissionError``; answer **409**) naming who placed the hold and why.
   That message is for a platform admin: to anybody else, answer that the
   tenant is on hold and no more (see *The reason is the platform's* below);
3. only then mark the tenant as being purged, and let later batches re-check
   :func:`is_on_legal_hold` before each one.

The RESTRICT key is the backstop for a path that skips all three, not a
substitute for them: it fires only at the final ``DELETE FROM tenants``, after
a careless purge has already emptied the tenant's other tables.

Placing and releasing is ``platform.legal_hold.manage`` — platform admins only —
behind a step-up, and both are in the audit trail with the reason.

**The reason is the platform's, not the tenant's.** A hold can be placed over a
matter the tenant must not learn of from its own console — an investigation of
the tenant, a preservation order with a non-disclosure clause. So the audit rows
are platform-level (``tenant_id`` NULL, ``resource_id`` the tenant), which keeps
them out of the tenant admin's trail, and the tenant's own retention page is
told only that a hold is in force and since when (:func:`public_view`).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.legal-hold")

#: Long enough for a matter number and a sentence; short enough that nobody
#: pastes the complaint into it.
MAX_REASON_LENGTH = 1000


class LegalHoldActive(PermissionError):
    """An act refused because the tenant is on legal hold.

    A ``PermissionError`` like ``QuotaExceeded`` and ``ScanScopeDenied``: the
    request is well formed and the caller authenticated, the tenant is simply
    not allowed to lose data right now. Routes answer **409** — the refusal
    lasts exactly as long as the hold, and says whose it is.
    """

    def __init__(
        self,
        tenant_id: str,
        *,
        reason: str,
        set_by: str,
        set_at: datetime | None,
        action: str = "",
    ) -> None:
        verb = f"{action} refused: " if action else ""
        super().__init__(
            f"{verb}tenant {tenant_id!r} is on legal hold (placed by {set_by}"
            f"{' at ' + _iso(set_at) if set_at else ''}: {reason})"
        )
        self.tenant_id = tenant_id
        self.reason = reason
        self.set_by = set_by
        self.set_at = set_at
        self.action = action


def _now() -> datetime:
    # Naive UTC, like every timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _to_dict(row: models.TenantLegalHold) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "reason": row.reason,
        "set_by": row.set_by,
        "set_at": _iso(row.set_at),
    }


# -- the read side every reaper and #325 use ---------------------------------


def is_on_legal_hold(session: Session, tenant_id: str) -> bool:
    """Whether ``tenant_id`` is on legal hold, read in the caller's session.

    In the caller's session on purpose: a purge that checks here and deletes in
    another transaction has a window in which a hold can land between the two.
    See the module docstring for the lock that closes it.
    """
    return session.get(models.TenantLegalHold, tenant_id) is not None


def held_tenants(session: Session) -> frozenset[str]:
    """Every tenant on hold. One query; the reapers read it once per sweep."""
    return frozenset(
        session.execute(select(models.TenantLegalHold.tenant_id)).scalars().all()
    )


def assert_not_on_hold(session: Session, tenant_id: str, *, action: str) -> None:
    """Raise :class:`LegalHoldActive` when ``tenant_id`` is on hold.

    ``action`` names what was refused (``"tenant.delete"``, ``"user.erase"``)
    and goes into the message, so the 409 an operator reads says which of
    their requests the hold stopped.
    """
    row = session.get(models.TenantLegalHold, tenant_id)
    if row is not None:
        raise LegalHoldActive(
            tenant_id,
            reason=row.reason,
            set_by=row.set_by,
            set_at=row.set_at,
            action=action,
        )


def public_view(hold: dict[str, Any] | None) -> dict[str, Any] | None:
    """What a tenant's own readers see of its hold: that it exists, and since when.

    Not who placed it or why — see the module docstring.
    """
    if hold is None:
        return None
    return {"tenant_id": hold["tenant_id"], "set_at": hold["set_at"], "reason": None, "set_by": None}


# -- the write side, platform admins only -------------------------------------


def get_hold(settings: Settings, tenant_id: str) -> dict[str, Any] | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantLegalHold, tenant_id)
        return _to_dict(row) if row is not None else None


def list_holds(settings: Settings) -> list[dict[str, Any]]:
    """Every hold in force, oldest first — the platform admin's register."""
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.TenantLegalHold).order_by(models.TenantLegalHold.set_at)
        ).scalars().all()
        return [_to_dict(row) for row in rows]


def place_hold(
    settings: Settings,
    tenant_id: str,
    *,
    reason: str,
    set_by: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Put ``tenant_id`` on hold, or amend the reason of the hold it is on.

    Idempotent on the tenant: placing a hold that exists keeps its original
    ``set_by``/``set_at`` — "since when has this been held" must not move
    because somebody corrected a typo — and records the new reason. The tenant
    row is locked first, which is what serialises this against a purge that
    follows the contract in the module docstring.

    Raises LookupError for an unknown tenant and ValueError for an empty reason.
    """
    cleaned = " ".join(str(reason or "").split())
    if not cleaned:
        raise ValueError("a legal hold needs a reason")
    if len(cleaned) > MAX_REASON_LENGTH:
        raise ValueError(f"reason must be at most {MAX_REASON_LENGTH} characters")
    with get_session(settings.postgres_url) as session:
        tenant = session.execute(
            select(models.Tenant).where(models.Tenant.tenant_id == tenant_id).with_for_update()
        ).scalar_one_or_none()
        if tenant is None:
            raise LookupError(f"tenant not found: {tenant_id}")
        row = session.get(models.TenantLegalHold, tenant_id)
        before = _to_dict(row) if row is not None else None
        if row is None:
            row = models.TenantLegalHold(
                tenant_id=tenant_id, reason=cleaned, set_by=set_by, set_at=_now()
            )
            session.add(row)
        else:
            row.reason = cleaned
        session.flush()
        after = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_LEGAL_HOLD_PLACE,
            resource_type="legal_hold",
            resource_id=tenant_id,
            before=before,
            after=after,
        )
    LOG.warning("Legal hold on tenant %s placed by %s", tenant_id, set_by)
    return after


def release_hold(
    settings: Settings,
    tenant_id: str,
    *,
    audit: audit_service.AuditContext | None = None,
) -> bool:
    """Release the hold. False when there was none.

    The released hold goes into the audit row's ``before``, which is its only
    record from here on: the reapers resume on their next tick and delete
    everything the hold kept past its window, so "who let this go, and what had
    it been held for" has to be answerable afterwards.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantLegalHold, tenant_id)
        if row is None:
            return False
        before = _to_dict(row)
        session.delete(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_LEGAL_HOLD_RELEASE,
            resource_type="legal_hold",
            resource_id=tenant_id,
            before=before,
            after=None,
        )
    LOG.warning("Legal hold on tenant %s released", tenant_id)
    return True
