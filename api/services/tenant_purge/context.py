"""What every purge step is handed: the tenant, the lease, and the hold check (#325).

A step deletes in batches, and between batches it calls :meth:`PurgeContext.guard`
(or :meth:`~PurgeContext.checkpoint`, which is a guard with nothing inside).
The guard is the legal-hold contract applied per batch
(``api/services/legal_hold.py``):

1. ``SELECT … FROM tenants WHERE tenant_id = :t FOR UPDATE`` — the lock
   ``place_hold`` takes, so a hold being placed and a batch being deleted are
   serialised, never interleaved;
2. ``legal_hold.assert_not_on_hold`` in that session — a hold placed since the
   last batch stops the purge here, with the rest of the tenant's data intact;
3. the deletion's lease renewed, in the same transaction — a replica that has
   lost the row to another (its lease lapsed during a long external call)
   stops instead of racing the new owner.

A Postgres batch runs *inside* the guard, so the rows and the hold check commit
together. A batch against another store (a bucket, ClickHouse, JetStream)
runs right after its guard, outside the transaction: holding a row lock across
a network call to a third system is the long lock the purge must not take. The
window that leaves — a hold committed between the check and one external batch
— is one batch wide.

Once the tenant row is gone there is nothing to lock, and nothing to hold
either: ``tenant_legal_holds`` has a RESTRICT key to ``tenants``, so a hold on a
tenant without a row cannot exist.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Iterator

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.services import legal_hold
from api.settings import Settings

#: How long a claim on a deletion lasts without a renewal. Every batch renews
#: it, so this only has to outlast the longest single call to another store —
#: a ClickHouse mutation on a large table is the one that gets close.
LEASE_SECONDS = 900


class StepSkipped(Exception):
    """The store this step purges is not configured here; nothing to do."""


class StepWaiting(Exception):
    """The step cannot start yet and will be retried at the ordinary interval."""


class LeaseLost(RuntimeError):
    """Another replica owns this deletion now; stop without recording anything."""


class RerunSteps(RuntimeError):
    """Earlier steps have to run again (a late writer left rows behind)."""

    def __init__(self, steps: tuple[str, ...], message: str) -> None:
        super().__init__(message)
        self.steps = steps


def now() -> datetime:
    # Naive UTC, like every timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


@contextmanager
def system_session(settings: Settings) -> Iterator[Session]:
    """Every database session the purge worker opens.

    The purge is a cross-tenant system path: it reads the journal of every
    tenant and deletes one tenant's rows on nobody's request. When row-level
    security lands (#311), this is the one function to wrap in its system scope
    — nothing in the purge opens a session any other way.
    """
    with get_session(settings.postgres_url) as session:
        yield session


class PurgeContext:
    """One step of one deletion, as seen by the code that deletes."""

    def __init__(
        self,
        settings: Settings,
        *,
        deletion_id: str,
        tenant_id: str,
        owner: str,
        step: str,
    ) -> None:
        self.settings = settings
        self.deletion_id = deletion_id
        self.tenant_id = tenant_id
        self.owner = owner
        self.step = step

    @contextmanager
    def guard(self) -> Iterator[Session]:
        """A transaction that holds the tenant row, has checked the hold, and owns the lease."""
        with system_session(self.settings) as session:
            tenant = session.execute(
                select(models.Tenant)
                .where(models.Tenant.tenant_id == self.tenant_id)
                .with_for_update()
            ).scalar_one_or_none()
            if tenant is not None:
                legal_hold.assert_not_on_hold(session, self.tenant_id, action="tenant.delete")
            self.renew(session)
            yield session

    def checkpoint(self) -> None:
        """The guard with nothing inside: call it before each external batch."""
        with self.guard():
            pass

    def renew(self, session: Session) -> None:
        from api.services.tenant_lifecycle import STATE_PURGING

        result = session.execute(
            update(models.TenantDeletion)
            .where(
                models.TenantDeletion.deletion_id == self.deletion_id,
                models.TenantDeletion.lease_owner == self.owner,
                models.TenantDeletion.state == STATE_PURGING,
            )
            .values(lease_until=now() + timedelta(seconds=LEASE_SECONDS))
        )
        if result.rowcount != 1:
            raise LeaseLost(f"deletion {self.deletion_id} is no longer held by {self.owner}")

    def add_counts(self, session: Session, counts: dict[str, int]) -> None:
        """Add to this step's counts in ``session`` — the batch's own transaction."""
        row = session.get(models.TenantDeletionStep, (self.deletion_id, self.step))
        if row is None:  # pragma: no cover - the journal row outlives every step
            return
        merged: dict[str, Any] = dict(row.counts or {})
        for key, value in counts.items():
            merged[key] = int(merged.get(key) or 0) + int(value)
        # Reassigned rather than mutated: the column is JSON, and an in-place
        # edit of the loaded value is not seen as a change.
        row.counts = merged

    def note(self, session: Session, **values: Any) -> None:
        """Record non-additive facts (a cursor, a verdict) in this step's counts."""
        row = session.get(models.TenantDeletionStep, (self.deletion_id, self.step))
        if row is None:  # pragma: no cover
            return
        row.counts = {**dict(row.counts or {}), **values}
