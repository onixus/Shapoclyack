"""An Idempotency-Key belongs to the caller who minted it, not to the tenant

Revision ID: 0055_idempotency_actor
Revises: 0053_tenant_scan_policy
Create Date: 2026-09-11

``0044_idempotency_records`` made ``(tenant_id, endpoint, key)`` unique, which
scopes a key to the customer but not to the caller. The console never noticed —
it mints a UUID per click — but the CI integrations ``docs/wiki/scenarios-
architect.md`` documents send *meaningful* keys: ``nightly-triage``,
``triage-2026-09-10``. Those are guessable, and inside one tenant they were a
shared namespace: any member could take ``nightly-triage`` and, for the life of
the record, either 409 somebody else's pipeline (a different body is a
mismatch) or — with a body that happens to match — be handed that pipeline's
report as a replay, with no audit row of their own, because the replay branch
returns before ``record_standalone``.

So the key gets an owner. ``actor`` is the principal string the audit trail
already uses (``service-token:<name>`` for an integration, the username for a
person — see ``ServiceTokenPrincipal.username``), which is exactly the identity
a CI job keeps across retries: the same token retrying the same batch lands on
its own key rather than minting a new one.

**Expand only, and nothing existing is rewritten.** Three moves, none of which
can fail on data that is already there:

* ``actor`` is added **nullable with no default**, so every row written before
  this migration is marked by construction: ``actor IS NULL`` means "reserved
  when keys were a tenant-wide namespace". There is nothing to backfill with —
  the table never recorded who reserved a key — and guessing would be worse
  than saying so.
* the new unique index ``(tenant_id, endpoint, actor, key)`` cannot conflict,
  because every existing row shares ``actor IS NULL`` and was already unique on
  the other three columns.
* the old index is replaced by the **same index restricted to legacy rows**.
  Dropping it outright would leave a replica still running the previous release
  — which writes no ``actor`` — with no uniqueness at all for the length of a
  rolling deploy, and that index is the mechanism by which two replicas racing
  one key are decided, not an optimisation. Restricted to ``actor IS NULL`` it
  guards exactly the rows old code writes and ignores the ones new code does.

The read path handles the rows this leaves behind rather than orphaning them:
``idempotency.reserve`` looks for the caller's own row first and falls back to a
legacy one, so a retry that arrives seconds after the deploy still replays its
answer instead of applying its batch a second time. That fallback and the
partial index are the temporary half of this change; both may go once no legacy
row can exist, which is ``RETENTION_SECONDS`` (24h) after the deploy — the
"contract" step in ``docs/operations.md`` terms, and it needs no migration of
its own because the sweep removes the rows on its own.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0055_idempotency_actor"
down_revision: Union[str, None] = "0053_tenant_scan_policy"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "idempotency_records",
        # Nullable on purpose: NULL is "written before keys had owners", which
        # is a fact about the row and not a missing value to be filled in.
        sa.Column("actor", sa.String(), nullable=True),
    )
    op.create_index(
        "uq_idempotency_tenant_endpoint_actor_key",
        "idempotency_records",
        ["tenant_id", "endpoint", "actor", "key"],
        unique=True,
    )
    op.drop_index("uq_idempotency_tenant_endpoint_key", table_name="idempotency_records")
    op.create_index(
        "uq_idempotency_legacy_tenant_endpoint_key",
        "idempotency_records",
        ["tenant_id", "endpoint", "key"],
        unique=True,
        postgresql_where=sa.text("actor IS NULL"),
        sqlite_where=sa.text("actor IS NULL"),
    )


def downgrade() -> None:
    # Rebuilding the tenant-wide index can fail, and legitimately: after the
    # upgrade two callers may each hold ``nightly-triage`` in one tenant, which
    # is the whole point, and which the old index forbids. Those rows are the
    # memory of a retry window rather than a record of anything, so the
    # duplicates are dropped — the loser of each (tenant, endpoint, key) goes,
    # keeping the row most recently created, and a client mid-retry re-executes
    # its batch, exactly as it would have if the record had been swept.
    op.execute(
        sa.text(
            """
            DELETE FROM idempotency_records a
            USING idempotency_records b
            WHERE a.tenant_id = b.tenant_id
              AND a.endpoint = b.endpoint
              AND a.key = b.key
              AND (a.created_at, a.id) < (b.created_at, b.id)
            """
        )
    )
    op.drop_index("uq_idempotency_legacy_tenant_endpoint_key", table_name="idempotency_records")
    op.create_index(
        "uq_idempotency_tenant_endpoint_key",
        "idempotency_records",
        ["tenant_id", "endpoint", "key"],
        unique=True,
    )
    op.drop_index("uq_idempotency_tenant_endpoint_actor_key", table_name="idempotency_records")
    op.drop_column("idempotency_records", "actor")
