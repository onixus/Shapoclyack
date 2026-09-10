"""Idempotency keys for write endpoints that create no row of their own (#346)

Revision ID: 0044_idempotency_records
Revises: 0043_user_mfa
Create Date: 2026-09-10

``POST /api/jobs`` has been idempotent since P1.5, and it could be without a
table: a scan start *inserts a job*, so the unique index on
``(jobs.tenant_id, jobs.idempotency_key)`` hangs the key on the thing the
request produced and a replay is that row. The bulk verbs added in #346 —
``POST /api/vulnerabilities/bulk`` and ``POST /api/assets/bulk`` — produce no
such row: they edit findings and assets that already exist, and their answer is
a per-id report. There is nowhere to hang the key, so it gets a table.

``(tenant_id, endpoint, key)`` is unique, and that index is the mechanism, not
an optimisation: a lookup-then-insert is something two API replicas can both
pass, while the second INSERT here fails and the request is told the first one
is running. ``response`` is NULL for exactly that window — reserved, not yet
answered.

**Expand only, nothing to backfill, and nothing reads it that did not ship in
the same release.** During a rolling deploy an old replica does not know the
table and simply has no bulk endpoints; a new one uses it. The rows are the
memory of a retry window rather than a record of anything, so the "contract"
phase of this change is the TTL sweep in ``api/services/idempotency.py``, not a
later migration.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0044_idempotency_records"
down_revision: Union[str, None] = "0043_user_mfa"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "idempotency_records",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        # No foreign key to tenants: a stale key outliving its tenant is
        # harmless, and the row is purged by age anyway.
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("request_digest", sa.String(), nullable=False, server_default=""),
        # NULL while the request that reserved the key is still running.
        sa.Column("response", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        # Naive UTC, like every other timestamp column in this schema: a
        # timestamptz filled with a naive UTC value is reinterpreted by the
        # session's TimeZone, which nothing in this repo pins.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_idempotency_tenant_endpoint_key",
        "idempotency_records",
        ["tenant_id", "endpoint", "key"],
        unique=True,
    )
    op.create_index("ix_idempotency_created_at", "idempotency_records", ["created_at"])


def downgrade() -> None:
    # Lossless in the only sense that matters: what is dropped is the memory of
    # which retries have already been answered, so a client mid-retry after a
    # rollback re-executes its batch. The batch verbs themselves go away with
    # the code, so there is nobody left to retry.
    op.drop_index("ix_idempotency_created_at", table_name="idempotency_records")
    op.drop_index("uq_idempotency_tenant_endpoint_key", table_name="idempotency_records")
    op.drop_table("idempotency_records")
