"""Idempotency keys for scan start and result upload (ROADMAP P1.5)

Revision ID: 0010_job_idempotency
Revises: 0009_job_leases
Create Date: 2026-08-09

``idempotency_key`` is the client's name for "this scan request", unique per
tenant, so a retried ``POST /api/jobs`` returns the job the first call created
instead of queueing a second scan of the same targets. The uniqueness is
enforced in the database rather than by a read-then-insert, because two API
replicas serving the same retry would both find nothing and both insert.

``results_idempotency_key`` is the same idea for the upload side: it records
which completion the job's terminal state came from, so a replay can be
recognised as a replay rather than as a conflicting second result.

Both are nullable — every job written before this migration, and every client
that sends no key, keeps working unchanged.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010_job_idempotency"
down_revision: Union[str, None] = "0009_job_leases"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("idempotency_key", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("results_idempotency_key", sa.String(), nullable=True))
    # Partial-by-nature: NULLs do not collide in a unique index, so jobs
    # started without a key are unaffected.
    op.create_index(
        "uq_jobs_tenant_idempotency_key",
        "jobs",
        ["tenant_id", "idempotency_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_jobs_tenant_idempotency_key", table_name="jobs")
    op.drop_column("jobs", "results_idempotency_key")
    op.drop_column("jobs", "idempotency_key")
