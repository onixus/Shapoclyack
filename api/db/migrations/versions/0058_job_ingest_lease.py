"""Ingest lease: fence the result upload at the final write, not only at the door

Revision ID: 0058_job_ingest_lease
Revises: 0057_endpoint_agent_management
Create Date: 2026-09-21

``complete_job`` verified the claim's attempt and the owning agent under a row
lock, closed that transaction, and then spent the length of an archive
extraction — plus artifact writes that are network I/O — outside any
transaction. Its terminal write took the lock again but compared nothing, so a
lease that lapsed inside that window, and a ``reap_expired_leases`` that handed
the job to a second attempt, left the first attempt free to finish somebody
else's work: ``claimed/running → succeeded`` is a legal transition whoever asks
for it.

Four columns, all expand-only and all NULL for every job that is not being
ingested at this instant:

``jobs.ingest_token``
    Reserved by the upload that is being processed. The terminal write is
    conditional on it, which is what makes "this result is stale" a decision
    rather than a race.

``jobs.ingest_attempt`` / ``jobs.ingest_agent_id``
    The attempt and owner the ingest started under, so the condition names the
    same triple the door check did — a restarted worker keeps its ``agent_id``,
    and the attempt is the only thing that tells two of its uploads apart.

``jobs.ingest_started_at``
    When it began. For the operator looking at a row that is neither finished
    nor idle; the deadline is ``claimed_until``, which the reservation pushes
    forward because an upload in flight is proof of life.

Rolling deploy: a replica still running the old code never writes these and
never reads them, so it keeps ingesting exactly as unfenced as it is today,
while a replica on the new code fences its own uploads. No backfill — an
ingest in flight across the deploy is one nobody can name after the fact, and
writing a token for it would claim knowledge this migration does not have.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0058_job_ingest_lease"
down_revision: Union[str, None] = "0057_endpoint_agent_management"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("ingest_token", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("ingest_attempt", sa.Integer(), nullable=True))
    op.add_column("jobs", sa.Column("ingest_agent_id", sa.String(), nullable=True))
    op.add_column("jobs", sa.Column("ingest_started_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    # An upload being processed at this moment loses its fence and finishes the
    # way it did before this revision. Nothing else reads these columns.
    op.drop_column("jobs", "ingest_started_at")
    op.drop_column("jobs", "ingest_agent_id")
    op.drop_column("jobs", "ingest_attempt")
    op.drop_column("jobs", "ingest_token")
