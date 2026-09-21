"""Ingest lease and run publications: fence the upload, then owe its publication

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

``run_publications`` is the other half, and it is what makes the ordering
question answerable at all. Publishing a run *before* the terminal write lets
a straggler's archive into the run directory, the store and the ingest bus
before anything refused it; publishing it *after* lets a store outage leave a
job reported ``succeeded`` with no scan behind it. Neither order is right,
because the publication is not an ordering problem: it is work that must
happen exactly once, after a decision, and survive the process that decided.
So the terminal write and one row here are the same transaction, and
``api/services/run_publisher.py`` redoes that row's publication — store, run
directory, ``latest_run.json``, ``ingest.results.{tenant}`` — until it is done
or until ``run_publication_max_attempts`` is spent, at which point the row
stays ``dead`` where an operator and ``/api/health`` can see it.

``publication_id`` is the ingest lease token from the columns above, so the
two are one mechanism: exactly one publication per accepted upload, and none
at all for an upload the fence refused.

The table is created here rather than altered by a later revision because it
is born in this release: no installation has one to migrate, and a column
added by ``0059`` to a table ``0058`` had just created would be expand/contract
theatre over an empty table.

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
    op.create_table(
        "run_publications",
        # The ingest lease token of the upload this publication is owed for.
        sa.Column("publication_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("job_status", sa.String(), nullable=False, server_default="succeeded"),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("scan_error", sa.String(), nullable=True),
        sa.Column("surface", sa.String(), nullable=True),
        # Paths on ``replica``'s disk: the extracted tree, and the archive the
        # bus message is built from. Not the payload itself — one ingest body
        # is megabytes of base64 and this table is read on a timer.
        sa.Column("staging_path", sa.String(), nullable=False, server_default=""),
        sa.Column("archive_path", sa.String(), nullable=True),
        sa.Column("replica", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        # Claims that reached no outcome. ``attempts`` counts refusals from the
        # store or the broker; a replica that dies mid-publication records
        # neither, and without this a row it keeps taking is retried forever
        # with nothing to see it (see ``_claims_spent`` in the publisher).
        sa.Column("claims", sa.Integer(), nullable=False, server_default="0"),
        # Naive UTC like every other timestamp in this schema.
        sa.Column("next_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("publication_id"),
    )
    op.create_index("ix_run_publications_tenant_id", "run_publications", ["tenant_id"])
    op.create_index("ix_run_publications_job_id", "run_publications", ["job_id"])
    op.create_index("ix_run_publications_run_id", "run_publications", ["run_id"])
    # The reconciler's predicate, running on every replica on a timer.
    op.create_index(
        "ix_run_publications_due", "run_publications", ["status", "next_attempt_at"]
    )
    op.create_index(
        "ix_run_publications_tenant_status",
        "run_publications",
        ["tenant_id", "status", "created_at"],
    )


def downgrade() -> None:
    # Drain the table first (``status='pending'`` empty): a row dropped here is
    # a run that was accepted, is on a replica's disk and will never be
    # published — the job says ``succeeded`` and nothing else remembers.
    op.drop_index("ix_run_publications_tenant_status", table_name="run_publications")
    op.drop_index("ix_run_publications_due", table_name="run_publications")
    op.drop_index("ix_run_publications_run_id", table_name="run_publications")
    op.drop_index("ix_run_publications_job_id", table_name="run_publications")
    op.drop_index("ix_run_publications_tenant_id", table_name="run_publications")
    op.drop_table("run_publications")
    # An upload being processed at this moment loses its fence and finishes the
    # way it did before this revision. Nothing else reads these columns.
    op.drop_column("jobs", "ingest_started_at")
    op.drop_column("jobs", "ingest_agent_id")
    op.drop_column("jobs", "ingest_attempt")
    op.drop_column("jobs", "ingest_token")
