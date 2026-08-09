"""Job leases: claimed_until + attempts (ROADMAP P1.4)

Revision ID: 0009_job_leases
Revises: 0008_jobs_agents
Create Date: 2026-08-09

A job handed to an executor had no deadline, so "the worker is still scanning"
and "the worker died three hours ago" looked identical in the table and the row
stayed in-flight forever. ``claimed_until`` is the deadline the executor keeps
pushing forward while it lives; ``attempts`` bounds how many times a job may be
handed out before the reaper gives up and fails it.

Existing rows get ``claimed_until = NULL``: a job already in flight at upgrade
time has no live lease, and the reaper only considers rows that have one, so
nothing in progress is swept by the migration itself.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009_job_leases"
down_revision: Union[str, None] = "0008_jobs_agents"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("claimed_until", sa.DateTime(), nullable=True))
    op.add_column(
        "jobs",
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_jobs_lease", "jobs", ["status", "claimed_until"])


def downgrade() -> None:
    op.drop_index("ix_jobs_lease", table_name="jobs")
    op.drop_column("jobs", "attempts")
    op.drop_column("jobs", "claimed_until")
