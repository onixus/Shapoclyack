"""Authentication audit trail + login rate-limit counter (#157)

Revision ID: 0014_auth_events
Revises: 0013_users
Create Date: 2026-08-14

``POST /api/auth/login`` had no rate limit, so guessing a password was bounded
only by network throughput, and neither successful nor failed logins were
recorded anywhere — "someone guessed the admin password" looked exactly like
normal use in the logs and in ``/metrics``.

One table serves both halves. The audit is the row set read forwards; the
limiter is the same rows counted inside a window for one ``(username,
client_ip)`` pair. A dedicated counter table would need to agree with the log
it summarises, and would still want this table's index.

The counter has to live in Postgres rather than in the process: with more than
one API replica an in-memory limit is divided by the replica count, and which
replica serves an attempt is the load balancer's choice.

``username`` is intentionally not a foreign key to ``users`` — attempts naming
an account that does not exist are the ones worth keeping.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014_auth_events"
down_revision: Union[str, None] = "0013_users"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "auth_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("username", sa.String(), nullable=False, server_default=""),
        sa.Column("client_ip", sa.String(), nullable=False, server_default=""),
        sa.Column("outcome", sa.String(), nullable=False, server_default="failure"),
        sa.Column("reason", sa.String(), nullable=True),
    )
    # Listing order for the admin endpoint, which reads newest-first with no
    # other predicate.
    op.create_index("ix_auth_events_occurred_at", "auth_events", ["occurred_at"])
    # The limiter's predicate, in its own column order: one pair's recent rows.
    op.create_index(
        "ix_auth_events_pair", "auth_events", ["username", "client_ip", "occurred_at"]
    )
    op.create_index("ix_auth_events_ip", "auth_events", ["client_ip", "occurred_at"])


def downgrade() -> None:
    op.drop_index("ix_auth_events_ip", table_name="auth_events")
    op.drop_index("ix_auth_events_pair", table_name="auth_events")
    op.drop_index("ix_auth_events_occurred_at", table_name="auth_events")
    op.drop_table("auth_events")
