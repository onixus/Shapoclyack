"""Run publications: a lease an operator can read, and a fence that only moves forward

Revision ID: 0062_run_publication_lease
Revises: 0059_nats_outbox
Create Date: 2026-09-23

#425 gives a ``dead`` publication two buttons — requeue and discard — and both
act on a row some attempt may still be working on: a row goes ``dead`` when
*one* attempt records its last failure, and a second attempt that took the row
while the first one's lease lapsed is not told. Neither button may start a
second live publication beside it, nor let a stale attempt take the new one's
keys back off. Three columns, all expand-only:

``leased_until``
    Proof of life. Stamped by every running attempt on every renewal
    (``run_publisher._Lease``), whatever the row's status — unlike
    ``next_attempt_at``, which only a ``pending`` row carries and which a
    ``dead`` row has cleared. An operator action is refused while it is in the
    future. NULL means no attempt has ever renewed this row, which is every row
    written before this revision.

``fence``
    A generation that only moves forward: every claim bumps it, and so does a
    requeue. ``claims`` could not serve: it is reset whenever an attempt records
    an outcome, so an attempt that snapshotted ``claims=1``, lost its lease and
    came back after a peer's failure and a fresh claim read ``1`` again and took
    the new attempt's keys for its own. The rollback fence now asks both.

``lease_lapses``
    How many renewals of this row failed or came too late (#426), so a
    post-mortem can tell which publication ran without its hold. The metric
    ``octo_run_publication_lease_renewal_total`` counts the class; this says
    where.

Rolling deploy: an old replica neither writes nor reads these. Its claims do
not bump ``fence`` — which is why the new rollback still compares ``claims``
as well, so a mixed fleet is fenced exactly as before, never less — and its
attempts never stamp ``leased_until``, so an attempt still running on an old
replica is invisible to the operator's buttons. Requeue and discard only act on
``dead`` rows, which an old replica stops renewing anyway; finish the rollout
before acting on a row that went ``dead`` during it. No backfill: a lease nobody
renewed is not one this migration can invent.

Rollback is a plain drop; the columns carry no state a downgraded replica
could use.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0062_run_publication_lease"
down_revision: Union[str, None] = "0059_nats_outbox"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Naive UTC like every other timestamp in this schema.
    op.add_column("run_publications", sa.Column("leased_until", sa.DateTime(), nullable=True))
    op.add_column(
        "run_publications",
        sa.Column("fence", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "run_publications",
        sa.Column("lease_lapses", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("run_publications", "lease_lapses")
    op.drop_column("run_publications", "fence")
    op.drop_column("run_publications", "leased_until")
