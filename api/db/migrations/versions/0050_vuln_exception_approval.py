"""Accepted risk gets a requester, an approver and an expiry sweep (#348)

Revision ID: 0050_vuln_exception_approval
Revises: 0049_rbac_permissions
Create Date: 2026-09-11

``POST /api/vulnerabilities/{id}/exception`` wrote ``exception_until`` under
one tenant admin: the person who wanted the SLA clock stopped was also the
person who stopped it, and nothing ever said the acceptance had lapsed. These
seven columns are the second signature and the paper trail around it.

``exception_state`` is the machine (``api/services/vuln_states.py``):
``none → exception_requested → exception_approved | exception_rejected``, with
``exception_approved → exception_expired`` written by the SLA worker's sweep.
The request columns say what was asked for and by whom; the decision columns
say who answered and what they wrote. The requester survives the decision
deliberately — a register that cannot say who asked cannot show that two people
were involved, which is the whole control.

**Expand, and the in-force columns keep their meaning.** ``exception_until``,
``exception_reason`` and ``exception_by`` still describe the acceptance that is
in force; nothing reads them differently after this upgrade, so a replica on
the old code goes on suspending clocks correctly for rows it finds. The one
shift is that ``exception_by`` now holds the *approver*, which for every row
that existed before this migration was the same person as the requester.

**The backfill is honest about that.** Every row with an unexpired
``exception_until`` becomes ``exception_approved`` with the requester and the
approver both set to its ``exception_by`` — because that is what happened, and
writing a NULL approver instead would let the register report pre-#348
self-approvals as properly approved. A row whose acceptance had already run out
becomes ``exception_expired`` for the same reason: it is the truth, and it puts
those findings in the register's "expired" half where somebody will see them.

No contract phase to schedule: nothing is being replaced, and no column is
dropped.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0050_vuln_exception_approval"
down_revision: Union[str, None] = "0049_rbac_permissions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Naive UTC, like every other timestamp in this schema.
    op.add_column(
        "vulnerabilities",
        sa.Column(
            "exception_state",
            sa.String(),
            nullable=False,
            server_default="none",
        ),
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_requested_by", sa.String(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_requested_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_requested_until", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_decided_by", sa.String(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_decided_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_decision_note", sa.String(), nullable=True)
    )

    # The backfill. ``updated_at`` is the closest thing the old schema kept to
    # "when the acceptance was written"; it is the wrong answer for a row
    # touched afterwards, which is why the register renders these decisions
    # with the same person on both sides rather than claiming a review.
    op.execute(
        sa.text(
            """
            UPDATE vulnerabilities
               SET exception_state = CASE
                       WHEN exception_until > NOW() AT TIME ZONE 'UTC'
                       THEN 'exception_approved'
                       ELSE 'exception_expired'
                   END,
                   exception_requested_by = exception_by,
                   exception_requested_at = updated_at,
                   exception_requested_until = exception_until,
                   exception_decided_by = exception_by,
                   exception_decided_at = updated_at
             WHERE exception_until IS NOT NULL
            """
        )
    )

    # Two reads want an index: the register report (one tenant's acceptances,
    # newest decision first) and the worker's expiry sweep, which is the same
    # tenant plus a state and a deadline.
    op.create_index(
        "ix_vulnerabilities_exception_state",
        "vulnerabilities",
        ["tenant_id", "exception_state", "exception_until"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_exception_state", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "exception_decision_note")
    op.drop_column("vulnerabilities", "exception_decided_at")
    op.drop_column("vulnerabilities", "exception_decided_by")
    op.drop_column("vulnerabilities", "exception_requested_until")
    op.drop_column("vulnerabilities", "exception_requested_at")
    op.drop_column("vulnerabilities", "exception_requested_by")
    op.drop_column("vulnerabilities", "exception_state")
