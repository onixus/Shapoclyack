"""Accepted risk gets a requester, an approver and an expiry sweep (#348)

Revision ID: 0050_vuln_exception_approval
Revises: 0049_rbac_permissions
Create Date: 2026-09-11

``POST /api/vulnerabilities/{id}/exception`` wrote ``exception_until`` under
one tenant admin: the person who wanted the SLA clock stopped was also the
person who stopped it, and nothing ever said the acceptance had lapsed. These
eleven columns are the second signature and the paper trail around it.

``exception_state`` is the machine (``api/services/vuln_states.py``):
``none → exception_requested → exception_approved | exception_rejected``, with
``exception_approved → exception_expired`` written by the SLA worker's sweep.
The request columns say what was asked for and by whom; the decision columns
say who answered and what they wrote. The requester survives the decision
deliberately — a register that cannot say who asked cannot show that two people
were involved, which is the whole control.

The acceptance in force gets columns of its own on top of those
(``exception_approved_at``, ``exception_approved_requested_by``), because the
request columns describe *the latest request*, and asking for an extension
overwrites them while the window somebody signed is still running. So the
register and the expiry sweep read "there is an approved window"
(``exception_until`` with an ``exception_by``) rather than "the workflow state
is ``exception_approved``", and ``exception_expired_at`` — not the state — is
what makes the sweep announce each lapse once.

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
    # The acceptance in force, kept apart from the request that is waiting.
    # ``exception_reason``/``exception_by`` plus these two are the row the risk
    # register prints; the request columns above are overwritten by the next
    # ask, and an ask is not an acceptance.
    op.add_column(
        "vulnerabilities", sa.Column("exception_requested_reason", sa.String(), nullable=True)
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_approved_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("exception_approved_requested_by", sa.String(), nullable=True),
    )
    op.add_column(
        "vulnerabilities", sa.Column("exception_expired_at", sa.DateTime(), nullable=True)
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
                   exception_decided_at = updated_at,
                   exception_approved_requested_by = exception_by,
                   exception_approved_at = updated_at,
                   -- An acceptance that had already run out is recorded as
                   -- lapsed here as well as in ``exception_state``. Without it
                   -- the first sweep after the upgrade would announce, as
                   -- fresh news, every expiry of the last several years.
                   exception_expired_at = CASE
                       WHEN exception_until <= NOW() AT TIME ZONE 'UTC'
                       THEN exception_until
                   END
             WHERE exception_until IS NOT NULL
            """
        )
    )

    # Two reads want an index: the register report (one tenant's acceptances,
    # ordered by expiry) and the worker's expiry sweep. Both select on the
    # window rather than on the workflow state — an acceptance whose extension
    # is pending is still in force — so the deadline comes second.
    op.create_index(
        "ix_vulnerabilities_exception_state",
        "vulnerabilities",
        ["tenant_id", "exception_until", "exception_state"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_exception_state", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "exception_expired_at")
    op.drop_column("vulnerabilities", "exception_approved_requested_by")
    op.drop_column("vulnerabilities", "exception_approved_at")
    op.drop_column("vulnerabilities", "exception_requested_reason")
    op.drop_column("vulnerabilities", "exception_decision_note")
    op.drop_column("vulnerabilities", "exception_decided_at")
    op.drop_column("vulnerabilities", "exception_decided_by")
    op.drop_column("vulnerabilities", "exception_requested_until")
    op.drop_column("vulnerabilities", "exception_requested_at")
    op.drop_column("vulnerabilities", "exception_requested_by")
    op.drop_column("vulnerabilities", "exception_state")
