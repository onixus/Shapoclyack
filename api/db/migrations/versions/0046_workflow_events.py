"""Workflow events: the once-only markers and the per-tenant escalation policy (#349)

Revision ID: 0046_workflow_events
Revises: 0043_user_mfa
Create Date: 2026-09-10

Two new tables, both additive.

``workflow_event_markers`` is what makes a *derived* condition emittable
exactly once. ``sla_state`` is computed on read from ``due_at`` and the clock,
so "this finding is breached" is true again every time anything looks at it;
the escalation worker looks every few minutes. Without a durable record of
having said it, the tenant's on-call would be paged on every tick for the rest
of the finding's life. The unique constraint over
``(tenant_id, kind, subject_id, marker)`` is the claim itself, which is what
makes a brief double-leader — the advisory lock is not fenced — send one
notification between the two replicas rather than one each. ``marker`` carries
the deadline (or the deadline and the threshold, or an agent's
``last_seen_at``), so a clock that restarts produces a new marker and is
announced again.

``sla_escalation_policies`` is the other half of an SLA: what happens when the
deadline passes. One row per tenant, and the absence of a row deliberately
does **not** disable the ``sla_due_soon``/``sla_breached`` events — those are
notifications and every tenant gets them. What the row gates is the part that
writes to somebody's queue (reassignment, a severity bump) and the part that
sends outbound mail (the owner digest), both off until a tenant admin asks.
That is the same fail-open shape as ``tenant_quotas`` (migration 0031) and the
opposite of the approved scan scope, for the same reason: neither is a
security boundary.

**Nothing is backfilled and there is no contract phase.** Both tables are new,
no reader precedes them, and the markers they would have wanted for the past
were never written down — inventing them would suppress the first
announcement of every breach an installation already has. A rolling deploy
therefore has old replicas that emit nothing and new ones that emit, and the
first tick after the upgrade announces the tenant's *current* breaches once.
An installation that would rather not have that as its introduction to the
feature sets ``OCTO_SLA_ESCALATION_ENABLED=false`` before the upgrade and
turns it on when it is ready.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0046_workflow_events"
down_revision: Union[str, None] = "0045_vuln_ticket_sync_cursor"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sla_escalation_policies",
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("escalate_after_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("escalate_to", sa.String(), nullable=True),
        sa.Column("escalate_owner_team", sa.String(), nullable=True),
        sa.Column("bump_severity", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("digest_enabled", sa.Boolean(), nullable=False, server_default="false"),
        # Naive UTC, like every other timestamp column in this schema: a
        # timestamptz filled with a naive UTC value is reinterpreted by the
        # session's TimeZone, which nothing in this repo pins.
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id"),
    )
    op.create_table(
        "workflow_event_markers",
        sa.Column("marker_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("subject_id", sa.String(), nullable=False),
        sa.Column("marker", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("marker_id"),
        # The claim. Two replicas that both believe they lead insert the same
        # key, and exactly one of them wins it.
        sa.UniqueConstraint(
            "tenant_id", "kind", "subject_id", "marker", name="uq_workflow_event_marker"
        ),
    )
    op.create_index(
        "ix_workflow_event_markers_tenant_id", "workflow_event_markers", ["tenant_id"]
    )
    # The retention sweep's predicate, and it is not covered by the unique
    # constraint above: pruning is "everything older than a cutoff" across
    # every tenant at once.
    op.create_index(
        "ix_workflow_event_markers_created_at", "workflow_event_markers", ["created_at"]
    )


def downgrade() -> None:
    # Lossy in one direction worth naming: dropping the markers loses the
    # record of what has already been announced, so a re-upgrade re-announces
    # every currently breached finding once. The escalation policies are
    # configuration and simply go.
    op.drop_index("ix_workflow_event_markers_created_at", table_name="workflow_event_markers")
    op.drop_index("ix_workflow_event_markers_tenant_id", table_name="workflow_event_markers")
    op.drop_table("workflow_event_markers")
    op.drop_table("sla_escalation_policies")
