"""Historical risk score snapshots (#144, Track C)

Revision ID: 0023_risk_score_snapshots
Revises: 0022_ticket_transports
Create Date: 2026-08-23

Stores periodic and run-triggered snapshots of estate risk posture,
severity counts, and SLA breaches for trend reporting.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023_risk_score_snapshots"
down_revision: Union[str, None] = "0022_ticket_transports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "risk_score_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("estate_risk", sa.String(), nullable=True),
        sa.Column("open_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("untriaged", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unassigned", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("breached", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("worst_breached_severity", sa.String(), nullable=True),
        sa.Column("by_severity_open", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("by_risk_level_open", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("by_state", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("by_sla", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("source", sa.String(), nullable=False, server_default="run"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_risk_score_snapshots_snapshot_id",
        "risk_score_snapshots",
        ["snapshot_id"],
        unique=True,
    )
    op.create_index(
        "ix_risk_score_snapshots_tenant_id",
        "risk_score_snapshots",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_risk_snapshots_tenant_time",
        "risk_score_snapshots",
        ["tenant_id", "recorded_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_risk_snapshots_tenant_time", table_name="risk_score_snapshots")
    op.drop_index("ix_risk_score_snapshots_tenant_id", table_name="risk_score_snapshots")
    op.drop_index("ix_risk_score_snapshots_snapshot_id", table_name="risk_score_snapshots")
    op.drop_table("risk_score_snapshots")
