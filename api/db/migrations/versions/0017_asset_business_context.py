"""Asset business context and its audit trail (#146)

Revision ID: 0017_asset_business_context
Revises: 0016_vuln_ticket_link
Create Date: 2026-08-19

#146 is the missing half of "why is this asset risky and who owns it".
Phase 7/9.4 already stored ``owner_email``, ``business_unit`` and
``asset_criticality``. That is not enough for a CMDB-shaped record: an
enterprise asks about the *service*, the *environment*, the *data* on the
box, and whether anyone has *said* it is internet-facing.

These columns are operator-set (or later, CMDB/AD-set via the same PATCH
with ``context_source``). They are **not** inferred from the scan:
internet exposure as a network fact is [#171], identity merge is P4.2.
Writing a guessed exposure here would launder a heuristic as a decision.

``asset_context_events`` is the same contract as ``vulnerability_events``:
every field change is a row in the same transaction as the write. A trail
reassembled from logs afterwards is an approximation.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017_asset_business_context"
down_revision: Union[str, None] = "0016_vuln_ticket_link"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("business_service", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("environment", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("data_classification", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("exposure_level", sa.String(), nullable=True))
    op.add_column("assets", sa.Column("context_source", sa.String(), nullable=True))

    op.create_table(
        "asset_context_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "asset_id",
            sa.String(),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(), nullable=False),
        sa.Column("field", sa.String(), nullable=False),
        sa.Column("old_value", sa.String(), nullable=True),
        sa.Column("new_value", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_asset_context_events_asset_time",
        "asset_context_events",
        ["asset_id", "occurred_at"],
    )
    op.create_index("ix_asset_context_events_tenant", "asset_context_events", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_asset_context_events_tenant", table_name="asset_context_events")
    op.drop_index("ix_asset_context_events_asset_time", table_name="asset_context_events")
    op.drop_table("asset_context_events")
    op.drop_column("assets", "context_source")
    op.drop_column("assets", "exposure_level")
    op.drop_column("assets", "data_classification")
    op.drop_column("assets", "environment")
    op.drop_column("assets", "business_service")
