"""Scan schedules: per-tenant recurring scan dispatch (Phase 8.5)

Revision ID: 0003_scan_schedules
Revises: 0002_config_overrides
Create Date: 2026-07-24

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_scan_schedules"
down_revision: Union[str, None] = "0002_config_overrides"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("schedule_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("cron", sa.String(), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("scan_options", sa.JSON(), nullable=False),
        sa.Column("targets", sa.JSON(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_job_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
    )
    op.create_index("ix_scan_schedules_tenant_id", "scan_schedules", ["tenant_id"])
    op.create_index(
        "ix_scan_schedules_tenant_enabled", "scan_schedules", ["tenant_id", "enabled"]
    )


def downgrade() -> None:
    op.drop_index("ix_scan_schedules_tenant_enabled", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_tenant_id", table_name="scan_schedules")
    op.drop_table("scan_schedules")
