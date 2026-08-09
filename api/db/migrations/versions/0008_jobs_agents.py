"""Durable control plane: jobs and agents in Postgres (ROADMAP P1.1)

Revision ID: 0008_jobs_agents
Revises: 0007_user_tenants
Create Date: 2026-08-09

Both registries used to be module-level dicts in the API process, mirrored to
``state/api_jobs.json`` / ``state/api_agents.json``. That made every API
replica a separate control plane and lost in-flight state on restart.

No data migration runs here: ``api/services/{jobs,agents}.py`` import the
legacy JSON files once at startup (if present) and rename them to
``*.imported``, so an upgrade keeps its history without this migration having
to parse operator state files.

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008_jobs_agents"
down_revision: Union[str, None] = "0007_user_tenants"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("agent_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False
        ),
        sa.Column("hostname", sa.String(), nullable=False, server_default=""),
        sa.Column("version", sa.String(), nullable=False, server_default=""),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="idle"),
        sa.Column("current_job_id", sa.String(), nullable=True),
        sa.Column("detail", sa.String(), nullable=True),
        sa.Column("registered_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])
    op.create_index("ix_agents_tenant_last_seen", "agents", ["tenant_id", "last_seen_at"])

    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False
        ),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("execution", sa.String(), nullable=False, server_default="local"),
        sa.Column("mode", sa.String(), nullable=False, server_default="balanced"),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("command", sa.JSON(), nullable=False),
        sa.Column("scan_options", sa.JSON(), nullable=False),
        sa.Column("target_counts", sa.JSON(), nullable=True),
        sa.Column("requested_by", sa.String(), nullable=False, server_default=""),
        sa.Column("assigned_agent_id", sa.String(), nullable=True),
        sa.Column("owner_id", sa.String(), nullable=True),
        sa.Column("queued_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("asset_upsert_error", sa.Text(), nullable=True),
    )
    op.create_index("ix_jobs_tenant_id", "jobs", ["tenant_id"])
    op.create_index("ix_jobs_run_id", "jobs", ["run_id"])
    op.create_index("ix_jobs_assigned_agent_id", "jobs", ["assigned_agent_id"])
    op.create_index("ix_jobs_tenant_status", "jobs", ["tenant_id", "status"])
    op.create_index(
        "ix_jobs_claim", "jobs", ["execution", "status", "tenant_id", "queued_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_jobs_claim", table_name="jobs")
    op.drop_index("ix_jobs_tenant_status", table_name="jobs")
    op.drop_index("ix_jobs_assigned_agent_id", table_name="jobs")
    op.drop_index("ix_jobs_run_id", table_name="jobs")
    op.drop_index("ix_jobs_tenant_id", table_name="jobs")
    op.drop_table("jobs")
    op.drop_index("ix_agents_tenant_last_seen", table_name="agents")
    op.drop_index("ix_agents_tenant_id", table_name="agents")
    op.drop_table("agents")
