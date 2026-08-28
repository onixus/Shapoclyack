"""SSH host key pinning and a durable deployment journal (#223, #232)

Revision ID: 0024_agent_deployment_security
Revises: 0023_risk_score_snapshots
Create Date: 2026-08-26

Two tables, both belonging to the SSH push deployer:

``agent_ssh_host_keys`` is the per-tenant pin the deployer verifies a target
against before it sends the operator's SSH credentials or a provisioning key.

``agent_deployments`` replaces the process-local run registry, so the status
poll answers on every replica and can be filtered by tenant.

Additive only — nothing reads or writes these tables before this revision, so
the downgrade drops them without touching data that predates it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0024_agent_deployment_security"
down_revision: Union[str, None] = "0023_risk_score_snapshots"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_ssh_host_keys",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("key_type", sa.String(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "host", "port", name="uq_agent_ssh_host_keys_target"),
    )
    op.create_index(
        "ix_agent_ssh_host_keys_tenant_id",
        "agent_ssh_host_keys",
        ["tenant_id"],
        unique=False,
    )

    op.create_table(
        "agent_deployments",
        sa.Column("deploy_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False, server_default=""),
        sa.Column("port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("username", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("stage", sa.String(), nullable=False, server_default=""),
        sa.Column("progress_percent", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("logs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("deploy_id"),
    )
    op.create_index(
        "ix_agent_deployments_tenant_id",
        "agent_deployments",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_agent_deployments_tenant_started",
        "agent_deployments",
        ["tenant_id", "started_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_agent_deployments_tenant_started", table_name="agent_deployments")
    op.drop_index("ix_agent_deployments_tenant_id", table_name="agent_deployments")
    op.drop_table("agent_deployments")
    op.drop_index("ix_agent_ssh_host_keys_tenant_id", table_name="agent_ssh_host_keys")
    op.drop_table("agent_ssh_host_keys")
