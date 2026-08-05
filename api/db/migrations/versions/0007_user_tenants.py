"""Tenant-aware IAM: user -> tenant memberships (ROADMAP P0)

Revision ID: 0007_user_tenants
Revises: 0006_endpoint_fk_cascade
Create Date: 2026-08-04

Binds console usernames (still sourced from ``OCTO_API_USERS``) to tenants
with a per-tenant role. No credential material is stored. Existing
installations need no data migration: a user with no rows keeps pre-P0
behaviour and acts in the ``default`` tenant with their configured global
role — see api/services/memberships.py.

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_user_tenants"
down_revision: Union[str, None] = "0006_endpoint_fk_cascade"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_tenants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
    )
    op.create_index("ix_user_tenants_username", "user_tenants", ["username"])
    op.create_index("ix_user_tenants_tenant_id", "user_tenants", ["tenant_id"])
    op.create_unique_constraint("uq_user_tenant", "user_tenants", ["username", "tenant_id"])


def downgrade() -> None:
    op.drop_constraint("uq_user_tenant", "user_tenants", type_="unique")
    op.drop_index("ix_user_tenants_tenant_id", table_name="user_tenants")
    op.drop_index("ix_user_tenants_username", table_name="user_tenants")
    op.drop_table("user_tenants")
