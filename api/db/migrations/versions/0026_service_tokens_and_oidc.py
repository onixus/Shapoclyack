"""Service tokens and OIDC identity links (Sprint 1 Enterprise IAM)

Revision ID: 0026_service_tokens_and_oidc
Revises: 0025_tenant_scan_scopes
Create Date: 2026-08-31
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026_service_tokens_and_oidc"
down_revision: Union[str, None] = "0025_tenant_scan_scopes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Service Tokens table
    op.create_table(
        "service_tokens",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("key_hash", sa.String(length=256), nullable=False),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="viewer"),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_service_tokens_key_prefix",
        "service_tokens",
        ["key_prefix"],
        unique=False,
    )
    op.create_index(
        "ix_service_tokens_tenant_id",
        "service_tokens",
        ["tenant_id"],
        unique=False,
    )

    # 2. OIDC Identities table
    op.create_table(
        "oidc_identities",
        sa.Column("id", sa.Integer(), autoincrement=True, primary_key=True, nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("issuer", sa.String(length=256), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=False),
        sa.Column("email", sa.String(length=256), nullable=True),
        sa.Column("claims", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
        sa.UniqueConstraint("issuer", "subject", name="uq_oidc_issuer_subject"),
    )
    op.create_index(
        "ix_oidc_identities_username",
        "oidc_identities",
        ["username"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_oidc_identities_username", table_name="oidc_identities")
    op.drop_table("oidc_identities")
    op.drop_index("ix_service_tokens_tenant_id", table_name="service_tokens")
    op.drop_index("ix_service_tokens_key_prefix", table_name="service_tokens")
    op.drop_table("service_tokens")
