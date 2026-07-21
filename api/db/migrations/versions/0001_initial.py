"""Initial schema: tenants, provisioning_keys, assets, asset_identifiers, asset_tags

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-21

"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("tenant_id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "provisioning_keys",
        sa.Column("key_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False),
        sa.Column("label", sa.String(), nullable=False, server_default=""),
        sa.Column("key_hash", sa.String(), nullable=False),
        sa.Column("key_lookup", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_provisioning_keys_tenant_id", "provisioning_keys", ["tenant_id"])
    op.create_index("ix_provisioning_keys_key_lookup", "provisioning_keys", ["key_lookup"])

    op.create_table(
        "assets",
        sa.Column("asset_id", sa.String(length=32), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("owner_email", sa.String(), nullable=True),
        sa.Column("business_unit", sa.String(), nullable=True),
        sa.Column("asset_criticality", sa.Integer(), nullable=True),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])
    op.create_index("ix_assets_tenant_status", "assets", ["tenant_id", "status"])

    op.create_table(
        "asset_identifiers",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.String(length=32), sa.ForeignKey("assets.asset_id"), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("identifier_type", sa.String(), nullable=False),
        sa.Column("identifier_value", sa.String(), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "identifier_type", "identifier_value", name="uq_asset_identifier"
        ),
    )
    op.create_index("ix_asset_identifiers_asset_id", "asset_identifiers", ["asset_id"])
    op.create_index("ix_asset_identifiers_tenant_id", "asset_identifiers", ["tenant_id"])

    op.create_table(
        "asset_tags",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("asset_id", sa.String(length=32), sa.ForeignKey("assets.asset_id"), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.UniqueConstraint("asset_id", "key", name="uq_asset_tag_key"),
    )
    op.create_index("ix_asset_tags_asset_id", "asset_tags", ["asset_id"])


def downgrade() -> None:
    op.drop_table("asset_tags")
    op.drop_table("asset_identifiers")
    op.drop_table("assets")
    op.drop_table("provisioning_keys")
    op.drop_table("tenants")
