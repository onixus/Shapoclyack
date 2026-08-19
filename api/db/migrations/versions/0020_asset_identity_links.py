"""IP↔FQDN↔certificate correlation evidence (P4.2)

Revision ID: 0020_asset_identity_links
Revises: 0019_network_exposure
Create Date: 2026-08-19

A certificate on an IP that asserts an FQDN, plus forward DNS to that IP,
is evidence the two observations are one asset. Shared hosting is not.
This table is the named trail: we do not merge silently.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020_asset_identity_links"
down_revision: Union[str, None] = "0019_network_exposure"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_identity_links",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("ip", sa.String(), nullable=False),
        sa.Column("fqdn", sa.String(), nullable=False),
        sa.Column("sources", sa.String(), nullable=False),
        sa.Column("confidence", sa.String(), nullable=False),
        sa.Column("shared", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("merged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("survivor_id", sa.String(), nullable=True),
        sa.Column("run_id", sa.String(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "ip", "fqdn", name="uq_asset_identity_link"),
    )
    op.create_index("ix_asset_identity_links_tenant_id", "asset_identity_links", ["tenant_id"])
    op.create_index("ix_asset_identity_links_survivor", "asset_identity_links", ["survivor_id"])


def downgrade() -> None:
    op.drop_index("ix_asset_identity_links_survivor", table_name="asset_identity_links")
    op.drop_index("ix_asset_identity_links_tenant_id", table_name="asset_identity_links")
    op.drop_table("asset_identity_links")
