"""Tenant-uploaded brute-force wordlists (Phase 8.2, UI-managed)

Revision ID: 0012_wordlists
Revises: 0011_webhooks
Create Date: 2026-08-13

Stores custom subdomain/bucket brute-force wordlists in Postgres so operators
can upload them through the API/UI instead of baking a file into the image or
a mounted volume. At local scan start the selected row is materialized to a
file and its path is injected into the job's effective config — see
api/services/wordlists.py and api/services/config_override.py.

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0012_wordlists"
down_revision: Union[str, None] = "0011_webhooks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "wordlists",
        sa.Column("wordlist_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="subdomain"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("line_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sha256", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.UniqueConstraint("tenant_id", "name", name="uq_wordlist_tenant_name"),
    )
    op.create_index("ix_wordlists_tenant_id", "wordlists", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_wordlists_tenant_id", table_name="wordlists")
    op.drop_table("wordlists")
