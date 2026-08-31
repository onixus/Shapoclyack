"""Endpoint CVE advisories & patch gap analysis (Sprint 3)

Revision ID: 0028_endpoint_cve_advisories
Revises: 0027_vuln_remediation_loop
Create Date: 2026-08-31
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0028_endpoint_cve_advisories"
down_revision: Union[str, None] = "0027_vuln_remediation_loop"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "endpoint_software_advisories",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column(
            "device_id",
            sa.String(length=64),
            sa.ForeignKey("endpoint_devices.device_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(length=64),
            sa.ForeignKey("assets.asset_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("software_name", sa.String(length=255), nullable=False),
        sa.Column("installed_version", sa.String(length=128), nullable=True),
        sa.Column("fixed_version", sa.String(length=128), nullable=True),
        sa.Column("purl", sa.String(length=512), nullable=True),
        sa.Column("cpe", sa.String(length=512), nullable=True),
        sa.Column("cve", sa.String(length=64), nullable=False),
        sa.Column("advisory_id", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False, server_default="medium"),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("vuln_id", sa.String(length=64), nullable=True),
        sa.Column("matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "device_id", "software_name", "cve", name="uq_endpoint_software_advisory"
        ),
    )
    op.create_index(
        "ix_endpoint_software_advisories_tenant",
        "endpoint_software_advisories",
        ["tenant_id"],
    )
    op.create_index(
        "ix_endpoint_software_advisories_device",
        "endpoint_software_advisories",
        ["device_id"],
    )
    op.create_index(
        "ix_endpoint_software_advisories_cve",
        "endpoint_software_advisories",
        ["cve"],
    )
    op.create_index(
        "ix_endpoint_software_advisories_asset",
        "endpoint_software_advisories",
        ["asset_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_endpoint_software_advisories_asset", table_name="endpoint_software_advisories")
    op.drop_index("ix_endpoint_software_advisories_cve", table_name="endpoint_software_advisories")
    op.drop_index("ix_endpoint_software_advisories_device", table_name="endpoint_software_advisories")
    op.drop_index("ix_endpoint_software_advisories_tenant", table_name="endpoint_software_advisories")
    op.drop_table("endpoint_software_advisories")
