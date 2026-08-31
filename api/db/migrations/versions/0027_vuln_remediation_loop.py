"""Vulnerability remediation loop & machine verification (Sprint 2)

Revision ID: 0027_vuln_remediation_loop
Revises: 0026_service_tokens_and_oidc
Create Date: 2026-08-31
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0027_vuln_remediation_loop"
down_revision: Union[str, None] = "0026_service_tokens_and_oidc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add verification and closure fields to vulnerabilities
    op.add_column(
        "vulnerabilities",
        sa.Column("machine_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("verification_job_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "vulnerabilities",
        sa.Column("closure_reason", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "closure_reason")
    op.drop_column("vulnerabilities", "last_verified_at")
    op.drop_column("vulnerabilities", "verification_job_id")
    op.drop_column("vulnerabilities", "machine_verified")
