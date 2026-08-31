"""Vulnerability remediation loop & machine verification (Sprint 2)

Revision ID: 0028_vuln_remediation_loop
Revises: 0027_software_cve_matches
Create Date: 2026-08-31
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0028_vuln_remediation_loop"
down_revision: Union[str, None] = "0027_software_cve_matches"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
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
    # A verification run is matched back to the findings awaiting it, so the
    # lookup is by job id rather than by asset.
    op.create_index(
        "ix_vulnerabilities_verification_job",
        "vulnerabilities",
        ["verification_job_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_verification_job", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "closure_reason")
    op.drop_column("vulnerabilities", "last_verified_at")
    op.drop_column("vulnerabilities", "verification_job_id")
    op.drop_column("vulnerabilities", "machine_verified")
