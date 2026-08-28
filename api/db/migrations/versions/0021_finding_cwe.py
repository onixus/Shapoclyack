"""CWE on tracked findings

Revision ID: 0021_finding_cwe
Revises: 0020_asset_identity_links
Create Date: 2026-08-20

CWE is copied from the latest observation (NVD overlay, else nuclei
classification). Missing stays empty — it is not inferred from the CVE
id, and the UI must not invent a value.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021_finding_cwe"
down_revision: Union[str, None] = "0020_asset_identity_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("cwe", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column("vulnerabilities", "cwe")
