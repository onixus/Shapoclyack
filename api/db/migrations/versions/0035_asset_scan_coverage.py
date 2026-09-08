"""When an asset was last actually scanned, as distinct from last seen

Revision ID: 0035_asset_scan_coverage
Revises: 0034_vuln_false_positive
Create Date: 2026-09-08

``assets.last_seen`` is moved by anything that observes the host, including an
endpoint agent checking in with its software inventory. Adoption was reading it
as "scanned recently", so a fleet of agents reporting on schedule made an estate
nobody had scanned in months look fully covered — the metric said the opposite
of the truth in exactly the case it exists to catch.

These three columns are written **only** by the scan-ingest path
(``api/services/assets.py``). There is no backfill and there cannot be one:
nothing in the schema records which past run covered which asset. Coverage
therefore reads ``None`` until the columns fill from real runs, which is the
honest answer rather than a zero that reads as a finding.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0035_asset_scan_coverage"
down_revision: Union[str, None] = "0034_vuln_false_positive"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets", sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("assets", sa.Column("last_scan_run_id", sa.String(length=64), nullable=True))
    # Separate from last_scanned_at: a discovery run that only enumerated hosts
    # covers the asset for inventory but says nothing about its vulnerabilities.
    op.add_column(
        "assets", sa.Column("last_vuln_scan_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("assets", "last_vuln_scan_at")
    op.drop_column("assets", "last_scan_run_id")
    op.drop_column("assets", "last_scanned_at")
