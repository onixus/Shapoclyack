"""Promoted related domains as durable per-tenant scope (org_profile M4, EPIC #182)

Revision ID: 0031_tenant_promoted_domains
Revises: 0030_tenant_quotas
Create Date: 2026-09-04


``POST /runs/{id}/related-domains/{domain}/promote`` used to append the domain
to ``promoted_domains.txt`` inside the run directory, and that was the whole
feature: nothing read the file back when the next scan started, and the run
retention worker (#187) deleted it with the run after ``OCTO_RUN_RETENTION_DAYS``.
An operator's decision that a discovered domain belongs to the organisation is
not a property of the run that happened to discover it — it is a property of
the tenant, and it has to outlive both the run and the API replica that
recorded it.

One row per (tenant, domain). ``source_run_id`` keeps the evidence trail
(which run proposed it, so the operator can go back to its
``related_domains.json``), ``promoted_by``/``promoted_at`` keep the decision
attributable. Deleting the row is how a promotion is withdrawn: the plan's
own risk table says an attribution error means scanning somebody else's
infrastructure, so a promote that cannot be undone is not acceptable.

Nothing is grandfathered: the per-run files were never consumed, so there is
no behaviour to preserve. Operators who promoted domains before this revision
promote them again from the run's Org Profile tab.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0031_tenant_promoted_domains"
down_revision: Union[str, None] = "0030_tenant_quotas"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_promoted_domains",
        sa.Column("tenant_id", sa.String(length=64), primary_key=True),
        sa.Column("domain", sa.String(length=253), primary_key=True),
        sa.Column("source_run_id", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("promoted_by", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("tenant_promoted_domains")
