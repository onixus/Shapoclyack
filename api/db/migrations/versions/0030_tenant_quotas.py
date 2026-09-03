"""Per-tenant usage quotas (ROADMAP Track E, enterprise operations & MSSP)

Revision ID: 0030_tenant_quotas
Revises: 0029_report_factory
Create Date: 2026-09-03


One table, one row per tenant, and it is deliberately unlike the scan scope of
migration 0025 in the one way that matters: **it fails open.** A scope is a
security boundary, so 0025 grandfathered every existing tenant into an
explicit, visibly marked allow-all rather than letting an absent row mean
"anything". A quota is a commercial boundary — the platform refusing scans on
upgrade because nobody had yet sold the customer a number would be an outage
caused by billing, so this revision inserts nothing. No row means the platform
default from ``Settings`` (unlimited unless the operator configured one).

``NULL`` in a limit column is therefore not the same as a missing row: it is a
per-tenant *override* meaning "unlimited for this one", which is how a single
customer is exempted without turning metering off for everybody else.

``jobs.quota_exempt`` is the one column this revision adds outside its own
table. A scan that the platform dispatched to close its own loop — the
verification re-scan of #183 — must neither be refused by a quota nor consume
one, and that is a property of the dispatch, not of the analyst whose name is
on the request. Keyed on a username it would be both wrong (the route passes
the operator's name) and forgeable; as a column it is stamped by the caller
that knows.

There is no usage column here. What a tenant has consumed is counted from
``assets`` and ``jobs`` at read time, so the meter cannot drift away from the
data it claims to measure — a counter column would eventually disagree with
the asset list the same customer is looking at.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0030_tenant_quotas"
down_revision: Union[str, None] = "0029_report_factory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_quotas",
        sa.Column("tenant_id", sa.String(length=64), primary_key=True),
        # NULL = unlimited for this tenant, overriding the platform default.
        sa.Column("max_assets", sa.Integer(), nullable=True),
        sa.Column("max_scans_per_month", sa.Integer(), nullable=True),
        sa.Column("note", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
    )

    op.add_column(
        "jobs",
        sa.Column(
            "quota_exempt", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )


def downgrade() -> None:
    op.drop_column("jobs", "quota_exempt")
    op.drop_table("tenant_quotas")
