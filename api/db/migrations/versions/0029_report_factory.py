"""Report factory: branding, templates, schedules and generated reports (Sprint 4)

Revision ID: 0029_report_factory
Revises: 0028_vuln_remediation_loop
Create Date: 2026-08-31


Four tables, one per thing that outlives a render: how a tenant's reports look
(``tenant_branding``), what they contain (``report_templates``), when they are
sent and to whom (``report_schedules``), and what was produced
(``generated_reports``).

The rendered bytes are *not* here. They are written under
``output_dir/reports/`` and referenced by a relative ``storage_path``, so this
migration adds no large-object column and a downgrade drops only bookkeeping —
the files stay on disk for an operator to remove deliberately.

``report_schedules.cron`` is NOT NULL with no interval alternative, unlike
``scan_schedules``: a report cadence people ask for is "the first of the
month" and "every Monday at 08:00", neither of which a fixed interval can
express, and offering both would only invite a schedule that drifts a day per
quarter.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029_report_factory"
down_revision: Union[str, None] = "0028_vuln_remediation_loop"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_branding",
        sa.Column("tenant_id", sa.String(length=64), primary_key=True),
        sa.Column("org_name", sa.String(length=200), nullable=True),
        sa.Column("primary_color", sa.String(length=16), nullable=True),
        sa.Column("accent_color", sa.String(length=16), nullable=True),
        # Base64 PNG. Text rather than LargeBinary so the JSON API can carry it
        # without a second transport, and capped by the service at 512 KiB.
        sa.Column("logo_png", sa.Text(), nullable=True),
        sa.Column("footer_text", sa.String(length=500), nullable=True),
        sa.Column("contact_email", sa.String(length=320), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
    )

    op.create_table(
        "report_templates",
        sa.Column("template_id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False, server_default="executive"),
        sa.Column("framework_id", sa.String(length=64), nullable=True),
        sa.Column("sections", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "name", name="uq_report_template_name"),
    )
    op.create_index("ix_report_templates_tenant", "report_templates", ["tenant_id"])

    op.create_table(
        "report_schedules",
        sa.Column("schedule_id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        sa.Column("template_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("cron", sa.String(length=120), nullable=False),
        sa.Column("fmt", sa.String(length=16), nullable=False, server_default="pdf"),
        sa.Column("recipients", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_report_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["template_id"], ["report_templates.template_id"], ondelete="CASCADE"
        ),
    )
    op.create_index(
        "ix_report_schedules_tenant_enabled", "report_schedules", ["tenant_id", "enabled"]
    )

    op.create_table(
        "generated_reports",
        sa.Column("report_id", sa.String(length=64), primary_key=True),
        sa.Column("tenant_id", sa.String(length=64), nullable=False),
        # Deliberately not FKs: a report is a record of what was sent, and
        # deleting the template it was rendered from must not delete the
        # evidence that a customer received it.
        sa.Column("template_id", sa.String(length=64), nullable=True),
        sa.Column("schedule_id", sa.String(length=64), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False, server_default="executive"),
        sa.Column("fmt", sa.String(length=16), nullable=False, server_default="pdf"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("title", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("storage_path", sa.String(length=500), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("delivery", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("generated_by", sa.String(length=200), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_generated_reports_tenant_time", "generated_reports", ["tenant_id", "generated_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_generated_reports_tenant_time", table_name="generated_reports")
    op.drop_table("generated_reports")
    op.drop_index("ix_report_schedules_tenant_enabled", table_name="report_schedules")
    op.drop_table("report_schedules")
    op.drop_index("ix_report_templates_tenant", table_name="report_templates")
    op.drop_table("report_templates")
    op.drop_table("tenant_branding")
