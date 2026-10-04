"""Tenant-owned custom compliance definitions, including the tenant RLS fence.

Revision ID: 0068_compliance_frameworks
Revises: 0067_tenant_rls
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0068_compliance_frameworks"
down_revision = "0067_tenant_rls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_framework_definitions",
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("framework_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("scope_note", sa.String(), nullable=False),
        sa.Column("control_count", sa.Integer(), nullable=False),
        sa.Column("definition", sa.JSON().with_variant(postgresql.JSONB(), "postgresql"), nullable=False),
        sa.Column("definition_sha256", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("tenant_id", "framework_id"),
    )
    if op.get_bind().dialect.name == "postgresql":
        # Match 0067's two-policy design: system workers retain their access;
        # the tenant role is additionally restricted on reads AND writes.
        op.execute(sa.text("ALTER TABLE compliance_framework_definitions ENABLE ROW LEVEL SECURITY"))
        op.execute(sa.text(
            "CREATE POLICY shapoclyack_unscoped ON compliance_framework_definitions "
            "AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
        ))
        op.execute(sa.text(
            "CREATE POLICY shapoclyack_tenant_isolation ON compliance_framework_definitions "
            "AS RESTRICTIVE FOR ALL TO shapoclyack_tenant "
            "USING (tenant_id = shapoclyack_current_tenant()) "
            "WITH CHECK (tenant_id = shapoclyack_current_tenant())"
        ))
        op.execute(sa.text(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_framework_definitions "
            "TO shapoclyack_tenant"
        ))


def downgrade() -> None:
    op.drop_table("compliance_framework_definitions")
