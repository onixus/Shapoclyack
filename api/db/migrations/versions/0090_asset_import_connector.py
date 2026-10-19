"""Tenant ServiceNow CMDB import schedules (#350)."""
import sqlalchemy as sa
from alembic import op

revision = "0090_asset_import_connector"
down_revision = "0089_service_token_rotation"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "asset_import_connectors",
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True),
        sa.Column("base_url", sa.String(), nullable=False),
        sa.Column("table", sa.String(), nullable=False),
        sa.Column("field_mapping", sa.JSON(), nullable=False),
        sa.Column("token_encrypted", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("interval_seconds", sa.Integer(), nullable=False),
        sa.Column("next_run_at", sa.DateTime(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column("last_counts", sa.JSON(), nullable=True),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE asset_import_connectors ENABLE ROW LEVEL SECURITY")
        op.execute("CREATE POLICY shapoclyack_unscoped ON asset_import_connectors AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)")
        op.execute("CREATE POLICY shapoclyack_tenant_isolation ON asset_import_connectors AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())")
        op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON asset_import_connectors TO shapoclyack_tenant")


def downgrade():
    op.drop_table("asset_import_connectors")
