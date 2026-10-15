"""Personal tenant-scoped console views (#357)."""

import sqlalchemy as sa
from alembic import op

revision = "0091_console_saved_views"
down_revision = "0090_asset_import_connector"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "console_saved_views",
        sa.Column("view_id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("page", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("state", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_console_saved_views_owner",
        "console_saved_views",
        ["tenant_id", "username", "page"],
    )
    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE console_saved_views ENABLE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY shapoclyack_unscoped ON console_saved_views AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
        )
        op.execute(
            "CREATE POLICY shapoclyack_tenant_isolation ON console_saved_views AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())"
        )
        op.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON console_saved_views TO shapoclyack_tenant"
        )


def downgrade():
    op.drop_table("console_saved_views")
