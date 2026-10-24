"""Durable tenant asset classification rules and provenance (#578)."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0100_asset_groups"
down_revision = "0099_operator_analysis_task"
branch_labels = None
depends_on = None

_TABLES = (
    "asset_groups",
    "asset_group_versions",
    "asset_group_memberships",
    "asset_group_evaluations",
    "asset_group_provenance",
    "asset_group_sweeps",
)


def upgrade():
    op.create_table(
        "asset_groups",
        sa.Column("id", sa.String(), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column("name", sa.String(), primary_key=False, nullable=False),
        sa.Column("description", sa.String(), primary_key=False, nullable=False),
        sa.Column("enabled", sa.Boolean(), primary_key=False, nullable=False),
        sa.Column("deleted", sa.Boolean(), primary_key=False, nullable=False),
        sa.Column("priority", sa.Integer(), primary_key=False, nullable=False),
        sa.Column("version", sa.Integer(), primary_key=False, nullable=False),
        sa.Column("rules", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("context", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("created_at", sa.DateTime(), primary_key=False, nullable=False),
        sa.Column("updated_at", sa.DateTime(), primary_key=False, nullable=False),
    )
    op.create_index("ix_asset_groups_tenant_id", "asset_groups", ["tenant_id"])
    op.create_table(
        "asset_group_versions",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), primary_key=False, nullable=False),
        sa.Column(
            "group_id",
            sa.String(),
            sa.ForeignKey("asset_groups.id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), primary_key=False, nullable=False),
        sa.Column("document", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("actor", sa.String(), primary_key=False, nullable=True),
        sa.Column("created_at", sa.DateTime(), primary_key=False, nullable=False),
        sa.UniqueConstraint("group_id", "version", name="uq_asset_group_version"),
    )
    op.create_index(
        "ix_asset_group_versions_tenant_id", "asset_group_versions", ["tenant_id"]
    )
    op.create_index(
        "ix_asset_group_versions_group_id", "asset_group_versions", ["group_id"]
    )
    op.create_table(
        "asset_group_memberships",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), primary_key=False, nullable=False),
        sa.Column(
            "group_id",
            sa.String(),
            sa.ForeignKey("asset_groups.id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column(
            "asset_id",
            sa.String(),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), primary_key=False, nullable=False),
        sa.Column("reasons", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("evaluated_at", sa.DateTime(), primary_key=False, nullable=False),
        sa.UniqueConstraint("group_id", "asset_id", name="uq_asset_group_member"),
    )
    op.create_index(
        "ix_asset_group_memberships_asset_id", "asset_group_memberships", ["asset_id"]
    )
    op.create_index(
        "ix_asset_group_memberships_group_id", "asset_group_memberships", ["group_id"]
    )
    op.create_index(
        "ix_asset_group_memberships_tenant_id", "asset_group_memberships", ["tenant_id"]
    )
    op.create_table(
        "asset_group_evaluations",
        sa.Column("id", sa.String(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), primary_key=False, nullable=False),
        sa.Column(
            "group_id",
            sa.String(),
            sa.ForeignKey("asset_groups.id", ondelete="CASCADE"),
            primary_key=False,
            nullable=True,
        ),
        sa.Column("version", sa.Integer(), primary_key=False, nullable=True),
        sa.Column("status", sa.String(), primary_key=False, nullable=False),
        sa.Column("started_at", sa.DateTime(), primary_key=False, nullable=False),
        sa.Column("completed_at", sa.DateTime(), primary_key=False, nullable=True),
        sa.Column("report", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("error", sa.String(), primary_key=False, nullable=True),
    )
    op.create_index(
        "ix_asset_group_evaluations_tenant_id", "asset_group_evaluations", ["tenant_id"]
    )
    op.create_index(
        "ix_asset_group_evaluations_group_id", "asset_group_evaluations", ["group_id"]
    )
    op.create_table(
        "asset_group_provenance",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(), primary_key=False, nullable=False),
        sa.Column(
            "asset_id",
            sa.String(),
            sa.ForeignKey("assets.asset_id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column("field", sa.String(), primary_key=False, nullable=False),
        sa.Column(
            "group_id",
            sa.String(),
            sa.ForeignKey("asset_groups.id", ondelete="CASCADE"),
            primary_key=False,
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), primary_key=False, nullable=False),
        sa.Column("value", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("previous", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("reason", sa.JSON().with_variant(JSONB(), "postgresql"), primary_key=False, nullable=False),
        sa.Column("updated_at", sa.DateTime(), primary_key=False, nullable=False),
        sa.UniqueConstraint("asset_id", "field", name="uq_asset_group_field"),
    )
    op.create_index(
        "ix_asset_group_provenance_asset_id", "asset_group_provenance", ["asset_id"]
    )
    op.create_index(
        "ix_asset_group_provenance_tenant_id", "asset_group_provenance", ["tenant_id"]
    )
    op.create_table(
        "asset_group_sweeps",
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("after_asset_id", sa.String(), primary_key=False, nullable=True),
        sa.Column("updated_at", sa.DateTime(), primary_key=False, nullable=False),
    )
    for name in _TABLES:
        if op.get_bind().dialect.name == "postgresql":
            op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
            op.execute(
                f"CREATE POLICY shapoclyack_unscoped ON {name} AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
            )
            op.execute(
                f"CREATE POLICY shapoclyack_tenant_isolation ON {name} AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())"
            )
            op.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO shapoclyack_tenant"
            )
            if name in (
                "asset_group_versions",
                "asset_group_memberships",
                "asset_group_provenance",
            ):
                op.execute(
                    f"GRANT USAGE, SELECT ON SEQUENCE {name}_id_seq TO shapoclyack_tenant"
                )


def downgrade():
    for name in reversed(_TABLES):
        op.drop_table(name)
