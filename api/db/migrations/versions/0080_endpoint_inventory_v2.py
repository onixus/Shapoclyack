"""Installation identity, per-source completeness, and signed endpoint releases.

Revision ID: 0080_endpoint_inventory_v2
Revises: 0079_vuln_detectors
"""

from alembic import op
import sqlalchemy as sa

revision = "0080_endpoint_inventory_v2"
down_revision = "0079_vuln_detectors"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "endpoint_devices",
        sa.Column("software_snapshot_id", sa.String(), nullable=True),
    )
    op.add_column(
        "endpoint_devices",
        sa.Column("source_states", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "endpoint_inventory_snapshots",
        sa.Column("source_states", sa.JSON(), nullable=False, server_default="[]"),
    )
    for name in (
        "product_identity",
        "installation_identity",
        "package_id",
        "scope",
        "install_instance_id",
    ):
        op.add_column(
            "endpoint_software_items", sa.Column(name, sa.String(), nullable=True)
        )
    op.add_column(
        "endpoint_agent_releases",
        sa.Column("signed_manifest", sa.JSON(), nullable=True),
    )
    op.execute("UPDATE endpoint_devices SET software_snapshot_id = latest_snapshot_id")


def downgrade():
    op.drop_column("endpoint_agent_releases", "signed_manifest")
    for name in (
        "product_identity",
        "installation_identity",
        "package_id",
        "scope",
        "install_instance_id",
    ):
        op.drop_column("endpoint_software_items", name)
    op.drop_column("endpoint_inventory_snapshots", "source_states")
    op.drop_column("endpoint_devices", "source_states")
    op.drop_column("endpoint_devices", "software_snapshot_id")
