"""Store native installer variants without overwriting another package format.

Revision ID: 0081_endpoint_release_variants
Revises: 0080_endpoint_inventory_v2
"""

from alembic import op
import sqlalchemy as sa

revision = "0081_endpoint_release_variants"
down_revision = "0080_endpoint_inventory_v2"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "endpoint_agent_releases",
        sa.Column(
            "package_kind",
            sa.String(),
            nullable=False,
            server_default="binary",
        ),
    )
    op.execute("""UPDATE endpoint_agent_releases
        SET package_kind = signed_manifest->'manifest'->>'package_kind'
        WHERE signed_manifest->'manifest'->>'package_kind' IS NOT NULL""")
    op.drop_constraint(
        "endpoint_agent_releases_pkey", "endpoint_agent_releases", type_="primary"
    )
    op.create_primary_key(
        "endpoint_agent_releases_pkey",
        "endpoint_agent_releases",
        ["version", "platform", "package_kind"],
    )


def downgrade():
    # Returning to a two-column key must never silently discard fleet builds.
    duplicate = (
        op.get_bind()
        .execute(
            sa.text("""SELECT 1 FROM endpoint_agent_releases
        GROUP BY version, platform HAVING COUNT(*) > 1 LIMIT 1""")
        )
        .first()
    )
    if duplicate:
        raise RuntimeError(
            "remove duplicate installer variants before downgrading release storage"
        )
    op.drop_constraint(
        "endpoint_agent_releases_pkey", "endpoint_agent_releases", type_="primary"
    )
    op.create_primary_key(
        "endpoint_agent_releases_pkey",
        "endpoint_agent_releases",
        ["version", "platform"],
    )
    op.drop_column("endpoint_agent_releases", "package_kind")
