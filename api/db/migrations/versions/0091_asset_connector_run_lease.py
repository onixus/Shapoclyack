"""Run lease for ServiceNow imports so the fetch holds no row lock (#350)."""
import sqlalchemy as sa
from alembic import op

revision = "0091_asset_connector_run_lease"
down_revision = "0090_asset_import_connector"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("asset_import_connectors", sa.Column("run_lease_until", sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column("asset_import_connectors", "run_lease_until")
