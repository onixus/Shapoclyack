"""Keep the distribution and package revision of a listener in fields of their own.

``asset_services.version`` holds the upstream version (``8.2p1``); the package
revision (``4ubuntu0.13``) used to be recoverable only by re-reading the banner
text. Expand step only: two nullable-free columns defaulting to ``''``. Old
rows keep ``''`` and the retro matcher keeps reading their banner; a listener's
next scan fills them. Nothing is dropped or rewritten.
"""

import sqlalchemy as sa
from alembic import op

revision = "0084_asset_service_distro"
down_revision = "0083_agent_cert_material"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("asset_services", sa.Column("distro", sa.String(), nullable=False, server_default=""))
    op.add_column("asset_services", sa.Column("distro_revision", sa.String(), nullable=False, server_default=""))


def downgrade():
    op.drop_column("asset_services", "distro_revision")
    op.drop_column("asset_services", "distro")
