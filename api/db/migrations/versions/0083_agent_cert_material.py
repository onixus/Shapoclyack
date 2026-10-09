"""Keep verified certificate material for issuer-scoped CRLs (#515).

Old rows have no reconstructible certificate: do not guess their issuer from
the source or serial. The CRL exporter requires operator-supplied PEM for
unexpired revoked legacy records.
"""

import sqlalchemy as sa
from alembic import op

revision = "0083_agent_cert_material"
down_revision = "0082_idempotency_actor_contract"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "agent_client_certs",
        sa.Column("certificate_pem", sa.Text(), nullable=False, server_default=""),
    )


def downgrade():
    op.drop_column("agent_client_certs", "certificate_pem")
