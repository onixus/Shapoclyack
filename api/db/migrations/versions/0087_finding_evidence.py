"""Additive observations; preserve all remediation identity and workflow fields."""
import sqlalchemy as sa
from alembic import op

revision = "0087_finding_evidence"
down_revision = "0086_run_risk_assessments"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("vulnerabilities", sa.Column("finding_evidence", sa.JSON(), nullable=True))


def downgrade():
    op.drop_column("vulnerabilities", "finding_evidence")
