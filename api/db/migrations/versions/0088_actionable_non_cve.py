"""Add non-CVE classification without changing historic finding keys."""
import sqlalchemy as sa
from alembic import op
revision = "0088_actionable_non_cve"
down_revision = "0087_finding_evidence"
branch_labels = None
depends_on = None


def upgrade():
    for name, kind in [("non_cve", sa.JSON()), ("finding_type", sa.String()), ("detector_source", sa.String()),
                       ("template_id", sa.String()), ("remediation", sa.Text())]:
        op.add_column("vulnerabilities", sa.Column(name, kind, nullable=True))


def downgrade():
    for name in ["remediation", "template_id", "detector_source", "finding_type", "non_cve"]:
        op.drop_column("vulnerabilities", name)
