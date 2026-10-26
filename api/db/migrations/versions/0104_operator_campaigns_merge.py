"""Join confirmed operator tools and remediation campaigns without rewriting history.

Alembic applies whichever parent branch is missing before reaching this node.
The merge itself has no DDL or data changes; both existing lineages stay valid.
"""

revision = "0104_operator_campaigns_merge"
down_revision = ("0103_operator_planner", "0101_remediation_campaigns")
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
