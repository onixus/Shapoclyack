"""Confirmed operator action claims and bounded outcome evidence (#589)."""
from alembic import op
import sqlalchemy as sa

revision = "0101_operator_actions"
down_revision = "0100_asset_groups"
branch_labels = None
depends_on = None


def upgrade():
    for table, old in (("operator_proposals", "ck_operator_proposal_reserved"),
                       ("operator_executions", "ck_operator_execution_reserved")):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(old, type_="check")
            batch.create_check_constraint(old, "status IN ('reserved','preview','executing','succeeded','failed','unknown')")
    op.add_column("operator_executions", sa.Column("payload", sa.JSON(), nullable=True))
    with op.batch_alter_table("operator_executions") as batch:
        batch.create_unique_constraint("uq_operator_execution_proposal", ["proposal_id"])


def downgrade():
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT 1 FROM operator_proposals WHERE status <> 'reserved' LIMIT 1")).first():
        raise RuntimeError("Operator actions must be exported and removed before downgrade")
    if connection.execute(sa.text("SELECT 1 FROM operator_executions WHERE status <> 'reserved' LIMIT 1")).first():
        raise RuntimeError("Operator execution evidence must be exported and removed before downgrade")
    with op.batch_alter_table("operator_executions") as batch:
        batch.drop_constraint("uq_operator_execution_proposal", type_="unique")
    op.drop_column("operator_executions", "payload")
    for table, name in (("operator_proposals", "ck_operator_proposal_reserved"),
                        ("operator_executions", "ck_operator_execution_reserved")):
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(name, type_="check")
            batch.create_check_constraint(name, "status = 'reserved'")
