"""Durable model intent-selection requests; no automatic side effects."""
from alembic import op
import sqlalchemy as sa

revision = "0103_operator_planner"
down_revision = "0102_operator_semantic"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("operator_tasks", sa.Column("payload", sa.JSON(), nullable=True))
    with op.batch_alter_table("operator_tasks") as batch:
        batch.drop_constraint("ck_operator_task_kind", type_="check")
        batch.create_check_constraint("ck_operator_task_kind",
            "kind IN ('summarize_run','analyze_run','plan_request')")


def downgrade():
    if op.get_bind().execute(sa.text("SELECT 1 FROM operator_tasks WHERE kind='plan_request' LIMIT 1")).first():
        raise RuntimeError("Export and remove planner history before downgrade")
    with op.batch_alter_table("operator_tasks") as batch:
        batch.drop_constraint("ck_operator_task_kind", type_="check")
        batch.create_check_constraint("ck_operator_task_kind", "kind IN ('summarize_run','analyze_run')")
    op.drop_column("operator_tasks", "payload")
