"""Durable personal operator state (#586), reserved proposals/executions only."""

from alembic import op
import sqlalchemy as sa

revision = "0097_operator_state"
down_revision = "0096_console_saved_views"
branch_labels = None
depends_on = None

_TABLES = (
    "operator_sessions",
    "operator_messages",
    "operator_tasks",
    "operator_proposals",
    "operator_executions",
)


def _owner():
    return [
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("username", sa.String(), nullable=False),
    ]


def upgrade():
    op.create_table(
        "operator_sessions",
        sa.Column("session_id", sa.String(), primary_key=True),
        *_owner(),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_operator_sessions_owner", "operator_sessions", ["tenant_id", "username"]
    )
    op.create_table(
        "operator_messages",
        sa.Column("message_id", sa.String(), primary_key=True),
        *_owner(),
        sa.Column(
            "session_id",
            sa.String(),
            sa.ForeignKey("operator_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("task_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_table(
        "operator_tasks",
        sa.Column("task_id", sa.String(), primary_key=True),
        *_owner(),
        sa.Column(
            "session_id",
            sa.String(),
            sa.ForeignKey("operator_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("actor_token_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("language", sa.String(), nullable=False),
        sa.Column("idempotency_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("lease_owner", sa.String()),
        sa.Column("lease_until", sa.DateTime()),
        sa.Column("result", sa.JSON()),
        sa.Column("error", sa.String()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "username",
            "idempotency_key",
            name="uq_operator_task_idempotency",
        ),
        sa.CheckConstraint("kind = 'summarize_run'", name="ck_operator_task_kind"),
        sa.CheckConstraint(
            "language IN ('ru', 'en')", name="ck_operator_task_language"
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','succeeded','failed','cancelled','interrupted')",
            name="ck_operator_task_status",
        ),
    )
    op.create_index(
        "ix_operator_tasks_queue", "operator_tasks", ["status", "created_at"]
    )
    op.create_table(
        "operator_proposals",
        sa.Column("proposal_id", sa.String(), primary_key=True),
        *_owner(),
        sa.Column(
            "session_id",
            sa.String(),
            sa.ForeignKey("operator_sessions.session_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint("status = 'reserved'", name="ck_operator_proposal_reserved"),
    )
    op.create_table(
        "operator_executions",
        sa.Column("execution_id", sa.String(), primary_key=True),
        *_owner(),
        sa.Column(
            "proposal_id",
            sa.String(),
            sa.ForeignKey("operator_proposals.proposal_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.CheckConstraint(
            "status = 'reserved'", name="ck_operator_execution_reserved"
        ),
    )
    for table in _TABLES[1:]:
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])
    for table in ("operator_messages", "operator_tasks"):
        op.create_index(f"ix_{table}_session_id", table, ["session_id"])
    if op.get_bind().dialect.name == "postgresql":
        for statement in (
            "ALTER TABLE operator_sessions ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY shapoclyack_unscoped ON operator_sessions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)",
            "CREATE POLICY shapoclyack_tenant_isolation ON operator_sessions AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON operator_sessions TO shapoclyack_tenant",
            "ALTER TABLE operator_messages ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY shapoclyack_unscoped ON operator_messages AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)",
            "CREATE POLICY shapoclyack_tenant_isolation ON operator_messages AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON operator_messages TO shapoclyack_tenant",
            "ALTER TABLE operator_tasks ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY shapoclyack_unscoped ON operator_tasks AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)",
            "CREATE POLICY shapoclyack_tenant_isolation ON operator_tasks AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON operator_tasks TO shapoclyack_tenant",
            "ALTER TABLE operator_proposals ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY shapoclyack_unscoped ON operator_proposals AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)",
            "CREATE POLICY shapoclyack_tenant_isolation ON operator_proposals AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON operator_proposals TO shapoclyack_tenant",
            "ALTER TABLE operator_executions ENABLE ROW LEVEL SECURITY",
            "CREATE POLICY shapoclyack_unscoped ON operator_executions AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)",
            "CREATE POLICY shapoclyack_tenant_isolation ON operator_executions AS RESTRICTIVE FOR ALL TO shapoclyack_tenant USING (tenant_id = shapoclyack_current_tenant()) WITH CHECK (tenant_id = shapoclyack_current_tenant())",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON operator_executions TO shapoclyack_tenant",
        ):
            op.execute(statement)


def downgrade():
    for table in reversed(_TABLES):
        op.drop_table(table)
