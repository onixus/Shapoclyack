"""SAML NameID on the console session, and which family a logout started.

Revision ID: 0106_saml_session_binding
Revises: 0105_saml_pending_requests

SP-initiated logout has to name the NameID and SessionIndex the IdP issued,
and the SLO callback has to end that console family rather than whichever
browser presented a cookie. Both are nullable: a password session has no
NameID, and a login row has no family yet.

Downgrade drops the three columns and ``family_id``. Sessions keep working;
an in-flight SLO can no longer tell which family it started, and an
IdP-initiated logout can no longer find sessions by NameID until the upgrade
is applied again. No account or artifact row is removed.
"""

import sqlalchemy as sa
from alembic import op

revision = "0106_saml_session_binding"
down_revision = "0105_saml_pending_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("session_families", sa.Column("saml_name_id", sa.String(), nullable=True))
    op.add_column(
        "session_families", sa.Column("saml_name_id_format", sa.String(), nullable=True)
    )
    op.add_column(
        "session_families", sa.Column("saml_session_index", sa.String(), nullable=True)
    )
    op.create_index(
        "ix_session_families_saml_name_id", "session_families", ["saml_name_id"]
    )
    op.add_column(
        "saml_pending_requests", sa.Column("family_id", sa.String(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("saml_pending_requests", "family_id")
    op.drop_index("ix_session_families_saml_name_id", table_name="session_families")
    op.drop_column("session_families", "saml_session_index")
    op.drop_column("session_families", "saml_name_id_format")
    op.drop_column("session_families", "saml_name_id")
