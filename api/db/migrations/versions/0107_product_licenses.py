"""Product license table and platform.license.manage permission (ADR 0007).

Revision ID: 0107_product_licenses
Revises: 0106_saml_session_binding

Stores the installation's signed product license (Lariska, Brand Watch, term).
Seeds ``platform.license.manage`` for platform-admin only — uploading a license
is an installation-wide commercial act, not a tenant admin's.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0107_product_licenses"
down_revision: Union[str, None] = "0106_saml_session_binding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "platform.license.manage"
_DESCRIPTION = "Upload and activate the installation's product license"
_ROLES = ("platform-admin",)


def upgrade() -> None:
    op.create_table(
        "product_licenses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("license_id", sa.String(), nullable=False),
        sa.Column("customer_name", sa.String(), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("valid_from", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("feature_lariska", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "feature_brand_watch", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("note", sa.String(), nullable=False, server_default=""),
        sa.Column("document_json", sa.Text(), nullable=False),
        sa.Column("uploaded_at", sa.DateTime(), nullable=False),
        sa.Column("uploaded_by", sa.String(), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("license_id"),
    )
    op.create_index("ix_product_licenses_license_id", "product_licenses", ["license_id"])
    op.create_index("ix_product_licenses_active", "product_licenses", ["active"])
    # At most one commercially active row; concurrent uploads deactivate then
    # insert, and this stops two active=True rows if they race.
    op.create_index(
        "uq_product_licenses_one_active",
        "product_licenses",
        ["active"],
        unique=True,
        postgresql_where=sa.text("active IS TRUE"),
        sqlite_where=sa.text("active IS 1"),
    )

    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [{"permission_key": _PERMISSION, "description": _DESCRIPTION}],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": _PERMISSION}
            for role_id in _ROLES
        ],
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM role_permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION
        )
    )
    op.execute(
        sa.text("DELETE FROM permissions WHERE permission_key = :key").bindparams(
            key=_PERMISSION
        )
    )
    op.drop_index("uq_product_licenses_one_active", table_name="product_licenses")
    op.drop_index("ix_product_licenses_active", table_name="product_licenses")
    op.drop_index("ix_product_licenses_license_id", table_name="product_licenses")
    op.drop_table("product_licenses")
