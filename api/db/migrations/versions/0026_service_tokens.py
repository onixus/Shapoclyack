"""Service tokens, and the federated-identity columns SSO links accounts by

Revision ID: 0026_service_tokens
Revises: 0025_tenant_scan_scopes
Create Date: 2026-08-30

Two halves of the same gap (ROADMAP Track E, "No SSO"): the platform had one
way to authenticate a human and one way to authenticate an agent, and nothing
in between. Both live here because both are identity storage and an
installation upgrading for one gets the other in the same step.

``service_tokens`` holds only a bcrypt hash of the secret, exactly like
``provisioning_keys``. ``token_prefix`` is the non-secret public half, unique
and indexed, so verifying a presented token is one row lookup plus one bcrypt
check rather than a bcrypt check per issued token. ``expires_at`` is NOT NULL:
the service layer always computes one, because a credential with no expiry is
a credential nobody rotates.

The ``users`` columns are the SSO link. ``email``/``email_verified`` exist so
an existing local account can be matched to a provider identity — and only
when the address is verified on both sides. ``oidc_issuer``/``oidc_subject``
are the durable identifier once that link is made, unique together so two
console accounts cannot claim the same provider identity. All four are
nullable and default to "no federated identity", so nothing changes for an
installation that never configures a provider.

The downgrade drops the table and the four columns; any SSO link and every
issued service token goes with them, which is the state that preceded the
upgrade.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0026_service_tokens"
down_revision: Union[str, None] = "0025_tenant_scan_scopes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "service_tokens",
        sa.Column("token_id", sa.String(), nullable=False),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("token_prefix", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False, server_default=""),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.tenant_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("token_id"),
    )
    op.create_index(
        "ix_service_tokens_tenant_id", "service_tokens", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_service_tokens_token_prefix", "service_tokens", ["token_prefix"], unique=True
    )

    op.add_column("users", sa.Column("email", sa.String(), nullable=True))
    op.add_column(
        "users",
        sa.Column("email_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("users", sa.Column("oidc_issuer", sa.String(), nullable=True))
    op.add_column("users", sa.Column("oidc_subject", sa.String(), nullable=True))
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_unique_constraint(
        "uq_users_oidc_identity", "users", ["oidc_issuer", "oidc_subject"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_users_oidc_identity", "users", type_="unique")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_column("users", "oidc_subject")
    op.drop_column("users", "oidc_issuer")
    op.drop_column("users", "email_verified")
    op.drop_column("users", "email")

    op.drop_index("ix_service_tokens_token_prefix", table_name="service_tokens")
    op.drop_index("ix_service_tokens_tenant_id", table_name="service_tokens")
    op.drop_table("service_tokens")
