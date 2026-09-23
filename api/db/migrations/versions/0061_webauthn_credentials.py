"""WebAuthn / passkeys: registered security keys and their one-time challenges

Revision ID: 0061_webauthn_credentials
Revises: 0059_nats_outbox
Create Date: 2026-09-23

Two new tables, additive, with no backfill and no contract phase (#315). There
is no reader before them: an account that has never registered a key simply
has no rows, and every path that asks "does this account hold a phishing-
resistant factor" reads an empty set as "no", which is what it was.

``webauthn_credentials`` is one registered authenticator. What is stored is
what the relying party needs to check the next assertion and nothing more: the
credential id the browser hands back, the COSE public key, and the signature
counter. None of it is secret — the private key never leaves the
authenticator — so nothing here goes through the secret envelope the TOTP seed
does. ``credential_id`` is globally unique because the WebAuthn spec makes it
so, and because a second account registering the same id is either a broken
authenticator or somebody replaying another account's registration.

``webauthn_challenges`` is the server half of a ceremony in flight. A row is
written by the options endpoint and **deleted** by the verification that
consumes it, whether that verification then succeeds or not — that is what
makes a challenge single-use. ``binding`` is the ``jti`` of the token that
asked for it (the pre-authentication token on a login, the session on a
step-up or a registration), so a challenge minted for one ceremony cannot be
spent by another. Rows are short-lived (``expires_at``) and swept by the writer.

Both carry ``username`` as a real FK with ``ON DELETE CASCADE``: a deleted
account's keys authenticate nothing, and keeping them would only let a later
account under the same name inherit them.

Rolling upgrade is safe in both directions: an old replica never reads either
table, and a new replica on an old schema is not a state this migration
creates — it runs before any replica starts.

Rollback is a plain drop. Every registered key is lost with it, so accounts
fall back to their authenticator app — which is still enrolled, because a key
can only be added on top of one — and any role listed in
``OCTO_MFA_PHISHING_RESISTANT_ROLES`` is confined until it registers again.
Unset that variable before downgrading.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0061_webauthn_credentials"
# Reserved number; 0060 is being taken by a parallel branch. Re-point at
# whichever revision is head when this merges.
down_revision: Union[str, None] = "0059_nats_outbox"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "webauthn_credentials",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        # base64url, as the browser reports it in ``rawId``. Text rather than
        # bytea so it is the same string in the API, the audit trail and here.
        sa.Column("credential_id", sa.String(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        # The authenticator's signature counter at the last accepted assertion.
        # BigInteger: the spec's counter is an unsigned 32-bit value.
        sa.Column("sign_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("aaguid", sa.String(), nullable=False, server_default=""),
        sa.Column("transports", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("backed_up", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("device_type", sa.String(), nullable=False, server_default=""),
        # Naive UTC like every other timestamp in this schema.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_used_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
        sa.UniqueConstraint("credential_id", name="uq_webauthn_credentials_credential_id"),
    )
    op.create_index(
        "ix_webauthn_credentials_username", "webauthn_credentials", ["username"]
    )

    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("binding", sa.String(), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["username"], ["users.username"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_webauthn_challenges_username", "webauthn_challenges", ["username"]
    )
    op.create_index(
        "ix_webauthn_challenges_expires_at", "webauthn_challenges", ["expires_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_webauthn_challenges_expires_at", table_name="webauthn_challenges")
    op.drop_index("ix_webauthn_challenges_username", table_name="webauthn_challenges")
    op.drop_table("webauthn_challenges")
    op.drop_index("ix_webauthn_credentials_username", table_name="webauthn_credentials")
    op.drop_table("webauthn_credentials")
