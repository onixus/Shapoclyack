"""Multi-factor authentication: the TOTP enrolment columns on users (#315)

Revision ID: 0043_user_mfa
Revises: 0042_audit_forward_cursors
Create Date: 2026-09-10

A local console account was protected by one password. Everything an admin can
do on this platform — mint a service token, approve a scanning scope, deploy an
agent onto somebody's network — was therefore one leaked or guessed password
away, and the audit trail could only record that the right password had been
presented.

Four columns carry the second factor. ``mfa_secret`` is the base32 RFC 6238
shared secret, stored as an envelope ciphertext (``api/services/crypto``, #310)
under the context ``users.mfa_secret``; it is nullable and NULL for every
account that has not enrolled. ``mfa_enabled_at`` is what "MFA is on for this
account" actually means — a secret alone is an abandoned setup that must not
start challenging anyone. ``mfa_last_step`` is the last time step the account
spent, which is what makes an observed code unusable a second time inside its
own thirty seconds. ``mfa_recovery_codes`` holds bcrypt hashes of the ten
one-time codes, in the same JSON shape the service writes.

**Expand only, and nothing is backfilled.** Every column is nullable (or, for
the JSON list, defaulted to ``[]``), so a replica still running the old code
inserts and updates ``users`` rows exactly as before during a rollout, and an
upgraded installation behaves identically until somebody enrols: no account has
a secret, so no login is challenged. Enforcement is a separate, deliberate act
— ``OCTO_MFA_REQUIRED_ROLES`` is empty by default, which is why this migration
cannot lock anybody out.

There is no contract phase to schedule. The columns are the feature; the only
thing that ever leaves is a row's own secret, which
``POST /api/users/{username}/mfa/reset`` clears.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0043_user_mfa"
down_revision: Union[str, None] = "0042_audit_forward_cursors"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret", sa.String(), nullable=True))
    # Naive UTC, like every other timestamp column in this schema: a
    # timestamptz filled with a naive UTC value is reinterpreted by the
    # session's TimeZone, which nothing in this repo pins.
    op.add_column("users", sa.Column("mfa_enabled_at", sa.DateTime(), nullable=True))
    op.add_column("users", sa.Column("mfa_last_step", sa.BigInteger(), nullable=True))
    op.add_column(
        "users",
        # NOT NULL with a server default rather than nullable: "no codes left"
        # and "never enrolled" are both the empty list, and a NULL here would
        # make every reader defend against a third state that means neither.
        # The default also backfills the existing rows in the DDL itself, so the
        # old code can keep inserting users during the rollout.
        sa.Column("mfa_recovery_codes", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    # Lossy on purpose: dropping the columns disenrols every account, and the
    # recovery codes are hashes that cannot be reconstructed. An installation
    # rolling back past this point should expect its users to re-enrol.
    op.drop_column("users", "mfa_recovery_codes")
    op.drop_column("users", "mfa_last_step")
    op.drop_column("users", "mfa_enabled_at")
    op.drop_column("users", "mfa_secret")
