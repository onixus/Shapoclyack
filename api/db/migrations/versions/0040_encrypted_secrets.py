"""Envelope encryption for integration secrets: the KEK id column (#310)

Revision ID: 0040_encrypted_secrets
Revises: 0036_oidc_pending_states
Create Date: 2026-09-09

``webhook_subscriptions.secret`` and the values in ``headers`` are credentials
for somebody else's Jira / ServiceNow / DefectDojo, and they were stored as
typed. Since #310 they are AES-256-GCM envelopes (``api/services/crypto``).

**Expand only, and nothing is re-encrypted here.** The ciphertext is
self-describing — ``v1:<kek_id>:…`` — and the read path accepts plaintext, so
the two forms coexist by design and no migration window is needed. Encrypting
what is already stored is an online, resumable operator step:

    python -m api.db.reencrypt_secrets            # encrypt the plaintext rows
    python -m api.db.reencrypt_secrets --rotate   # rewrap under a new KEK

Doing it here instead would mean an Alembic run holding every tenant's secrets
in memory, needing ``OCTO_MASTER_KEY`` in the initContainer that runs
migrations, and no way to resume a half-finished pass.

``key_id`` mirrors the id inside each ciphertext so that "which rows are still
plaintext" and "which rows are on the previous key" are single predicates
rather than a parse of every column — the startup check in
``api/services/crypto/startup.py`` asks the first on every boot. NULL means
"plaintext, predates this change", which is why it is nullable with no server
default: a backfilled value would claim rows were encrypted when they are not.

No index: the table is capped per tenant
(``OCTO_WEBHOOK_MAX_SUBSCRIPTIONS_PER_TENANT``, default 20), the predicate runs
once per process start and once per re-encryption pass, and an index maintained
on every webhook write to serve that would cost more than it saves.

Contract phase (dropping the plaintext acceptance in ``decrypt_secret``) is
deliberately not scheduled here: it can only follow an installation confirming
``key_id IS NULL`` returns nothing — see docs/operations.md § Secrets at rest.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# Not "0040_encrypted_integration_secrets": alembic_version.version_num is
# varchar(32), and the longer name is 34 characters — the upgrade fails on the
# bookkeeping UPDATE, after the DDL has already been applied.
revision: str = "0040_encrypted_secrets"
down_revision: Union[str, None] = "0036_oidc_pending_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "webhook_subscriptions",
        sa.Column("key_id", sa.String(), nullable=True),
    )


def downgrade() -> None:
    # Only the mirror is dropped. The ciphertext in `secret` and `headers`
    # stays, and the previous code reads it as an opaque string it would sign
    # with or send as a header — so a downgrade past this point has to be
    # preceded by decrypting the rows while the key is still configured:
    #   python -m api.db.reencrypt_secrets --decrypt
    op.drop_column("webhook_subscriptions", "key_id")
