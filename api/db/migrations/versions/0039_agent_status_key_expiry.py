"""Agent lifecycle state, agent↔key binding, and provisioning key expiry (#308)

Revision ID: 0039_agent_status_key_expiry
Revises: 0036_oidc_pending_states
Create Date: 2026-09-09

An agent JWT named an ``agent_id`` that nothing checked against the row, and
deleting an agent left the provisioning key it registered with fully valid — so
the same host re-registered on its next poll and the operator's "delete" was a
pause. Three columns close that:

``agents.lifecycle_status`` is the operator's verdict (active | disabled |
quarantined). Deliberately **not** the existing ``agents.status``, which holds
what the agent last reported about itself (idle/busy/error, with "stale"
derived on read). Overloading one column would have let a heartbeat overwrite a
quarantine, and would have made ``?q=disabled`` on the fleet list ambiguous
between "an operator disabled it" and "it says it is disabled".

``agents.provisioning_key_id`` records which key the agent registered with, so
``DELETE /api/agents/{id}?revoke_key=true`` has something to revoke.

``provisioning_keys.expires_at`` is filled at mint time from
``OCTO_PROVISIONING_KEY_TTL_DAYS``.

**Expand only; nothing is backfilled and nothing is dropped.**
``lifecycle_status`` gets ``server_default='active'``, which is both the value
existing rows take and the honest one: an agent already in the fleet was never
disabled. The other two stay NULL, and NULL is meaningful in each case rather
than a gap waiting to be filled:

* ``provisioning_key_id`` — nothing ever recorded which key an existing agent
  used, and it is not recoverable. Those agents answer "no key to revoke" on
  delete until they re-register, which rewrites the column. The API says so
  in the delete response instead of pretending the key is gone.
* ``expires_at`` — every key minted before this migration is **perpetual and
  stays perpetual**. Stamping a TTL onto keys an operator was never told had
  one would silently strand whichever fleets are past it; expiring old keys is
  an operator act (``POST .../provisioning-keys/{id}/revoke``), and the key
  list marks the unexpiring ones so they can be found.

A rolling deploy is safe in both directions: old API code never reads these
columns, and new code treats every one of them as optional.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0039_agent_status_key_expiry"
down_revision: Union[str, None] = "0036_oidc_pending_states"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column(
            "lifecycle_status",
            sa.String(length=32),
            nullable=False,
            server_default="active",
        ),
    )
    op.add_column("agents", sa.Column("lifecycle_reason", sa.String(length=512), nullable=True))
    op.add_column("agents", sa.Column("provisioning_key_id", sa.String(length=64), nullable=True))
    op.create_index("ix_agents_provisioning_key_id", "agents", ["provisioning_key_id"])
    op.create_foreign_key(
        "fk_agents_provisioning_key_id",
        "agents",
        "provisioning_keys",
        ["provisioning_key_id"],
        ["key_id"],
    )
    # Naive UTC, like every other timestamp in this schema and like
    # `api/services/tenants.py::_now`, which writes it. A `timestamptz` filled
    # with a naive UTC value is reinterpreted by the session's TimeZone, which
    # nothing in this repo pins, so on an installation not running UTC a key
    # would expire early or never.
    op.add_column("provisioning_keys", sa.Column("expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    # Lossy, and knowingly so: a downgrade restores the state where the only
    # way to stop an agent is to delete it and revoke its key by hand.
    op.drop_column("provisioning_keys", "expires_at")
    op.drop_constraint("fk_agents_provisioning_key_id", "agents", type_="foreignkey")
    op.drop_index("ix_agents_provisioning_key_id", table_name="agents")
    op.drop_column("agents", "provisioning_key_id")
    op.drop_column("agents", "lifecycle_reason")
    op.drop_column("agents", "lifecycle_status")
