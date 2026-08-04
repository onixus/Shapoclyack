"""Software changes: tenant-scoped timestamp index + backfill removed-event names

Revision ID: 0005_endpoint_changes_fix
Revises: 0004_endpoint_inventory
Create Date: 2026-08-04

The cross-device recent-changes feed (``GET /endpoint/changes``, issue #98
Phase 3) orders by ``observed_at`` within a tenant. The only existing index
is ``(device_id, observed_at)`` (per-device history), so a tenant-wide query
had to fall back to the standalone ``tenant_id`` index and sort in memory.
Adds ``(tenant_id, observed_at)`` to keep that query index-only as history
grows.

Also backfills ``display_name`` for pre-existing ``removed`` events: the
diff logic that wrote them only looked up names from the *new* snapshot's
software list, which never contains a removed item, so every such row was
stored with ``display_name=''``. ``comparison_key`` is a deterministic hash
of (name, publisher, architecture, source) — see
``api/services/endpoint_inventory.py::_comparison_key`` — so any
``endpoint_software_items`` row for the same device sharing that key has
the same name.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_endpoint_changes_fix"
down_revision: Union[str, None] = "0004_endpoint_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE endpoint_software_changes
            SET display_name = (
                SELECT i.name
                FROM endpoint_software_items AS i
                WHERE i.device_id = endpoint_software_changes.device_id
                  AND i.comparison_key = endpoint_software_changes.comparison_key
                LIMIT 1
            )
            WHERE event_type = 'removed'
              AND (display_name IS NULL OR display_name = '')
              AND EXISTS (
                  SELECT 1
                  FROM endpoint_software_items AS i
                  WHERE i.device_id = endpoint_software_changes.device_id
                    AND i.comparison_key = endpoint_software_changes.comparison_key
              )
            """
        )
    )
    op.create_index(
        "ix_endpoint_software_changes_tenant_time",
        "endpoint_software_changes",
        ["tenant_id", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_endpoint_software_changes_tenant_time", table_name="endpoint_software_changes"
    )
    # The display_name backfill is not reversible (the original empty-string
    # value carried no information worth restoring).
