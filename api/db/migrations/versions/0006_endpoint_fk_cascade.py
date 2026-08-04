"""Endpoint inventory: ON DELETE clauses on the endpoint FK chain (S9)

Agent_plan.md decision 9: endpoint data has no bespoke deletion flow and
follows whatever general tenant-offboarding mechanism ships later. The 0004
foreign keys carried no ``ondelete``, so deleting a tenant would fail on an FK
violation instead of removing its endpoint rows. This migration makes the
chain self-clearing:

* ``endpoint_devices.tenant_id`` -> ``tenants`` CASCADE
* ``endpoint_devices.asset_id`` -> ``assets`` SET NULL (unlinking an asset must
  not destroy the endpoint device record)
* identifiers/snapshots/changes -> ``endpoint_devices`` CASCADE
* software items/changes -> ``endpoint_inventory_snapshots`` CASCADE

FK constraint names are looked up from the live database rather than assumed,
because 0004 created them unnamed (server-generated names). SQLite cannot
alter a constraint in place and would need a full table rebuild; a fresh
SQLite deployment already gets the clauses from ``api/db/models.py``
metadata, so this migration is a no-op there.

Revision ID: 0006_endpoint_fk_cascade
Revises: 0005_endpoint_changes_fix
Create Date: 2026-08-04

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_endpoint_fk_cascade"
down_revision: Union[str, None] = "0005_endpoint_changes_fix"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, column, referred table, referred column, ondelete-after-upgrade)
_FOREIGN_KEYS: list[tuple[str, str, str, str, str]] = [
    ("endpoint_devices", "tenant_id", "tenants", "tenant_id", "CASCADE"),
    ("endpoint_devices", "asset_id", "assets", "asset_id", "SET NULL"),
    ("endpoint_identifiers", "device_id", "endpoint_devices", "device_id", "CASCADE"),
    ("endpoint_inventory_snapshots", "device_id", "endpoint_devices", "device_id", "CASCADE"),
    (
        "endpoint_software_items",
        "snapshot_id",
        "endpoint_inventory_snapshots",
        "snapshot_id",
        "CASCADE",
    ),
    ("endpoint_software_changes", "device_id", "endpoint_devices", "device_id", "CASCADE"),
    (
        "endpoint_software_changes",
        "snapshot_id",
        "endpoint_inventory_snapshots",
        "snapshot_id",
        "CASCADE",
    ),
]


def _existing_fk_name(inspector: sa.Inspector, table: str, column: str) -> str | None:
    for fk in inspector.get_foreign_keys(table):
        if fk.get("constrained_columns") == [column]:
            return fk.get("name")
    return None


def _rewrite(ondelete_for: dict[tuple[str, str], str | None]) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return
    inspector = sa.inspect(bind)
    for table, column, ref_table, ref_column, _ in _FOREIGN_KEYS:
        existing = _existing_fk_name(inspector, table, column)
        if existing:
            op.drop_constraint(existing, table, type_="foreignkey")
        op.create_foreign_key(
            f"fk_{table}_{column}",
            table,
            ref_table,
            [column],
            [ref_column],
            ondelete=ondelete_for[(table, column)],
        )


def upgrade() -> None:
    _rewrite({(t, c): ondelete for t, c, _rt, _rc, ondelete in _FOREIGN_KEYS})


def downgrade() -> None:
    _rewrite({(t, c): None for t, c, _rt, _rc, _od in _FOREIGN_KEYS})
