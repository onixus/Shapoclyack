"""Endpoint inventory: Lariska agent device/software ingestion (S1-S7)

Revision ID: 0004_endpoint_inventory
Revises: 0003_scan_schedules
Create Date: 2026-07-24

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_endpoint_inventory"
down_revision: Union[str, None] = "0003_scan_schedules"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "endpoint_devices",
        sa.Column("device_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), sa.ForeignKey("tenants.tenant_id"), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), sa.ForeignKey("assets.asset_id"), nullable=True),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("os_family", sa.String(), nullable=True),
        sa.Column("os_name", sa.String(), nullable=True),
        sa.Column("os_version", sa.String(), nullable=True),
        sa.Column("os_arch", sa.String(), nullable=True),
        sa.Column("agent_version", sa.String(), nullable=False),
        sa.Column("labels", sa.JSON(), nullable=False),
        sa.Column("reconciliation_status", sa.String(), nullable=False, server_default="linked"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("last_inventory_at", sa.DateTime(), nullable=True),
        sa.Column("latest_snapshot_id", sa.String(), nullable=True),
    )
    op.create_index("ix_endpoint_devices_tenant_id", "endpoint_devices", ["tenant_id"])
    op.create_unique_constraint(
        "uq_endpoint_device_tenant_agent", "endpoint_devices", ["tenant_id", "agent_id"]
    )

    op.create_table(
        "endpoint_identifiers",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "device_id", sa.String(), sa.ForeignKey("endpoint_devices.device_id"), nullable=False
        ),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("identifier_type", sa.String(), nullable=False),
        sa.Column("value_hash", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_endpoint_identifiers_device_id", "endpoint_identifiers", ["device_id"])
    op.create_index("ix_endpoint_identifiers_tenant_id", "endpoint_identifiers", ["tenant_id"])
    op.create_unique_constraint(
        "uq_endpoint_identifier",
        "endpoint_identifiers",
        ["tenant_id", "identifier_type", "value_hash"],
    )

    op.create_table(
        "endpoint_inventory_snapshots",
        sa.Column("snapshot_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column(
            "device_id", sa.String(), sa.ForeignKey("endpoint_devices.device_id"), nullable=False
        ),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("collected_at", sa.DateTime(), nullable=False),
        sa.Column("received_at", sa.DateTime(), nullable=False),
        sa.Column("payload_digest", sa.String(), nullable=False),
        sa.Column("software_count", sa.Integer(), nullable=False),
        sa.Column("collector_warnings", sa.JSON(), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
    )
    op.create_index(
        "ix_endpoint_inventory_snapshots_tenant_id", "endpoint_inventory_snapshots", ["tenant_id"]
    )
    op.create_index(
        "ix_endpoint_inventory_snapshots_device_id", "endpoint_inventory_snapshots", ["device_id"]
    )
    op.create_unique_constraint(
        "uq_endpoint_snapshot",
        "endpoint_inventory_snapshots",
        ["tenant_id", "snapshot_id"],
    )

    op.create_table(
        "endpoint_software_items",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "snapshot_id",
            sa.String(),
            sa.ForeignKey("endpoint_inventory_snapshots.snapshot_id"),
            nullable=False,
        ),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("comparison_key", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("publisher", sa.String(), nullable=True),
        sa.Column("architecture", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("install_location", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_endpoint_software_items_snapshot_id", "endpoint_software_items", ["snapshot_id"]
    )
    op.create_index("ix_endpoint_software_items_tenant_id", "endpoint_software_items", ["tenant_id"])
    op.create_index("ix_endpoint_software_items_device_id", "endpoint_software_items", ["device_id"])
    op.create_unique_constraint(
        "uq_software_item_snapshot_key",
        "endpoint_software_items",
        ["snapshot_id", "comparison_key"],
    )

    op.create_table(
        "endpoint_software_changes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.String(), nullable=False),
        sa.Column(
            "device_id", sa.String(), sa.ForeignKey("endpoint_devices.device_id"), nullable=False
        ),
        sa.Column(
            "snapshot_id",
            sa.String(),
            sa.ForeignKey("endpoint_inventory_snapshots.snapshot_id"),
            nullable=False,
        ),
        sa.Column("comparison_key", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("old_version", sa.String(), nullable=True),
        sa.Column("new_version", sa.String(), nullable=True),
        sa.Column("display_name", sa.String(), nullable=False),
        sa.Column("observed_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_endpoint_software_changes_tenant_id", "endpoint_software_changes", ["tenant_id"]
    )
    op.create_index(
        "ix_endpoint_software_changes_device_id", "endpoint_software_changes", ["device_id"]
    )
    op.create_index(
        "ix_endpoint_software_changes_device_time",
        "endpoint_software_changes",
        ["device_id", "observed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_endpoint_software_changes_device_time", table_name="endpoint_software_changes")
    op.drop_index("ix_endpoint_software_changes_device_id", table_name="endpoint_software_changes")
    op.drop_index("ix_endpoint_software_changes_tenant_id", table_name="endpoint_software_changes")
    op.drop_table("endpoint_software_changes")

    op.drop_constraint(
        "uq_software_item_snapshot_key", "endpoint_software_items", type_="unique"
    )
    op.drop_index("ix_endpoint_software_items_device_id", table_name="endpoint_software_items")
    op.drop_index("ix_endpoint_software_items_tenant_id", table_name="endpoint_software_items")
    op.drop_index("ix_endpoint_software_items_snapshot_id", table_name="endpoint_software_items")
    op.drop_table("endpoint_software_items")

    op.drop_constraint("uq_endpoint_snapshot", "endpoint_inventory_snapshots", type_="unique")
    op.drop_index(
        "ix_endpoint_inventory_snapshots_device_id", table_name="endpoint_inventory_snapshots"
    )
    op.drop_index(
        "ix_endpoint_inventory_snapshots_tenant_id", table_name="endpoint_inventory_snapshots"
    )
    op.drop_table("endpoint_inventory_snapshots")

    op.drop_constraint("uq_endpoint_identifier", "endpoint_identifiers", type_="unique")
    op.drop_index("ix_endpoint_identifiers_tenant_id", table_name="endpoint_identifiers")
    op.drop_index("ix_endpoint_identifiers_device_id", table_name="endpoint_identifiers")
    op.drop_table("endpoint_identifiers")

    op.drop_constraint("uq_endpoint_device_tenant_agent", "endpoint_devices", type_="unique")
    op.drop_index("ix_endpoint_devices_tenant_id", table_name="endpoint_devices")
    op.drop_table("endpoint_devices")
