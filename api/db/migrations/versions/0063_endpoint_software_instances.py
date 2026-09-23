"""Endpoint inventory v2: preserve side-by-side software installations

Revision ID: 0063_endpoint_software_instances
Revises: 0062_run_publication_lease
Create Date: 2026-09-23

The v1 comparison key identifies a product by name, publisher, architecture and
source. That is sufficient for package managers that expose one active version,
but it collapses side-by-side installations such as JDK 17 and JDK 21, parallel
Python environments, multiple Homebrew formula versions, and Windows products
whose display metadata is otherwise identical.

``install_instance_id`` is an optional opaque SHA-256 value calculated by the
endpoint agent from local installation evidence. Raw profile identifiers and
paths do not need to become server identifiers. Inventory schema v2 includes
this value in the stable comparison key; v1 rows keep NULL and retain their
existing semantics.

The existing unique constraint on ``(snapshot_id, comparison_key)`` remains
correct because the comparison key itself becomes instance-aware for v2. The
migration is expand-only and safe before agent rollout: old agents continue to
write NULL.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0063_endpoint_software_instances"
down_revision: Union[str, None] = "0062_run_publication_lease"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "endpoint_software_items",
        sa.Column("install_instance_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("endpoint_software_items", "install_instance_id")
