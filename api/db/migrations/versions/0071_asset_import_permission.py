"""The right to import a CMDB/AD export into the asset registry (#350)

Revision ID: 0071_asset_import_permission
Revises: 0068_compliance_frameworks
Create Date: 2026-10-04

``POST /api/assets/import`` writes into tables that already exist —
``assets``, ``asset_identifiers``, ``asset_tags`` and
``asset_context_events`` — so the schema does not change. What does is the
catalogue: the endpoint is gated on a named permission (#318), seeded here into
``permissions`` and granted to the tenant ``admin`` and the platform admin,
the roles :mod:`api.core.permissions` gives it to.

Nobody loses anything: the endpoint is new. Nobody gains an authority beyond
it either — the operator keeps ``PATCH`` and ``/assets/bulk`` and does not get
the import, because an import registers assets against the tenant's quota.

Rolling deploy: an old replica neither serves the route nor reads these rows
for its own decisions (enforcement resolves built-in roles from code), so the
seed changes nothing for it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0071_asset_import_permission"
down_revision: Union[str, None] = "0068_compliance_frameworks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "asset.import"
_DESCRIPTION = "Import a CMDB or directory export into the asset registry"
#: Frozen, like 0049's seed: the roles that hold the permission when this
#: migration runs, not whatever the role table says later.
_ROLES = ("admin", "platform-admin")


def upgrade() -> None:
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
