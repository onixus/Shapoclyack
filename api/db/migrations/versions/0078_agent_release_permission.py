"""Endpoint-agent builds are the platform admin's to write (#510)

Revision ID: 0078_agent_release_permission
Revises: 0076_idp_resync_scim
Create Date: 2026-10-05

``endpoint_agent_releases`` is one row per ``(version, platform)`` for the
whole installation, and its upload and delete were gated on the tenant
permission ``endpoint_agent.manage`` — so a tenant admin could replace the
binary every other tenant's endpoints download. The routes now ask for
``platform.endpoint_agent_release.manage``, seeded here and granted to the
platform admin only; ``endpoint_agent.manage`` keeps the tenant's policy and
the listing, and its published description says so.

The schema does not change, and no row is touched: a build uploaded before
this revision stays downloadable. Before it, a tenant admin could have
uploaded one, so check after the upgrade — from the audit trail
(``endpoint_agent.release.upload`` / ``.delete``), not from ``uploaded_by`` on
the current rows: a row shows only the last write, so a foreign build later
re-uploaded with the official bytes, or uploaded and then deleted, does not
show there. docs/operations.md ("Endpoint Agent (Lariska) builds") has the
procedure.

Rolling deploy: an old replica still lets a tenant admin write a build until
it is replaced; it does not read these rows for its own decisions
(enforcement resolves built-in roles from code), so the seed changes nothing
for it.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0078_agent_release_permission"
down_revision: Union[str, None] = "0076_idp_resync_scim"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "platform.endpoint_agent_release.manage"
_DESCRIPTION = "Upload and delete the installation's endpoint agent builds"
#: Frozen, like 0049's seed: the roles that hold the permission when this
#: migration runs, not whatever the role table says later.
_ROLES = ("platform-admin",)

_MANAGE = "endpoint_agent.manage"
_MANAGE_DESCRIPTION = "Manage the tenant's endpoint agents and choose their build"
_MANAGE_DESCRIPTION_BEFORE = "Manage the tenant's endpoint agents and their builds"


def _describe(key: str, description: str) -> None:
    op.execute(
        sa.text(
            "UPDATE permissions SET description = :description WHERE permission_key = :key"
        ).bindparams(description=description, key=key)
    )


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
    _describe(_MANAGE, _MANAGE_DESCRIPTION)


def downgrade() -> None:
    _describe(_MANAGE, _MANAGE_DESCRIPTION_BEFORE)
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
