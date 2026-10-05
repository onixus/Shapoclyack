"""Tenant roles at the admin rank keep minting provisioning keys (#504)

Revision ID: 0073_rank3_credential_permission
Revises: 0072_run_publication_projected
Create Date: 2026-10-05

``POST /api/agent/deployment-command`` and ``POST /api/agent/deploy/ssh`` mint
a provisioning key, and were gated on the admin *rank* (3) where their twin
``POST /api/tenants/{id}/provisioning-keys`` asks for
``tenant.credential.manage``. #504 moves both onto the permission, so the
credential has one gate whichever door it leaves by. A tenant-defined role
written at rank 3 without the permission could press the console's
**Deploy Agent** button before the upgrade; this revision writes the
permission onto every such role so it still can after. No schema change.

What it widens, on purpose: those roles also reach the rest of what the
permission covers — listing and revoking the tenant's provisioning keys and
minting service tokens up to their own authority. That is the honest form of
what they held: a key minted from the console is the same credential as one
minted from the API, and the role editor now shows the permission, so a tenant
that did not mean it can take it off.

And it widens **delegation** for the rank-3 roles that also hold
``tenant.member.manage``: ``exceeds_authority`` lets a member manager hand out
what it holds, so once the role carries the permission its holders may write a
role carrying it, grant that role, and grant the built-in ``token-admin``. The
power to pass key minting on is not new — such a holder could always grant its
own role, and every holder minted keys from the console — but it now travels
without the member and rank authority it used to come bundled with. It cannot
be kept apart: leaving those roles out would take the **Deploy Agent** button
from roles that pressed it yesterday, and the gate has no shape between "holds
the permission" and "does not" that keeps one and drops the other. The tenants
it concerns are listed by the query in ``docs/operations.md`` (#504). Built-in roles are not touched — the
compiled table is their source of truth (``api/core/permissions.py``) and the
built-in ``admin`` already holds it. Rank 1 and 2 roles are not touched: they
could not mint before.

Downgrade leaves the rows. Which rank-3 role held the permission before the
upgrade is not recorded anywhere, and removing it from all of them would take
it from roles the tenant gave it to deliberately. Under the previous release
the rows left behind keep those roles on the permission's own routes (keys
and service tokens) — the widening above, not a new one; a tenant that wants
the narrower shape removes the permission from the role.

Rolling deploy: an old replica gates the two routes on rank and is unaffected
by the rows; a new one finds them in place before it serves a request.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0073_rank3_credential_permission"
down_revision: Union[str, None] = "0072_run_publication_projected"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PERMISSION = "tenant.credential.manage"
#: Frozen: the rank ``require_tenant(Role.admin)`` let through when this ran.
_ADMIN_RANK = 3


def upgrade() -> None:
    # Idempotent, so a retried rollout (or up/down/up) writes each row once.
    op.execute(
        sa.text(
            "INSERT INTO role_permissions (role_id, tenant_id, permission_key) "
            "SELECT r.role_id, r.tenant_id, :key FROM roles r "
            "WHERE NOT r.builtin AND r.tenant_id <> '' AND r.rank >= :rank "
            "AND NOT EXISTS (SELECT 1 FROM role_permissions rp "
            "WHERE rp.role_id = r.role_id AND rp.tenant_id = r.tenant_id "
            "AND rp.permission_key = :key)"
        ).bindparams(key=_PERMISSION, rank=_ADMIN_RANK)
    )


def downgrade() -> None:
    # See the module docstring: the grants stay.
    pass
