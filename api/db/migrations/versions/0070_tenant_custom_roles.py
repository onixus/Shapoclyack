"""Tenant-defined roles: the write side of ``roles`` (#318)

Revision ID: 0070_tenant_custom_roles
Revises: 0068_compliance_frameworks
Create Date: 2026-10-04

Migration 0049 created ``roles``/``role_permissions`` keyed by ``(role_id,
tenant_id)`` with the built-ins under ``tenant_id = ''``, and nothing wrote a
tenant's own row: the API published the table and enforced only the compiled
built-ins. This revision is what the write side
(``POST/PATCH/DELETE /api/tenants/{tenant_id}/roles``) needs from the schema,
and nothing else:

* ``roles.updated_at`` / ``roles.updated_by`` — who last changed what a
  tenant role may do. The audit trail has the full story; these are what the
  console shows next to the role without reading it.
* ``ck_roles_rank`` — a rank is 1, 2 or 3. The service validates it, and the
  constraint is what keeps a hand-written row from carrying a rank no gate in
  the API was written against.
* ``ck_roles_builtin_scope`` — ``builtin`` exactly when ``tenant_id = ''``. A
  "built-in" row inside one tenant would be listed as the platform's own, and
  a tenant row under ``''`` would be every tenant's role; neither is a state
  the service can produce, so the schema refuses both.
* ``ix_user_tenants_tenant_role`` — "who holds this role in this tenant",
  asked before a tenant role is deleted (refused while it is held, unless the
  holders are reassigned) and by the rename that carries them along.

**Expand only, and nothing existing changes meaning.** Every membership row
written before this keeps its built-in role name, which still resolves from
``api/core/permissions.py`` without touching these tables. The two checks hold
for every row 0049 seeded (``builtin`` true, ``tenant_id = ''``, ranks 1–3) and
for every row the previous release could write, which is none: it had no write
side. A replica still running the previous release reads a membership that
names a tenant role as an unknown role and resolves it to the lowest authority
— the direction a rolling deploy has to fail in.

**But the previous release's API is not ready for such a membership.** Its
member list declares ``role`` as a ``Literal`` of the eight built-in names, so
``GET /api/tenants/{id}/members`` on an old replica answers 500 for every
tenant where somebody holds a tenant role — during a rolling deploy, and after
a downgrade of this revision for as long as those memberships stay. Tenant
roles are defined only once the rollout is complete, and a rollback starts by
regranting every holder a built-in role (the procedure is in
``docs/operations.md`` → *Tenant-defined roles*); the downgrade below keeps the
rows and does not do that for you.

The tables are small (a few dozen role rows, one membership per user and
tenant), so the checks' validating scan and the index build hold their locks
for milliseconds; ``api/db/migrate.py``'s ``lock_timeout`` bounds the wait.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0070_tenant_custom_roles"
down_revision: Union[str, None] = "0068_compliance_frameworks"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("roles", sa.Column("updated_at", sa.DateTime(), nullable=True))
    op.add_column("roles", sa.Column("updated_by", sa.String(), nullable=True))
    op.create_check_constraint("ck_roles_rank", "roles", "rank BETWEEN 1 AND 3")
    op.create_check_constraint(
        "ck_roles_builtin_scope", "roles", "builtin = (tenant_id = '')"
    )
    op.create_index(
        "ix_user_tenants_tenant_role", "user_tenants", ["tenant_id", "role"]
    )


def downgrade() -> None:
    # Lossless for the built-ins. A tenant role survives the downgrade as a
    # row the previous release lists and does not enforce: its holders resolve
    # to the lowest authority there, which is that release's rule for a role
    # name it does not know — a demotion, never a promotion. Its member list,
    # though, answers 500 for a tenant where a membership still names one
    # (see the module docstring): regrant the holders before downgrading.
    op.drop_index("ix_user_tenants_tenant_role", table_name="user_tenants")
    op.drop_constraint("ck_roles_builtin_scope", "roles", type_="check")
    op.drop_constraint("ck_roles_rank", "roles", type_="check")
    op.drop_column("roles", "updated_by")
    op.drop_column("roles", "updated_at")
