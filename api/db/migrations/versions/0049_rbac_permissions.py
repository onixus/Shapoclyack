"""Named permissions, and the roles that carry them (#318)

Revision ID: 0049_rbac_permissions
Revises: 0043_user_mfa
Create Date: 2026-09-10

The platform had three roles and no way to name an authority smaller than one
of them: read the audit trail without being able to mint credentials, approve
what a tenant may scan without being able to run the scans. Three tables carry
the vocabulary that fixes it — ``permissions`` (the catalogue), ``roles`` (a
role, built-in or defined by a tenant) and ``role_permissions`` (which
permissions it holds).

**Nothing is enforced from these tables.** They are seeded here so the
catalogue is discoverable over ``GET /api/rbac/*`` and so a future custom role
has something to inherit from, but the checks resolve a built-in role from
``api/core/permissions.py``: a request that queried for its own authority
would fail open on a slow database, and a bad seed in an upgrade would be able
to lock an installation out of its own console.
``tests/test_api_rbac_permissions.py`` asserts the seed below and that module
still agree, which is the whole cost of keeping the two in step.

**Expand only, and the three original roles are unchanged by it.** The seed
below writes ``viewer``/``operator``/``admin`` with exactly the authority they
already had, so no administrator has to do anything after the upgrade and no
existing grant means anything different than it did. The new role names are
rows nobody holds until somebody grants them.

There is no contract phase: nothing is being replaced. ``user_tenants.role``
keeps holding a role *name*, which is now allowed to be one of eight rather
than three — a widening of accepted values, not a schema change, so a replica
still running the old code keeps reading every membership it wrote (it would
read a membership carrying a *new* role name as an unknown one, which
:func:`api.services.memberships.resolve_tenant` already resolves to the lowest
authority; granting the new roles during a rolling deploy is therefore safe in
the direction that matters).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0049_rbac_permissions"
down_revision: Union[str, None] = "0048_maintenance_windows"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# A frozen copy of api/core/permissions.py, on purpose: a migration that
# imports application code is a migration whose meaning changes after it has
# run. The drift between the two is a test, not a shared import.
_PERMISSIONS: tuple[tuple[str, str], ...] = (
    ("audit.read", "Read the administrative audit trail"),
    ("config.read", "Read the editable scanner configuration"),
    ("config.write", "Change the installation-wide scanner configuration"),
    ("scan_scope.read", "Read the tenant's approved scanning scope"),
    ("scan_scope.approve", "Approve what the tenant may scan"),
    ("tenant.member.read", "List the tenant's members"),
    ("tenant.member.manage", "Grant and revoke the tenant's members"),
    (
        "tenant.credential.manage",
        "Manage the tenant's provisioning keys and service tokens",
    ),
    ("tenant.quota.read", "Read the tenant's quota"),
    ("platform.quota.manage", "Set any tenant's quota"),
    ("platform.tenant.manage", "Create tenants"),
    ("platform.fleet.read", "Read installation-wide counters across tenants"),
    ("vulnerability.exception.approve", "Approve an accepted risk on a finding"),
)

_TENANT_ADMIN = (
    "audit.read",
    "config.read",
    "scan_scope.read",
    "tenant.member.read",
    "tenant.member.manage",
    "tenant.credential.manage",
    "tenant.quota.read",
)

_ROLES: tuple[tuple[str, int, str, tuple[str, ...]], ...] = (
    ("viewer", 1, "Reads the tenant's findings and assets", ()),
    ("operator", 2, "Runs scans and works the findings", ("config.read",)),
    (
        "admin",
        3,
        "Administers this tenant: members, credentials, audit trail",
        _TENANT_ADMIN,
    ),
    (
        "auditor",
        1,
        "Reads the audit trail and the configuration, writes nothing",
        ("audit.read", "config.read", "scan_scope.read", "tenant.quota.read"),
    ),
    (
        "scan-operator",
        2,
        "Runs scans within the approved scope, and cannot widen it",
        ("config.read",),
    ),
    (
        "scope-approver",
        1,
        "Approves what the tenant may scan, and runs nothing",
        ("scan_scope.read", "scan_scope.approve"),
    ),
    (
        "token-admin",
        1,
        "Manages the tenant's provisioning keys and service tokens",
        ("tenant.credential.manage",),
    ),
    (
        "risk-approver",
        1,
        "Approves accepted risk on findings (#348)",
        ("vulnerability.exception.approve",),
    ),
    (
        "platform-admin",
        3,
        "Administers the installation and every tenant in it",
        tuple(key for key, _ in _PERMISSIONS),
    ),
)


def upgrade() -> None:
    op.create_table(
        "permissions",
        sa.Column("permission_key", sa.String(), primary_key=True),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
    )
    op.create_table(
        "roles",
        sa.Column("role_id", sa.String(), primary_key=True),
        # "" is the built-in scope — every tenant's. Not NULL: it is half of
        # the primary key, and a unique index over a nullable column would let
        # the same built-in role be seeded twice.
        sa.Column("tenant_id", sa.String(), primary_key=True, server_default=""),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rank", sa.Integer(), nullable=False, server_default="1"),
        # Naive UTC, like every other timestamp column in this schema.
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.String(), primary_key=True),
        sa.Column("tenant_id", sa.String(), primary_key=True, server_default=""),
        sa.Column(
            "permission_key",
            sa.String(),
            sa.ForeignKey("permissions.permission_key", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.ForeignKeyConstraint(
            ["role_id", "tenant_id"],
            ["roles.role_id", "roles.tenant_id"],
            ondelete="CASCADE",
            name="fk_role_permissions_role",
        ),
    )

    now = datetime.now(UTC).replace(tzinfo=None)
    op.bulk_insert(
        sa.table(
            "permissions",
            sa.column("permission_key", sa.String()),
            sa.column("description", sa.String()),
        ),
        [{"permission_key": key, "description": text} for key, text in _PERMISSIONS],
    )
    op.bulk_insert(
        sa.table(
            "roles",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("description", sa.String()),
            sa.column("builtin", sa.Boolean()),
            sa.column("rank", sa.Integer()),
            sa.column("created_at", sa.DateTime()),
            sa.column("created_by", sa.String()),
        ),
        [
            {
                "role_id": role_id,
                "tenant_id": "",
                "description": description,
                "builtin": True,
                "rank": rank,
                "created_at": now,
                "created_by": None,
            }
            for role_id, rank, description, _ in _ROLES
        ],
    )
    op.bulk_insert(
        sa.table(
            "role_permissions",
            sa.column("role_id", sa.String()),
            sa.column("tenant_id", sa.String()),
            sa.column("permission_key", sa.String()),
        ),
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": key}
            for role_id, _, _, keys in _ROLES
            for key in keys
        ],
    )


def downgrade() -> None:
    # Lossless for the built-in roles, which live in the code; a role a tenant
    # defined here is gone, because there is nowhere else it was written down.
    op.drop_table("role_permissions")
    op.drop_table("roles")
    op.drop_table("permissions")
