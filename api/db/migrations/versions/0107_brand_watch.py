"""Brand-watch profiles, candidates, observations and jobs (M1).

Revision ID: 0107_brand_watch
Revises: 0106_saml_session_binding

Four tenant tables. Observations store a DNS/HTTP result document, never a
page archive: there is no raw HTML column. Jobs are claimed with
``FOR UPDATE SKIP LOCKED`` by the service, not by this migration.

RLS is spelled out here. Migration 0067 discovers every ``tenant_id`` table
that exists *when it runs*, so a database that already applied 0067 does not
pick up a table added afterwards. The two policies and the grant are the same
statements 0067's ``shapoclyack_protect`` executes for an ordinary tenant
table (not ``roles`` / ``role_permissions``).

The permission seed is frozen, like 0071: the roles that hold each permission
when this migration runs, not whatever the role table says later. Enforcement
of built-in roles still resolves from ``api/core/permissions.py``.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0107_brand_watch"
down_revision: Union[str, None] = "0106_saml_session_binding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Drop order: children before the profiles they reference.
_TABLES = (
    "brand_observations",
    "brand_watch_jobs",
    "brand_candidates",
    "brand_profiles",
)

# Frozen, like 0049 / 0071. Viewer and auditor read; operator also disposes;
# admin writes profiles and holds both.
_PERMISSIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "brand_watch.read",
        "Read brand-watch profiles, candidates and diffs",
        ("admin", "platform-admin"),
    ),
    (
        "brand_watch.write",
        "Create and approve brand-watch profiles",
        ("admin", "platform-admin"),
    ),
    (
        "brand_watch.disposition",
        "Set a brand-watch candidate disposition",
        ("operator", "admin", "platform-admin"),
    ),
)


def upgrade() -> None:
    op.create_table(
        "brand_profiles",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("official_domains", sa.JSON(), nullable=False),
        sa.Column("brand_strings", sa.JSON(), nullable=False),
        sa.Column("whitelist", sa.JSON(), nullable=False),
        sa.Column("reference", sa.JSON(), nullable=False),
        sa.Column("approved_at", sa.DateTime(), nullable=True),
        sa.Column("approved_by", sa.String(), nullable=True),
        sa.Column("our_brand", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("last_dispatched_at", sa.DateTime(), nullable=True),
        sa.Column("last_rebuilt_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_brand_profiles_tenant_id", "brand_profiles", ["tenant_id"])

    op.create_table(
        "brand_candidates",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.String(),
            sa.ForeignKey("brand_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name_unicode", sa.String(), nullable=False),
        sa.Column("name_punycode", sa.String(), nullable=False),
        sa.Column("seed", sa.String(), nullable=False, server_default=""),
        sa.Column("generator_class", sa.String(), nullable=False, server_default=""),
        sa.Column("reason", sa.String(), nullable=False, server_default=""),
        sa.Column("state", sa.String(), nullable=False, server_default="unregistered"),
        sa.Column("previous_state", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_checked", sa.DateTime(), nullable=True),
        sa.Column("last_changed", sa.DateTime(), nullable=True),
        sa.Column("ns", sa.JSON(), nullable=False),
        sa.Column("addresses", sa.JSON(), nullable=False),
        sa.Column("mx_present", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rdap", sa.JSON(), nullable=True),
        sa.Column("http", sa.JSON(), nullable=True),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("disposition", sa.String(), nullable=False, server_default="open"),
        sa.Column("content_hash", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "tenant_id", "profile_id", "name_punycode", name="uq_brand_candidates_name"
        ),
    )
    op.create_index("ix_brand_candidates_tenant_id", "brand_candidates", ["tenant_id"])
    op.create_index("ix_brand_candidates_profile_id", "brand_candidates", ["profile_id"])
    op.create_index(
        "ix_brand_candidates_changed", "brand_candidates", ["tenant_id", "last_changed"]
    )

    op.create_table(
        "brand_watch_jobs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "profile_id",
            sa.String(),
            sa.ForeignKey("brand_profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("lease_owner", sa.String(), nullable=True),
        sa.Column("lease_until", sa.DateTime(), nullable=True),
        sa.Column("result_hash", sa.String(), nullable=True),
        sa.Column("applied_at", sa.DateTime(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_brand_watch_jobs_tenant_id", "brand_watch_jobs", ["tenant_id"])
    op.create_index(
        "ix_brand_watch_jobs_claim", "brand_watch_jobs", ["tenant_id", "status"]
    )

    op.create_table(
        "brand_observations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(),
            sa.ForeignKey("tenants.tenant_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "candidate_id",
            sa.String(),
            sa.ForeignKey("brand_candidates.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "job_id",
            sa.String(),
            sa.ForeignKey("brand_watch_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("checked_at", sa.DateTime(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
    )
    op.create_index("ix_brand_observations_tenant_id", "brand_observations", ["tenant_id"])
    op.create_index(
        "ix_brand_observations_candidate_id", "brand_observations", ["candidate_id"]
    )

    if op.get_bind().dialect.name == "postgresql":
        for name in _TABLES:
            op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
            op.execute(
                f"DROP POLICY IF EXISTS shapoclyack_unscoped ON {name}"
            )
            op.execute(
                f"CREATE POLICY shapoclyack_unscoped ON {name} "
                "AS PERMISSIVE FOR ALL TO PUBLIC USING (true) WITH CHECK (true)"
            )
            op.execute(
                f"DROP POLICY IF EXISTS shapoclyack_tenant_isolation ON {name}"
            )
            op.execute(
                f"CREATE POLICY shapoclyack_tenant_isolation ON {name} "
                "AS RESTRICTIVE FOR ALL TO shapoclyack_tenant "
                "USING (tenant_id = shapoclyack_current_tenant()) "
                "WITH CHECK (tenant_id = shapoclyack_current_tenant())"
            )
            op.execute(
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON {name} TO shapoclyack_tenant"
            )

    permissions = sa.table(
        "permissions",
        sa.column("permission_key", sa.String()),
        sa.column("description", sa.String()),
    )
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", sa.String()),
        sa.column("tenant_id", sa.String()),
        sa.column("permission_key", sa.String()),
    )
    op.bulk_insert(
        permissions,
        [
            {"permission_key": key, "description": description}
            for key, description, _roles in _PERMISSIONS
        ],
    )
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_id, "tenant_id": "", "permission_key": key}
            for key, _description, roles in _PERMISSIONS
            for role_id in roles
        ],
    )


def downgrade() -> None:
    for key, _description, _roles in _PERMISSIONS:
        op.execute(
            sa.text("DELETE FROM role_permissions WHERE permission_key = :key").bindparams(
                key=key
            )
        )
        op.execute(
            sa.text("DELETE FROM permissions WHERE permission_key = :key").bindparams(key=key)
        )
    for name in _TABLES:
        op.drop_table(name)
