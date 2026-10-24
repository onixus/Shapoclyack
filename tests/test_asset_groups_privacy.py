"""Console erasure retains tenant rule history and discloses no sibling data."""

from datetime import UTC, datetime
import json
from uuid import uuid4

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import asset_groups, data_subject
from tests.conftest import requires_postgres
from tests.test_asset_groups import setup


def _rule(email, name):
    return {
        "name": name,
        "description": "Tenant-owned classification",
        "rules": {"all": [{"field": "environment", "op": "eq", "value": "production"}]},
        "context": {"owner_email": email, "business_service": "payments"},
    }


def _operational_state(settings, tenants):
    state = {}
    with get_session(settings.postgres_url) as session:
        for model in (
            models.AssetGroup,
            models.AssetGroupVersion,
            models.AssetGroupMembership,
            models.AssetGroupEvaluation,
            models.AssetGroupProvenance,
            models.AssetContextEvent,
        ):
            rows = session.scalars(select(model).where(model.tenant_id.in_(tenants)))
            state[model.__tablename__] = sorted(
                [
                    {
                        column.name: getattr(row, column.name)
                        for column in model.__table__.columns
                    }
                    for row in rows
                ],
                key=lambda row: str(row.get("id", row.get("asset_id"))),
            )
    return state


@requires_postgres
def test_rule_actor_export_and_erasure_preserve_tenant_owned_receipts_and_sibling(
    tmp_path,
):
    settings, tenant = setup(tmp_path)
    _, sibling = setup(tmp_path)
    username = f"opaque-{uuid4().hex}"
    other = f"other-{uuid4().hex}"
    email = f"{uuid4().hex}@example.test"
    sibling_email = f"secret-{uuid4().hex}@example.test"
    sibling_name = f"private-sibling-rule-{uuid4().hex}"
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.User(
                username=username,
                email=email,
                password_hash="invalidated-at-erasure",
                role="viewer",
                created_at=now,
                updated_at=now,
            )
        )
        session.add(
            models.User(
                username=other,
                email=sibling_email,
                password_hash="unrelated",
                role="viewer",
                created_at=now,
                updated_at=now,
            )
        )
    group = asset_groups.save_group(
        settings, tenant, _rule(email, "Own operational rule"), actor=username
    )
    asset_groups.save_group(
        settings,
        tenant,
        {"description": "Second immutable version"},
        group_id=group["id"],
        actor=username,
    )
    asset_groups.save_group(
        settings, sibling, _rule(sibling_email, sibling_name), actor=other
    )
    asset_groups.reconcile_batch(settings, tenant, actor=username)
    asset_groups.reconcile_batch(settings, sibling, actor=other)
    before = _operational_state(settings, [tenant, sibling])
    exported = data_subject.export_user(settings, username)
    assert {"table": "asset_group_versions", "column": "actor", "rows": 2} in exported[
        "attributions"
    ]
    encoded = json.dumps(exported)
    assert (
        sibling_email not in encoded
        and sibling_name not in encoded
        and sibling not in encoded
    )
    assert (
        "Second immutable version" not in encoded
    )  # tenant records are counted, never copied
    erased = data_subject.erase_user(
        settings, username, requested_by="separate-platform-admin"
    )
    assert erased["removed"]["email"]
    assert _operational_state(settings, [tenant, sibling]) == before
    with get_session(settings.postgres_url) as session:
        account = session.get(models.User, username)
        assert (
            account.erased_at is not None
            and account.email is None
            and account.password_hash == ""
        )
        assert session.get(models.User, other).email == sibling_email
        versions = list(
            session.scalars(
                select(models.AssetGroupVersion).where(
                    models.AssetGroupVersion.group_id == group["id"]
                )
            )
        )
        assert all(
            version.actor == username for version in versions
        )  # now an erased opaque pseudonym
        assert (
            versions[-1].document["context"]["owner_email"] == email
        )  # independently-owned tenant context
    again = data_subject.export_user(settings, username)
    assert again["account"]["email"] is None
    assert {"table": "asset_group_versions", "column": "actor", "rows": 2} in again[
        "attributions"
    ]
    assert data_subject.erase_user(
        settings, username, requested_by="separate-platform-admin"
    )["already_erased"]
