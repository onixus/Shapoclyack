"""An explicit CMDB value takes precedence over matching rule-owned output."""
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import asset_groups, asset_import, assets
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


def _estate(tmp_path):
    settings = make_settings(tmp_path)
    tenant, aid = uuid4().hex, uuid4().hex
    with get_session(settings.postgres_url) as session:
        session.add(models.Tenant(tenant_id=tenant, name=tenant, created_at=datetime.now()))
        session.flush()
        session.add(models.Asset(asset_id=aid, tenant_id=tenant, first_seen=datetime.now(),
                                 last_seen=datetime.now(), environment="production"))
    group = asset_groups.save_group(settings, tenant, {
        "name": "Payments", "rules": {"field": "environment", "op": "eq", "value": "production"},
        "context": {"business_service": "payments"},
    })
    asset_groups.reconcile_batch(settings, tenant)
    return settings, tenant, aid, group["id"]


def _import(settings, tenant, aid, *, dry_run=False, extra=""):
    return asset_import.run_import(settings, tenant_id=tenant,
        content=f"asset_id,business_service{',business_unit' if extra else ''}\n{aid},payments{',' + extra if extra else ''}\n",
        format="csv", dry_run=dry_run, context_source="cmdb", overwrite_operator_edits=False, actor="cmdb-sync")


def _events(settings, tenant):
    with get_session(settings.postgres_url) as session:
        return session.scalar(select(func.count()).select_from(models.AssetContextEvent).where(models.AssetContextEvent.tenant_id == tenant))


def test_same_value_cmdb_claim_survives_rule_removal_and_is_idempotent(tmp_path):
    settings, tenant, aid, gid = _estate(tmp_path)
    before = _events(settings, tenant)
    preview = _import(settings, tenant, aid, dry_run=True)
    assert preview["counts"]["update"] == 1
    assert preview["rows"][0]["changes"]["business_service"] == {"old": "payments", "new": "payments"}
    assert _events(settings, tenant) == before
    with get_session(settings.postgres_url) as session:
        assert session.scalar(select(func.count()).select_from(models.AssetGroupProvenance).where(models.AssetGroupProvenance.tenant_id == tenant)) == 1
    applied = _import(settings, tenant, aid)
    assert applied["counts"]["update"] == 1
    assert _events(settings, tenant) == before + 1
    assert _import(settings, tenant, aid)["counts"]["unchanged"] == 1
    assert _events(settings, tenant) == before + 1
    with get_session(settings.postgres_url) as session:
        event = session.scalars(select(models.AssetContextEvent).where(models.AssetContextEvent.tenant_id == tenant).order_by(models.AssetContextEvent.id.desc())).first()
        assert (event.source, event.old_value, event.new_value) == ("cmdb", "payments", "payments")
    asset_groups.delete_group(settings, tenant, gid)
    asset_groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service == "payments"


@pytest.mark.parametrize("content", ["asset_id,business_service\n{aid},\n", "asset_id\n{aid}\n"])
def test_absent_or_blank_import_cell_does_not_claim_rule_ownership(tmp_path, content):
    settings, tenant, aid, gid = _estate(tmp_path)
    before = _events(settings, tenant)
    report = asset_import.run_import(settings, tenant_id=tenant, content=content.format(aid=aid),
        format="csv", dry_run=False, context_source="cmdb", overwrite_operator_edits=False, actor="cmdb-sync")
    assert report["counts"]["unchanged"] == 1 and _events(settings, tenant) == before
    asset_groups.delete_group(settings, tenant, gid)
    asset_groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service is None


def test_conflicting_row_does_not_half_claim_rule_owned_fields(tmp_path):
    settings, tenant, aid, gid = _estate(tmp_path)
    assets.update_asset(settings, tenant, aid, {"business_unit": "operator-team"}, actor="operator")
    before = _events(settings, tenant)
    report = _import(settings, tenant, aid, extra="different-team")
    assert report["counts"]["conflict"] == 1
    assert report["rows"][0]["code"] == "operator_override"
    assert _events(settings, tenant) == before
    asset_groups.delete_group(settings, tenant, gid)
    asset_groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Asset, aid)
        assert row.business_service is None and row.business_unit == "operator-team"


def test_same_value_import_does_not_claim_an_operator_owned_field(tmp_path):
    settings, tenant, aid, gid = _estate(tmp_path)
    assets.update_asset(settings, tenant, aid, {"business_service": "payments"}, actor="operator")
    before = _events(settings, tenant)
    assert _import(settings, tenant, aid)["counts"]["unchanged"] == 1
    assert _events(settings, tenant) == before
    with get_session(settings.postgres_url) as session:
        event = session.scalars(select(models.AssetContextEvent).where(models.AssetContextEvent.tenant_id == tenant).order_by(models.AssetContextEvent.id.desc())).first()
        assert event.source == "operator"
    asset_groups.delete_group(settings, tenant, gid)
    asset_groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service == "payments"
