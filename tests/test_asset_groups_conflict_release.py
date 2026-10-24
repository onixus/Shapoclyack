"""Foreign conflicts cannot keep obsolete ownership alive after rule removal."""

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import asset_groups
from tests.conftest import requires_postgres
from tests.test_asset_groups_import_ownership import _estate

pytestmark = requires_postgres


def _conflicts(settings, tenant):
    for name, value in (("B", "other-b"), ("C", "other-c")):
        asset_groups.save_group(
            settings,
            tenant,
            {
                "name": name,
                "priority": 2,
                "rules": {"field": "environment", "op": "eq", "value": "production"},
                "context": {"business_service": value},
            },
        )


def _state(settings, tenant, aid):
    with get_session(settings.postgres_url) as session:
        return session.get(models.Asset, aid).business_service, session.scalar(
            select(models.AssetGroupProvenance.group_id).where(
                models.AssetGroupProvenance.tenant_id == tenant
            )
        )


@pytest.mark.parametrize("removal", ["delete", "disable", "nonmatch", "remove_field"])
def test_obsolete_owner_releases_value_despite_other_rules_conflicting(
    tmp_path, removal
):
    settings, tenant, aid, gid = _estate(tmp_path)
    _conflicts(settings, tenant)
    if removal == "delete":
        asset_groups.delete_group(settings, tenant, gid)
    else:
        patch = {
            "disable": {"enabled": False},
            "nonmatch": {"rules": {"field": "environment", "op": "eq", "value": "lab"}},
            "remove_field": {"context": {}},
        }[removal]
        asset_groups.save_group(settings, tenant, patch, group_id=gid)
    for _ in range(2):
        report = asset_groups.reconcile_batch(settings, tenant)
        assert report["conflicts"] == 1
        assert _state(settings, tenant, aid) == (None, None)


def test_conflict_freezes_value_only_while_owner_has_a_matching_proposal(tmp_path):
    settings, tenant, aid, gid = _estate(tmp_path)
    _conflicts(settings, tenant)
    for _ in range(2):
        report = asset_groups.reconcile_batch(settings, tenant)
        assert report["conflicts"] == 1
        assert _state(settings, tenant, aid) == ("payments", gid)


def test_conflict_drops_stale_provenance_without_overwriting_a_later_value(tmp_path):
    settings, tenant, aid, _ = _estate(tmp_path)
    _conflicts(settings, tenant)
    # Simulate a legacy writer that predated ownership-revocation hooks.
    with get_session(settings.postgres_url) as session:
        session.get(models.Asset, aid).business_service = "later-manual"
    asset_groups.reconcile_batch(settings, tenant)
    assert _state(settings, tenant, aid) == ("later-manual", None)
