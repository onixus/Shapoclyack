"""Durable classification contract, with real transactional PostgreSQL."""

from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import asset_groups as groups
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


def setup(tmp_path, count=1):
    settings = make_settings(tmp_path)
    tenant = uuid4().hex
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Tenant(tenant_id=tenant, name=tenant, created_at=datetime.now())
        )
        session.flush()
        for index in range(count):
            aid = f"{tenant[:20]}-{index:04}"
            session.add(
                models.Asset(
                    asset_id=aid,
                    tenant_id=tenant,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    environment="production",
                )
            )
    return settings, tenant


def draft(**overrides):
    return {
        "name": "Production",
        "rules": {"all": [{"field": "environment", "op": "eq", "value": "production"}]},
        "context": {"business_service": "payments"},
        **overrides,
    }


@pytest.mark.parametrize("status", ["suspended", "pending_deletion", "deleting"])
def test_background_reconciliation_cannot_mutate_inactive_tenant(tmp_path, status):
    settings, tenant = setup(tmp_path)
    groups.save_group(settings, tenant, draft())
    with get_session(settings.postgres_url) as session:
        session.get(models.Tenant, tenant).status = status
    assert groups.reconcile_batch(settings, tenant)["evaluated"] == 0
    assert asset(settings, tenant)[1] is None
    with pytest.raises(LookupError):
        groups.recalculate(settings, tenant)


def asset(settings, tenant):
    with get_session(settings.postgres_url) as session:
        row = session.scalars(
            select(models.Asset).where(models.Asset.tenant_id == tenant)
        ).first()
        return row.asset_id, row.business_service


def test_preview_does_not_write_and_replay_is_idempotent(tmp_path):
    settings, tenant = setup(tmp_path)
    group = groups.save_group(settings, tenant, draft())
    report = groups.preview(settings, tenant, draft(), group_id=group["id"])
    assert report["entrants"] == 1 and report["changed"] == 1
    assert asset(settings, tenant)[1] is None
    groups.reconcile_batch(settings, tenant)
    groups.reconcile_batch(settings, tenant)
    assert asset(settings, tenant)[1] == "payments"
    with get_session(settings.postgres_url) as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(models.AssetContextEvent)
                .where(models.AssetContextEvent.tenant_id == tenant)
            )
            == 1
        )
    assert groups.list_members(settings, tenant, group["id"])[1] == 1


def test_exit_restores_owned_context_and_preserves_manual_override(tmp_path):
    settings, tenant = setup(tmp_path)
    group = groups.save_group(settings, tenant, draft())
    groups.reconcile_batch(settings, tenant)
    aid, _ = asset(settings, tenant)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Asset, aid)
        row.environment = "lab"
    report = groups.reconcile_batch(settings, tenant)
    assert report["exits"] == 1 and asset(settings, tenant)[1] is None
    with get_session(settings.postgres_url) as session:
        session.get(models.Asset, aid).environment = "production"
    groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Asset, aid)
        row.business_service = "manual"
        groups.revoke_managed_fields(session, tenant, aid, ["business_service"])
    groups.delete_group(settings, tenant, group["id"])
    groups.reconcile_batch(settings, tenant)
    assert asset(settings, tenant)[1] == "manual"


def test_priority_conflict_never_writes_and_tenant_ids_are_checked(tmp_path):
    settings, tenant = setup(tmp_path)
    first = groups.save_group(settings, tenant, draft())
    groups.save_group(
        settings, tenant, draft(name="Other", context={"business_service": "other"})
    )
    report = groups.reconcile_batch(settings, tenant)
    assert report["conflicts"] == 1 and asset(settings, tenant)[1] is None
    for callback in (
        groups.get_group,
        groups.list_members,
        groups.list_evaluations,
        groups.delete_group,
    ):
        with pytest.raises(LookupError):
            callback(settings, uuid4().hex, first["id"])


def test_durable_bounded_cursor_and_context_predicates_do_not_oscillate(tmp_path):
    settings, tenant = setup(tmp_path, 3)
    group = groups.save_group(settings, tenant, draft(context={"environment": "lab"}))
    first = groups.reconcile_batch(settings, tenant, limit=2)
    assert first["evaluated"] == 2 and first["has_more"]
    second = groups.reconcile_batch(settings, tenant, limit=2)
    assert second["evaluated"] == 1 and not second["has_more"]
    groups.reconcile_batch(settings, tenant, limit=3)
    assert groups.list_members(settings, tenant, group["id"])[1] == 3


def test_assignment_receipts_survive_version_change_and_delete(tmp_path):
    settings, tenant = setup(tmp_path)
    group = groups.save_group(settings, tenant, draft())
    first = groups.reconcile_batch(settings, tenant)
    groups.save_group(settings, tenant, {"description": "v2"}, group_id=group["id"])
    second = groups.reconcile_batch(settings, tenant)
    assert second["items"][0]["changes"]["business_service"]["version"] == 2
    groups.delete_group(settings, tenant, group["id"])
    third = groups.reconcile_batch(settings, tenant)
    release = third["items"][0]["changes"]["business_service"]
    assert release["group_id"] == group["id"] and release["release"]
    with get_session(settings.postgres_url) as session:
        original = session.get(models.AssetGroupEvaluation, first["evaluation_id"])
        receipt = original.report["transitions"][0]["changes"]["business_service"]
        assert receipt["version"] == 1 and receipt["group_id"] == group["id"]
        assert receipt["reason"] and receipt["source"] == "group_rule"


def test_failed_batch_rolls_back_cursor_and_exposes_durable_error(
    tmp_path, monkeypatch
):
    settings, tenant = setup(tmp_path)
    group = groups.save_group(settings, tenant, draft())

    def fail(*args, **kwargs):
        raise RuntimeError("internal credential should never be exposed")

    monkeypatch.setattr(groups.engine, "evaluate_rules", fail)
    with pytest.raises(RuntimeError):
        groups.reconcile_batch(settings, tenant)
    assert asset(settings, tenant)[1] is None
    rows, _ = groups.list_evaluations(settings, tenant, group["id"])
    assert rows[0]["status"] == "failed"
    assert "credential" not in rows[0]["error"]
    with get_session(settings.postgres_url) as session:
        assert session.get(models.AssetGroupSweep, tenant) is None


def test_snapshot_query_count_is_independent_of_batch_size(tmp_path):
    from sqlalchemy import event
    from api.db.engine import get_session_factory

    settings, tenant = setup(tmp_path, 20)
    groups.save_group(settings, tenant, draft())
    factory = get_session_factory(settings.postgres_url)
    bind = factory.kw["bind"]
    queries = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("SELECT"):
            queries.append(statement)

    event.listen(bind, "before_cursor_execute", observe)
    try:
        groups.recalculate(settings, tenant, limit=1)
        one = len(queries)
        queries.clear()
        groups.recalculate(settings, tenant, limit=20)
        assert len(queries) <= one + 1
    finally:
        event.remove(bind, "before_cursor_execute", observe)


def test_per_group_evaluations_count_only_own_members_and_winning_changes(tmp_path):
    settings, tenant = setup(tmp_path, 2)
    with get_session(settings.postgres_url) as session:
        rows = list(
            session.scalars(
                select(models.Asset)
                .where(models.Asset.tenant_id == tenant)
                .order_by(models.Asset.asset_id)
            )
        )
        first_id, second_id = [row.asset_id for row in rows]
        rows[1].environment = "lab"
    production = groups.save_group(settings, tenant, draft(priority=1))
    all_assets = groups.save_group(
        settings,
        tenant,
        draft(
            name="All",
            priority=2,
            rules={
                "any": [
                    {"field": "environment", "op": "in", "value": ["production", "lab"]}
                ]
            },
            context={"business_service": "all-winner"},
        ),
    )
    global_report = groups.reconcile_batch(settings, tenant)
    production_report = groups.list_evaluations(settings, tenant, production["id"])[0][
        0
    ]["report"]
    all_report = groups.list_evaluations(settings, tenant, all_assets["id"])[0][0][
        "report"
    ]
    assert (
        production_report["matched"],
        production_report["entrants"],
        production_report["changed"],
    ) == (1, 1, 0)
    assert (all_report["matched"], all_report["entrants"], all_report["changed"]) == (
        2,
        2,
        2,
    )
    assert {row["asset_id"] for row in production_report["transitions"]} == {first_id}
    assert production_report["transitions"][0]["changes"] == {}
    assert {row["asset_id"] for row in all_report["transitions"]} == {
        first_id,
        second_id,
    }
    assert all(
        change["group_id"] == all_assets["id"]
        for row in all_report["transitions"]
        for change in row["changes"].values()
    )
    with get_session(settings.postgres_url) as session:
        global_evaluation = session.get(
            models.AssetGroupEvaluation, global_report["evaluation_id"]
        )
        assert global_evaluation.group_id is None
        assert len(global_evaluation.report["transitions"]) == 2


def test_unchanged_worker_diagnostics_are_coalesced_without_mutating_receipts(tmp_path):
    settings, tenant = setup(tmp_path)
    group = groups.save_group(settings, tenant, draft())
    receipt = groups.reconcile_batch(settings, tenant)["evaluation_id"]
    for _ in range(5):
        groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        rows = list(
            session.scalars(
                select(models.AssetGroupEvaluation).where(
                    models.AssetGroupEvaluation.tenant_id == tenant
                )
            )
        )
        assert len(rows) == 4  # global + group immutable receipt and diagnostic each
        assert session.get(models.AssetGroupEvaluation, receipt).report["transitions"]
    assert (
        groups.list_evaluations(settings, tenant, group["id"])[0][0]["status"]
        == "completed"
    )
