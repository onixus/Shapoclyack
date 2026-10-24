"""Independent tenant, restart and writer concurrency acceptance for #578."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta
import json
from threading import Event
from time import perf_counter
from uuid import uuid4

import pytest
from sqlalchemy import event, func, select

from api.db import models
from api.db.engine import get_engine, get_session
from api.services import asset_groups as groups
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_risk_context import estate as estate

pytestmark = requires_postgres


def _draft(**changes):
    return {"name": "Production", "rules": {"all": [{"field": "environment", "op": "eq", "value": "production"}]},
            "context": {"business_service": "payments"}, **changes}


def _seed(settings, count=1):
    tenant = uuid4().hex
    ids = sorted(uuid4().hex for _ in range(count))
    with get_session(settings.postgres_url) as session:
        session.add(models.Tenant(tenant_id=tenant, name=tenant, created_at=datetime.now()))
        session.flush()
        for asset_id in ids:
            session.add(models.Asset(asset_id=asset_id, tenant_id=tenant, first_seen=datetime.now(),
                                     last_seen=datetime.now(), environment="production"))
    return tenant, ids


def _events(settings, tenant):
    with get_session(settings.postgres_url) as session:
        return session.scalar(select(func.count()).select_from(models.AssetContextEvent).where(models.AssetContextEvent.tenant_id == tenant))


def test_failed_batch_rolls_back_cursor_and_context_then_restarts(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    tenant, ids = _seed(settings, 3)
    group = groups.save_group(settings, tenant, _draft())
    first = groups.reconcile_batch(settings, tenant, limit=1)
    assert first["next_asset_id"] == ids[0]
    original = groups._batch

    def crash_after_writes(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated process loss before commit")

    monkeypatch.setattr(groups, "_batch", crash_after_writes)
    with pytest.raises(RuntimeError):
        groups.reconcile_batch(settings, tenant, limit=1)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.AssetGroupSweep, tenant).after_asset_id == ids[0]
        assert session.get(models.Asset, ids[1]).business_service is None
    assert _events(settings, tenant) == 1
    monkeypatch.setattr(groups, "_batch", original)
    assert groups.reconcile_batch(settings, tenant, limit=1)["next_asset_id"] == ids[1]
    assert not groups.reconcile_batch(settings, tenant, limit=1)["has_more"]
    groups.reconcile_batch(settings, tenant, limit=3)
    assert groups.list_members(settings, tenant, group["id"])[1] == 3
    assert _events(settings, tenant) == 3


def test_concurrent_context_writer_wins_over_waiting_recalculation(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    tenant, ids = _seed(settings)
    groups.save_group(settings, tenant, _draft())
    started = Event()
    original = groups._batch

    def announce(*args, **kwargs):
        started.set()
        return original(*args, **kwargs)

    monkeypatch.setattr(groups, "_batch", announce)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.Asset, ids[0], with_for_update=True)
            future = pool.submit(groups.reconcile_batch, settings, tenant)
            assert started.wait(5), "classification did not start"
            row.business_service = "operator-value"
            session.add(models.AssetContextEvent(tenant_id=tenant, asset_id=ids[0], field="business_service",
                old_value=None, new_value="operator-value", source="operator", occurred_at=datetime.now()))
        report = future.result(timeout=10)
    assert report["conflicts"] == 1
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, ids[0]).business_service == "operator-value"
        assert session.scalar(select(func.count()).select_from(models.AssetGroupProvenance).where(models.AssetGroupProvenance.tenant_id == tenant)) == 0


def test_scope_checks_cover_all_existing_group_operations(tmp_path):
    settings = make_settings(tmp_path)
    tenant, _ = _seed(settings)
    foreign, foreign_ids = _seed(settings)
    group = groups.save_group(settings, foreign, _draft())
    callbacks = [lambda: groups.get_group(settings, tenant, group["id"]),
                 lambda: groups.save_group(settings, tenant, {"name": "stolen"}, group_id=group["id"]),
                 lambda: groups.preview(settings, tenant, _draft(), group_id=group["id"]),
                 lambda: groups.recalculate(settings, tenant, group_id=group["id"]),
                 lambda: groups.list_members(settings, tenant, group["id"]),
                 lambda: groups.list_evaluations(settings, tenant, group["id"]),
                 lambda: groups.delete_group(settings, tenant, group["id"])]
    for callback in callbacks:
        with pytest.raises(LookupError):
            callback()
    groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, foreign_ids[0]).business_service is None
    assert groups.get_group(settings, foreign, group["id"])["name"] == "Production"


def test_routes_require_writer_and_hide_foreign_groups(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    foreign, _ = _seed(settings)
    theirs = groups.save_group(settings, foreign, _draft())
    gid = theirs["id"]
    for path in (f"/{gid}", f"/{gid}/members", f"/{gid}/evaluations"):
        assert client.get("/api/asset-groups" + path, headers=viewer).status_code == 404
    for method, path, body in [("post", "", _draft()), ("post", "/preview", _draft()),
            ("patch", f"/{gid}", {"name": "changed"}), ("post", f"/{gid}/recalculate", {}),
            ("delete", f"/{gid}", None)]:
        args = {"headers": viewer}
        if body is not None:
            args["json"] = body
        assert getattr(client, method)("/api/asset-groups" + path, **args).status_code == 403
    assert client.patch(f"/api/asset-groups/{gid}", headers=operator, json={"name": "changed"}).status_code == 404
    assert client.post(f"/api/asset-groups/{gid}/recalculate", headers=operator, json={}).status_code == 404
    assert client.post("/api/asset-groups/preview", headers=operator, json={**_draft(), "group_id": gid}).status_code == 404
    assert client.delete(f"/api/asset-groups/{gid}", headers=operator).status_code == 404
    for invalid in [
        {"rules": {"field": "made_up", "op": "eq", "value": "x"}},
        {"rules": {"field": "environment", "op": "regex", "value": ".*"}},
        {"rules": {"field": "asset_criticality", "op": "eq", "value": True}},
        {"context": {"exposure_level": "internet"}},
    ]:
        response = client.post("/api/asset-groups", headers=operator, json=_draft(**invalid))
        assert response.status_code == 422, response.text


def test_api_composite_rule_preview_is_a_read_only_transaction(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    operator = auth_headers(client, "operator")
    aid = uuid4().hex
    with get_session(settings.postgres_url) as session:
        session.add(models.Asset(asset_id=aid, tenant_id="default", first_seen=datetime.now(), last_seen=datetime.now(), environment="production"))
    draft = _draft(rules={"all": [{"field": "environment", "op": "eq", "value": "production"},
        {"any": [{"field": "status", "op": "eq", "value": "active"}, {"field": "tag:team", "op": "eq", "value": "blue"}]}]})
    created = client.post("/api/asset-groups", headers=operator, json=draft)
    assert created.status_code == 201, created.text
    gid = created.json()["id"]
    watched = (models.AssetGroup, models.AssetGroupVersion, models.AssetGroupMembership,
               models.AssetGroupProvenance, models.AssetContextEvent, models.AssetGroupEvaluation, models.AssetGroupSweep)

    def counts():
        with get_session(settings.postgres_url) as session:
            return {model.__tablename__: session.scalar(select(func.count()).select_from(model)) for model in watched}

    before = counts()
    response = client.post("/api/asset-groups/preview", headers=operator, json={**draft, "group_id": gid})
    assert response.status_code == 200, response.text
    report = response.json()
    assert (report["evaluated"], report["entrants"], report["exits"], report["changed"], report["conflicts"]) == (1, 1, 0, 1, 0)
    assert report["items"][0]["asset_id"] == aid and report["items"][0]["reasons"]
    assert counts() == before
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service is None


def test_maximum_batch_is_bounded_and_select_queries_do_not_scale_with_assets(tmp_path):
    settings = make_settings(tmp_path)
    tenant, _ = _seed(settings, 503)
    group = groups.save_group(settings, tenant, _draft())
    statements = []

    def count_reads(_connection, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    db_engine = get_engine(settings.postgres_url)
    event.listen(db_engine, "before_cursor_execute", count_reads)
    try:
        started = perf_counter()
        first = groups.reconcile_batch(settings, tenant, limit=500)
        duration = perf_counter() - started
        first_reads = len(statements)
        statements.clear()
        second = groups.reconcile_batch(settings, tenant, limit=500)
        second_reads = len(statements)
    finally:
        event.remove(db_engine, "before_cursor_execute", count_reads)
    assert first["evaluated"] == 500 and first["has_more"]
    assert second["evaluated"] == 3 and not second["has_more"]
    assert first_reads == second_reads
    assert first_reads < 25
    assert groups.list_members(settings, tenant, group["id"])[1] == 503
    print(f"500-asset batch: {duration:.3f}s, {first_reads} SELECTs; 3-asset batch: {second_reads} SELECTs")


def test_assignment_receipt_survives_new_rule_version_and_release(tmp_path):
    settings = make_settings(tmp_path)
    tenant, ids = _seed(settings)
    group = groups.save_group(settings, tenant, _draft())
    first = groups.recalculate(settings, tenant, group_id=group["id"])
    with get_session(settings.postgres_url) as session:
        original = deepcopy(session.get(models.AssetGroupEvaluation, first["evaluation_id"]).report)
    assignment = original["transitions"][0]["changes"]["business_service"]
    assert assignment == {"old": None, "new": "payments", "group_id": group["id"], "version": 1,
                          "source": "group_rule", "reason": assignment["reason"]}
    assert assignment["reason"][0]["actual"] == ["production"]
    groups.save_group(settings, tenant, {"context": {"business_service": "billing"}}, group_id=group["id"])
    groups.recalculate(settings, tenant, group_id=group["id"])
    groups.delete_group(settings, tenant, group["id"])
    groups.reconcile_batch(settings, tenant)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, ids[0]).business_service is None
        assert session.get(models.AssetGroupEvaluation, first["evaluation_id"]).report == original
        assert session.scalar(select(models.AssetGroupVersion.document).where(
            models.AssetGroupVersion.group_id == group["id"], models.AssetGroupVersion.version == 1))["context"] == {"business_service": "payments"}


def test_actual_worker_tick_discovers_excludes_and_preserves_manual_override(tmp_path, monkeypatch):
    from api.services import asset_group_worker as worker, assets, runs
    from api.services.artifact_store import keys, workspace
    from scanner.pipeline.asset_identity import ip_identity_key

    settings = make_settings(tmp_path)
    tenant, _ = _seed(settings, 0)
    monkeypatch.setattr(worker, "_stop", Event())
    group = groups.save_group(settings, tenant, _draft(rules={"all": [
        {"field": "ip", "op": "cidr", "value": "10.78.0.0/24"},
        {"field": "status", "op": "eq", "value": "active"},
    ]}))
    worker.tick(settings)
    assert groups.list_members(settings, tenant, group["id"])[1] == 0
    run_id = "discovery-" + uuid4().hex[:12]
    directory = workspace.run_dir(settings, keys.run_ref(run_id, tenant), refresh=False)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "alive_hosts.json").write_text(json.dumps([{"host": "10.78.0.5"}]))
    runs.stage_run_tenant(directory, tenant)
    assert assets.upsert_assets_from_run(settings, tenant_id=tenant, run_id=run_id).assets_created == 1
    aid = ip_identity_key(tenant, "10.78.0.5")
    worker.tick(settings)
    assert groups.list_members(settings, tenant, group["id"])[0][0]["asset_id"] == aid
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service == "payments"
    assets.update_asset(settings, tenant, aid, {"status": "decommissioned"}, actor="operator")
    worker.tick(settings)
    assert groups.list_members(settings, tenant, group["id"])[1] == 0
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service is None
    assets.upsert_assets_from_run(settings, tenant_id=tenant, run_id=run_id)
    worker.tick(settings)
    assets.update_asset(settings, tenant, aid, {"business_service": "manual-owner"}, actor="operator")
    count = _events(settings, tenant)
    worker.tick(settings)
    worker.tick(settings)
    groups.delete_group(settings, tenant, group["id"])
    worker.tick(settings)
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service == "manual-owner"
    assert _events(settings, tenant) == count


def test_classification_preserves_finding_identity_sla_history_and_captured_risk(estate):
    from api.services import runs
    from tests.test_risk_context import _register

    settings, tenant, _, aid, _, _, _, _, _ = estate
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Asset, aid)
        row.asset_criticality = None
        row.environment = "production"
    _register(settings, tenant)
    with get_session(settings.postgres_url) as session:
        finding = session.scalars(select(models.Vulnerability).where(models.Vulnerability.tenant_id == tenant)).first()
        finding.exception_until = datetime.now() + timedelta(days=30)
        finding.exception_reason = "Approved temporary compensating control"
        finding.exception_by = "risk-approver"
        finding.assignee = "remediation-owner"
        finding.owner_team = "payments-remediation"
    historical = [item.model_dump() for item in runs.get_vulnerabilities(settings, "risk-run", tenant_id=tenant)]

    def state():
        with get_session(settings.postgres_url) as session:
            return {model.__tablename__: [deepcopy({column.name: getattr(row, column.name) for column in model.__table__.columns})
                    for row in session.scalars(select(model).where(model.tenant_id == tenant).order_by(*model.__table__.primary_key.columns))]
                    for model in (models.Vulnerability, models.VulnerabilityEvent, models.RunRiskAssessment)}

    before = state()
    groups.save_group(settings, tenant, _draft(context={"asset_criticality": 4}))
    groups.reconcile_batch(settings, tenant)
    assert state() == before
    assert [item.model_dump() for item in runs.get_vulnerabilities(settings, "risk-run", tenant_id=tenant)] == historical
    current = runs.get_vulnerabilities(settings, "risk-run", tenant_id=tenant, assessment_mode="current")
    assert all(item.asset_criticality == 4 and item.risk_assessment["mode"] == "current" for item in current)
    assert any(old["contextual_score"] != new.contextual_score for old, new in zip(historical, current, strict=True))
    assert state() == before


def test_classified_group_targets_still_pass_scope_deny_and_scan_policy(tmp_path, monkeypatch):
    from api.services import scan_scopes

    settings = make_settings(tmp_path, job_execution_mode="agent")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    tenant = "default"
    aid = uuid4().hex
    with get_session(settings.postgres_url) as session:
        session.add(models.Asset(asset_id=aid, tenant_id=tenant, first_seen=datetime.now(), last_seen=datetime.now(), environment="production"))
        session.flush()
        session.add(models.AssetIdentifier(asset_id=aid, tenant_id=tenant, identifier_type="ip", identifier_value="10.78.0.5"))
    group = groups.save_group(settings, tenant, _draft())
    groups.reconcile_batch(settings, tenant)
    assert groups.list_members(settings, tenant, group["id"])[1] == 1
    scope = [
        {"effect": "allow", "kind": "cidr", "value": "10.78.0.0/24"},
        {"effect": "deny", "kind": "cidr", "value": "10.78.0.5/32"},
    ]
    scan_scopes.replace_scope(settings, tenant_id=tenant, entries=scope, approved_by="admin")
    operator = auth_headers(client, "operator")
    denied = client.post("/api/jobs", headers=operator, json={"mode": "safe", "ranges": "10.78.0.5"})
    assert denied.status_code == 403 and "denied" in denied.json()["detail"]
    # Outside the allow list remains out of scope even after classification.
    outside = client.post("/api/jobs", headers=operator, json={"mode": "safe", "ranges": "192.0.2.5"})
    assert outside.status_code == 403
    scan_scopes.replace_scope(settings, tenant_id=tenant, entries=scope[:1], approved_by="admin")
    assert client.put("/api/tenants/default/scan-policy", headers=auth_headers(client, "admin"), json={"safe_only": True}).status_code == 200
    policy = client.post("/api/jobs", headers=operator, json={"mode": "fast", "ranges": "10.78.0.5"})
    assert policy.status_code == 403 and "safe" in policy.json()["detail"]
    with get_session(settings.postgres_url) as session:
        assert session.scalar(select(func.count()).select_from(models.Job).where(models.Job.tenant_id == tenant)) == 0
