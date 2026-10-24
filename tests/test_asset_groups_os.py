"""Confirmed OS classification uses fresh tenant-bound endpoint facts only."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import asset_groups as groups
from tests.conftest import requires_postgres
from tests.test_asset_groups import setup

NOW = datetime(2026, 10, 24, 12, tzinfo=UTC)


def observation(
    *, family="windows", status="linked", age=1, received_age=1, snapshot=True
):
    device = SimpleNamespace(
        device_id="device",
        latest_snapshot_id="snapshot",
        reconciliation_status=status,
        os_family=family,
    )
    receipt = (
        SimpleNamespace(
            snapshot_id="snapshot",
            collected_at=NOW - timedelta(hours=age),
            received_at=NOW - timedelta(hours=received_age),
        )
        if snapshot
        else None
    )
    return device, receipt


@pytest.mark.parametrize(
    "observations,state,family",
    [
        ([], "missing", None),
        ([observation()], "confirmed", "windows"),
        ([observation(family="Darwin")], "confirmed", "macos"),
        ([observation(family="LINUX")], "confirmed", "linux"),
        ([observation(age=49)], "stale", None),
        ([observation(received_age=49)], "stale", None),
        ([observation(age=-1)], "stale", None),
        ([observation(snapshot=False)], "missing", None),
        ([observation(family="Windows Server 2022")], "unknown", None),
        ([observation(status="conflict")], "conflict", None),
        ([observation(status="unlinked")], "conflict", None),
        ([observation(), observation(family="linux")], "conflict", None),
        ([observation(), observation(age=49)], "stale", None),
        ([observation(), observation()], "confirmed", "windows"),
    ],
)
def test_os_evidence_is_explicit_fresh_and_unambiguous(observations, state, family):
    snapshot = groups._endpoint_os_snapshot(observations, now=NOW, freshness_hours=48)
    assert snapshot["os_family"] == family
    assert snapshot["_os_evidence"]["state"] == state
    assert snapshot["_os_evidence"]["source"] == "endpoint_inventory"


def _endpoint(
    settings,
    tenant,
    aid,
    *,
    family="windows",
    age=1,
    status="linked",
    snapshot_tenant=None,
):
    now = datetime.now(UTC).replace(tzinfo=None)
    did, sid = uuid4().hex, uuid4().hex
    with get_session(settings.postgres_url) as session:
        session.add(
            models.EndpointDevice(
                device_id=did,
                tenant_id=tenant,
                agent_id=uuid4().hex,
                asset_id=aid,
                hostname="os.example",
                os_family=family,
                agent_version="test",
                reconciliation_status=status,
                first_seen=now,
                last_seen=now,
                last_inventory_at=now,
                latest_snapshot_id=sid,
            )
        )
        session.flush()
        session.add(
            models.EndpointInventorySnapshot(
                snapshot_id=sid,
                tenant_id=snapshot_tenant or tenant,
                device_id=did,
                schema_version=1,
                collected_at=now - timedelta(hours=age),
                received_at=now,
                payload_digest="test",
                software_count=0,
            )
        )
    return did, sid


def _os_draft(negate=False):
    return {
        "name": "Confirmed Windows",
        "rules": {
            "all": [
                {"field": "os_family", "op": "eq", "value": "windows", "negate": negate}
            ]
        },
        "context": {"business_service": "windows-estate"},
    }


@requires_postgres
def test_network_os_guess_is_never_confirmed_even_under_negation(tmp_path):
    settings, tenant = setup(tmp_path)
    with get_session(settings.postgres_url) as session:
        aid = session.scalar(
            select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant)
        )
        session.add(
            models.AssetOs(
                asset_id=aid,
                tenant_id=tenant,
                os_name="Windows",
                accuracy=100,
                source="pulse",
                last_seen_at=datetime.now(),
            )
        )
    for negate in (False, True):
        report = groups.preview(settings, tenant, _os_draft(negate))
        assert report["matched"] == 0
        assert not report["items"][0]["changes"]


@requires_postgres
def test_fresh_endpoint_assigns_then_expiry_removes_membership_and_context(tmp_path):
    settings, tenant = setup(tmp_path)
    with get_session(settings.postgres_url) as session:
        aid = session.scalar(
            select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant)
        )
    did, sid = _endpoint(settings, tenant, aid)
    group = groups.save_group(settings, tenant, _os_draft())
    first = groups.reconcile_batch(settings, tenant)
    assert first["matched"] == 1 and first["changed"] == 1
    reason = first["items"][0]["reasons"][0]
    assert reason["evidence"]["state"] == "confirmed"
    assert reason["evidence"]["observations"][0]["snapshot_id"] == sid
    with get_session(settings.postgres_url) as session:
        session.get(models.EndpointInventorySnapshot, sid).collected_at = datetime.now(
            UTC
        ).replace(tzinfo=None) - timedelta(hours=49)
    second = groups.reconcile_batch(settings, tenant)
    assert second["exits"] == 1 and second["changed"] == 1
    assert groups.list_members(settings, tenant, group["id"])[1] == 0
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, aid).business_service is None


@requires_postgres
@pytest.mark.parametrize(
    "kind",
    ["cross_tenant_snapshot", "conflict", "disagree", "custom_freshness", "overflow"],
)
def test_os_ambiguity_and_cross_tenant_receipts_never_match(tmp_path, kind):
    settings, tenant = setup(tmp_path)
    with get_session(settings.postgres_url) as session:
        aid = session.scalar(
            select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant)
        )
    if kind == "cross_tenant_snapshot":
        _endpoint(settings, tenant, aid, snapshot_tenant=uuid4().hex)
    elif kind == "conflict":
        _endpoint(settings, tenant, aid, status="conflict")
    elif kind == "disagree":
        _endpoint(settings, tenant, aid)
        _endpoint(settings, tenant, aid, family="linux")
    elif kind == "overflow":
        for _ in range(groups.MAX_OS_ENDPOINTS + 1):
            _endpoint(settings, tenant, aid)
    else:
        from dataclasses import replace

        settings = replace(settings, endpoint_stale_hours=1)
        _endpoint(settings, tenant, aid, age=2)
    for negate in (False, True):
        preview = groups.preview(settings, tenant, _os_draft(negate))
        assert preview["matched"] == 0
        if kind == "cross_tenant_snapshot":
            assert (
                preview["items"][0]["reasons"][0]["evidence"]["observations"][0][
                    "snapshot_id"
                ]
                is None
            )
        elif kind == "overflow":
            evidence = preview["items"][0]["reasons"][0]["evidence"]
            assert evidence["state"] == "incomplete"
            assert len(evidence["observations"]) == groups.MAX_OS_ENDPOINTS


def test_os_evidence_overflow_is_incomplete_instead_of_hiding_conflicts():
    observations = [observation() for _ in range(groups.MAX_OS_ENDPOINTS)] + [
        observation(family="linux")
    ]
    snapshot = groups._endpoint_os_snapshot(observations, now=NOW, freshness_hours=48)
    assert snapshot["os_family"] is None
    assert snapshot["_os_evidence"]["state"] == "incomplete"
    assert len(snapshot["_os_evidence"]["observations"]) == groups.MAX_OS_ENDPOINTS
    assert snapshot["_os_evidence"]["observations_truncated"]


@requires_postgres
def test_ingest_latest_os_is_atomic_and_replay_or_older_receipt_cannot_replace_it(
    tmp_path, monkeypatch
):
    from api.schemas import EndpointInventorySnapshotRequest
    from api.services import endpoint_inventory

    settings, tenant = setup(tmp_path)
    monkeypatch.setattr(endpoint_inventory, "_settings", settings)
    with get_session(settings.postgres_url) as session:
        aid = session.scalar(
            select(models.Asset.asset_id).where(models.Asset.tenant_id == tenant)
        )
        session.add(
            models.AssetIdentifier(
                asset_id=aid,
                tenant_id=tenant,
                identifier_type="fqdn",
                identifier_value="os.example",
            )
        )
    agent = uuid4().hex
    now = datetime.now(UTC)

    def request(family, minutes):
        return EndpointInventorySnapshotRequest(
            schema_version=1,
            snapshot_id=uuid4().hex,
            agent_id=agent,
            collected_at=(now - timedelta(minutes=minutes)).isoformat(),
            hostname="os.example",
            os_family=family,
            agent_version="test",
        )

    first = request("windows", 2)
    endpoint_inventory.ingest_snapshot(tenant_id=tenant, agent_id=agent, request=first)
    assert groups.preview(settings, tenant, _os_draft())["matched"] == 1
    second = request("linux", 1)
    endpoint_inventory.ingest_snapshot(tenant_id=tenant, agent_id=agent, request=second)
    replay = endpoint_inventory.ingest_snapshot(
        tenant_id=tenant, agent_id=agent, request=first
    )
    assert replay["_replay"]
    with pytest.raises(endpoint_inventory.ConflictError):
        endpoint_inventory.ingest_snapshot(
            tenant_id=tenant,
            agent_id=agent,
            request=first.model_copy(update={"os_family": "macos"}),
        )
    with pytest.raises(ValueError, match="precedes"):
        endpoint_inventory.ingest_snapshot(
            tenant_id=tenant, agent_id=agent, request=request("windows", 3)
        )
    assert groups.preview(settings, tenant, _os_draft())["matched"] == 0
    with get_session(settings.postgres_url) as session:
        device = session.scalar(
            select(models.EndpointDevice).where(
                models.EndpointDevice.tenant_id == tenant,
                models.EndpointDevice.agent_id == agent,
            )
        )
        assert (device.os_family, device.latest_snapshot_id) == (
            "linux",
            second.snapshot_id,
        )
