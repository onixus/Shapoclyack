"""Mixed fleet identity and authoritative per-source inventory regressions."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.schemas import EndpointInventorySnapshotRequest, EndpointSoftwareItem
from api.services import endpoint_inventory as inventory
from api.services import software_match_worker, tenants
from tests.conftest import make_settings, requires_postgres


def _now():
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _item(instance="a", version="1.0", source="pip"):
    return EndpointSoftwareItem(
        name="example",
        version=version,
        source=source,
        product_identity=f"example|||{source}",
        installation_identity=hashlib.sha256(instance.encode()).hexdigest(),
        install_instance_id=hashlib.sha256(instance.encode()).hexdigest(),
        scope="runtime",
        package_id="example",
    )


def _request(snapshot="v2_1", items=None, statuses=None, **overrides):
    now = _now()
    values = dict(
        schema_version=2,
        snapshot_id=snapshot,
        agent_id="v2-agent",
        hostname="v2-host",
        os_family="linux",
        os_name="Ubuntu",
        os_version="24.04",
        agent_version="0.5.0",
        collected_at=now,
        software=items if items is not None else [_item()],
        sources=[
            dict(
                source=source,
                status=status,
                collected_at=now,
                collector_version="0.5.0",
            )
            for source, status in (statuses or [("pip", "complete")])
        ],
    )
    values.update(overrides)
    return EndpointInventorySnapshotRequest(**values)


def test_side_by_side_installations_have_distinct_comparison_keys():
    assert inventory._comparison_key(_item("old")) != inventory._comparison_key(
        _item("new")
    )


def test_v2_requires_source_status_and_private_installation_identity():
    with pytest.raises(ValidationError, match="collection status"):
        _request(sources=[])
    with pytest.raises(ValidationError, match="raw install"):
        _request(
            items=[
                _item().model_copy(update={"install_location": "/Users/private/env"})
            ]
        )
    with pytest.raises(ValidationError, match="requires product"):
        _request(items=[EndpointSoftwareItem(name="example", source="pip")])
    with pytest.raises(ValidationError, match="duplicate source"):
        _request(statuses=[("pip", "complete"), ("pip", "failed")])


def test_v1_canonical_digest_preserves_pre_v2_replay_contract():
    request = EndpointInventorySnapshotRequest(
        schema_version=1,
        snapshot_id="legacy",
        agent_id="old",
        hostname="host",
        agent_version="0.4.0",
        collected_at=_now(),
        software=[EndpointSoftwareItem(name="x")],
    )
    old_payload = request.model_dump(mode="json")
    old_payload.pop("sources")
    for item in old_payload["software"]:
        for field in inventory._IDENTITY_FIELDS:
            item.pop(field)
    expected = hashlib.sha256(
        json.dumps(old_payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert inventory._canonical_digest(request) == expected


@pytest.fixture()
def settings(tmp_path):
    settings = make_settings(tmp_path)
    tenants.configure(settings)
    tenants.load_tenants(settings)
    tenants.reset_for_tests()
    tenants.load_tenants(settings)
    inventory.configure(settings)
    inventory.reset_for_tests()
    return settings


def _ingest(request):
    return inventory.ingest_snapshot(
        tenant_id="default", agent_id="v2-agent", request=request
    )


def _rows(settings, snapshot):
    with get_session(settings.postgres_url) as session:
        return list(
            session.scalars(
                select(models.EndpointSoftwareItem).where(
                    models.EndpointSoftwareItem.snapshot_id == snapshot
                )
            )
        )


@requires_postgres
def test_side_by_side_update_and_removal_are_per_installation(settings):
    first = _ingest(_request(items=[_item("old", "1.0"), _item("new", "2.0")]))
    assert first["software_count"] == 2
    second = _ingest(_request("v2_2", items=[_item("old", "1.1"), _item("new", "2.0")]))
    assert second["changes"] == {"installed": 0, "removed": 0, "updated": 1}
    third = _ingest(_request("v2_3", items=[_item("new", "2.0")]))
    assert third["changes"] == {"installed": 0, "removed": 1, "updated": 0}
    assert (
        _rows(settings, "v2_3")[0].installation_identity
        == _item("new").installation_identity
    )


@requires_postgres
@pytest.mark.parametrize("status", ["partial", "failed", "not_applicable"])
def test_incomplete_source_retains_last_complete_without_rematching(settings, status):
    first_request = _request()
    first = _ingest(first_request)
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, first["device_id"])
        device.last_matched_snapshot_id = "v2_1"
    second = _ingest(
        _request("v2_2", items=[_item(version="9.9")], statuses=[("pip", status)])
    )
    assert second["changes"] == {"installed": 0, "removed": 0, "updated": 0}
    assert _rows(settings, "v2_2")[0].version == "1.0"
    state = inventory.get_device("default", first["device_id"])["sources"][0]
    assert state["status"] == status
    assert state["last_complete_at"] == first_request.collected_at
    assert (
        software_match_worker.pending_device_ids(
            settings, tenant_id="default", limit=10
        )
        == []
    )


@requires_postgres
def test_failed_python_does_not_block_complete_dpkg_or_remove_python(settings):
    _ingest(
        _request(
            items=[_item("python", source="pip"), _item("system", source="dpkg")],
            statuses=[("pip", "complete"), ("dpkg", "complete")],
        )
    )
    second = _ingest(
        _request(
            "v2_2",
            items=[_item("system", "2.0", "dpkg")],
            statuses=[("pip", "failed"), ("dpkg", "complete")],
        )
    )
    assert second["software_count"] == 2
    assert second["changes"] == {"installed": 0, "removed": 0, "updated": 1}
    assert {(row.source, row.version) for row in _rows(settings, "v2_2")} == {
        ("pip", "1.0"),
        ("dpkg", "2.0"),
    }


@requires_postgres
def test_omitted_source_is_degraded_and_cannot_remove_previous_installations(settings):
    first = _ingest(_request())
    second = _ingest(_request("v2_2", items=[], statuses=[("dpkg", "complete")]))
    assert second["changes"]["removed"] == 0
    assert second["software_count"] == 1
    state = next(
        s
        for s in inventory.get_device("default", first["device_id"])["sources"]
        if s["source"] == "pip"
    )
    assert state["diagnostic_code"] == "source_not_reported"


@requires_postgres
def test_v1_to_v2_transition_establishes_baseline_and_rollback_keeps_both(settings):
    legacy = _request().model_dump()
    legacy.update(
        schema_version=1,
        sources=[],
        software=[dict(name="example", version="1.0", source="pip")],
    )
    _ingest(EndpointInventorySnapshotRequest(**legacy))
    second = _ingest(_request("v2_2", items=[_item("old"), _item("new", "2.0")]))
    assert second["software_count"] == 2
    assert second["changes"] == {"installed": 0, "removed": 0, "updated": 0}
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, second["device_id"])
        device.last_matched_snapshot_id = "v2_2"
    legacy["snapshot_id"] = "v1_rollback"
    legacy["collected_at"] = _now()
    rollback = _ingest(EndpointInventorySnapshotRequest(**legacy))
    assert rollback["software_count"] == 2
    assert all(row.installation_identity for row in _rows(settings, "v1_rollback"))
    for index in range(2, 4):
        legacy["snapshot_id"] = f"v1_rollback_{index}"
        legacy["collected_at"] = _now()
        rollback = _ingest(EndpointInventorySnapshotRequest(**legacy))
        assert rollback["software_count"] == 2
        assert rollback["changes"] == {"installed": 0, "removed": 0, "updated": 0}
        assert all(
            row.installation_identity for row in _rows(settings, legacy["snapshot_id"])
        )
        assert all(
            state["diagnostic_code"] == "schema_downgrade"
            for state in inventory.get_device("default", rollback["device_id"])[
                "sources"
            ]
        )
    assert (
        software_match_worker.pending_device_ids(
            settings, tenant_id="default", limit=10
        )
        == []
    )


@requires_postgres
def test_old_complete_snapshot_cannot_overwrite_newer_installations(settings):
    first = _ingest(_request())
    newer = _request("v2_2", items=[_item("new", "2.0")])
    _ingest(newer)
    with pytest.raises(ValueError, match="precedes"):
        _ingest(
            _request(
                "v2_delayed",
                collected_at=(datetime.now(UTC) - timedelta(seconds=10)).isoformat(),
                sources=[],
                items=[],
            )
        )
    assert (
        inventory.get_device("default", first["device_id"])["latest_snapshot_id"]
        == "v2_2"
    )


@requires_postgres
def test_unchanged_complete_inventory_assesses_new_advisories(
    settings, tmp_path, monkeypatch
):
    from pathlib import Path
    from api.services import advisories, software_findings

    feed = json.loads(
        (
            Path(__file__).parent / "fixtures/advisories/ubuntu-lifecycle.json"
        ).read_text()
    )
    feed_path = tmp_path / "ubuntu-advisories.json"
    feed_path.write_text(json.dumps(feed))
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(feed_path))
    monkeypatch.setenv("OCTO_CVSS4_DATABASE", str(tmp_path / "no-cvss4.json"))
    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()
    item = _item(source="dpkg").model_copy(
        update={"name": "curl", "version": "7.68.0-1ubuntu2.1"}
    )
    try:
        first = _ingest(
            _request(items=[item], statuses=[("dpkg", "complete")], os_version="20.04")
        )
        software_match_worker.sweep_tenant(settings, "default")
        with get_session(settings.postgres_url) as session:
            assert set(session.scalars(select(models.Vulnerability.cve))) == {
                "CVE-2023-38545"
            }
        new_advisory = dict(feed["entries"][0])
        new_advisory["cve_ids"] = ["CVE-2026-33333"]
        new_advisory["advisory_id"] = "USN-NEW-1"
        feed["entries"].append(new_advisory)
        feed_path.write_text(json.dumps(feed))
        advisories.reload_providers()

        second = _ingest(
            _request(
                "v2_2",
                items=[item],
                statuses=[("dpkg", "complete")],
                os_version="20.04",
            )
        )
        assert second["changes"] == {"installed": 0, "removed": 0, "updated": 0}
        assert software_match_worker.pending_device_ids(
            settings, tenant_id="default", limit=10
        ) == [first["device_id"]]
        software_match_worker.sweep_tenant(settings, "default")
        with get_session(settings.postgres_url) as session:
            assert set(session.scalars(select(models.Vulnerability.cve))) == {
                "CVE-2023-38545",
                "CVE-2026-33333",
            }
    finally:
        advisories.reload_providers()
        software_findings.reset_cvss4_cache_for_tests()


@requires_postgres
def test_retention_keeps_last_effective_software_snapshot_after_degraded_receipts(
    settings,
):
    from datetime import timedelta
    from api.services import endpoint_retention

    first = _ingest(_request())
    _ingest(_request("v2_2", items=[], statuses=[("pip", "failed")]))
    with get_session(settings.postgres_url) as session:
        old = session.get(models.EndpointInventorySnapshot, "v2_1")
        old.received_at = datetime.now(UTC) - timedelta(days=120)
    endpoint_retention.sweep_tenant(settings, "default")
    assert _rows(settings, "v2_1")[0].version == "1.0"
    assert (
        inventory.get_device("default", first["device_id"])["latest_snapshot_id"]
        == "v2_2"
    )


def test_shared_v2_fixture_accepts_both_jdk_installations_without_raw_paths():
    from pathlib import Path

    payload = json.loads(
        (
            Path(__file__).parent / "fixtures/endpoint_inventory_v2_valid.json"
        ).read_text()
    )
    request = EndpointInventorySnapshotRequest.model_validate(payload)
    assert len(request.software) == 2
    assert len({item.installation_identity for item in request.software}) == 2
    assert all(item.install_location is None for item in request.software)
    assert request.sources[0].status == "failed"
