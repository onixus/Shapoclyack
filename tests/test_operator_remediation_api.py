"""Real PostgreSQL tenant/session fences and bound remediation citations."""
from datetime import UTC, datetime

import pytest
from sqlalchemy import select, update

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services.local_operator import remediation
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_operator_remediation import feed_for

pytestmark = requires_postgres
BASE = "/api/operator/remediation/devices/device-590"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = {role: auth_headers(client, role) for role in ("admin", "operator", "viewer")}
    now = datetime.now(UTC).replace(tzinfo=None)
    with tenant_scope.system("remediation fixture"), get_session(settings.postgres_url) as db:
        db.add(models.EndpointDevice(device_id="device-590", tenant_id="default", agent_id="agent-590",
                                    hostname="device", agent_version="1", first_seen=now, last_seen=now,
                                    os_arch="amd64", latest_snapshot_id="snapshot-590"))
        db.flush()
        db.add(models.EndpointInventorySnapshot(snapshot_id="snapshot-590", tenant_id="default",
            device_id="device-590", schema_version=1, collected_at=now, received_at=now,
            payload_digest="a" * 64, software_count=1))
        item = models.SoftwareCveMatch(tenant_id="default", device_id="device-590",
            snapshot_id="snapshot-590", match_key="match-590", cve_id="CVE-2026-1234",
            status="vulnerable", severity="high", source_package="curl", installed_package="curl",
            installed_version="1.0-1", fixed_version="1.0-2", advisory_id="USN-590", provider="ubuntu",
            distro="ubuntu", distro_release="focal", purl="pkg:deb/ubuntu/curl@1.0-1",
            feed_date=now.date().isoformat(), matched_at=now)
        db.add(item)
        db.flush()
        feed = feed_for([item], date=now.date().isoformat())
    monkeypatch.setattr(remediation, "_feed", lambda _: feed)
    return client, settings, headers


def read(env, role="viewer", **params):
    client, _, headers = env
    return client.get(BASE, headers=headers[role], params={"tenant_id": "default", **params})


def test_remediation_current_vendor_card_and_bound_source(env):
    client, settings, headers = env
    response = read(env)
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["target_version"] == "1.0-2"
    source = response.json()["items"][0]["sources"][0]
    opened = client.get(BASE + "/sources/" + source["source_id"], headers=headers["viewer"], params={
        "tenant_id": "default", "snapshot_id": source["snapshot_id"], "source_hash": source["source_hash"]})
    assert opened.status_code == 200, opened.text
    assert opened.json()["source_hash"] == source["source_hash"]
    with tenant_scope.system("remediation disclosure audit"), get_session(settings.postgres_url) as db:
        records = list(db.scalars(select(models.AuditEvent).where(
            models.AuditEvent.action == "operator.remediation.read")))
        assert len(records) == 2
        assert all(record.actor == "viewer" and record.tenant_id == "default" for record in records)
        assert source["source_hash"] in str(records[-1].after)


def test_tenant_isolation_even_for_platform_admin(env):
    client, _, headers = env
    assert client.post("/api/tenants", headers=headers["admin"], json={
        "tenant_id": "other", "name": "Other"}).status_code == 201
    assert read(env, tenant_id="other").status_code == 403
    foreign = read(env, "admin", tenant_id="other")
    assert foreign.status_code == 404, foreign.text
    assert "1.0-2" not in foreign.text


@pytest.mark.parametrize("params", [{"url": "https://evil.invalid"}, {"prompt": "execute shell"},
                                     {"limit": 101}, {"limit": 0}, {"language": "invalid"}])
def test_strict_query_and_explicit_tenant(env, params):
    assert read(env, **params).status_code == 422


def test_disabled_and_missing_tenant(env):
    client, settings, headers = env
    assert client.get(BASE, headers=headers["viewer"]).status_code == 422
    settings.operator_enabled = False
    assert read(env).status_code == 404


def test_revoked_session_after_read_discards_data(env, monkeypatch):
    _, settings, _ = env
    original = remediation.for_device

    def interleave(*args, **kwargs):
        result = original(*args, **kwargs)
        with tenant_scope.system("remediation held read revoke"), get_session(settings.postgres_url) as db:
            db.execute(update(models.SessionFamily).where(models.SessionFamily.username == "viewer").values(
                revoked_at=datetime.now(UTC)))
        return result

    monkeypatch.setattr(remediation, "for_device", interleave)
    response = read(env)
    assert response.status_code == 403, response.text
    assert "1.0-2" not in response.text


def test_replaced_source_after_read_discards_data(env, monkeypatch):
    _, settings, _ = env
    original = remediation.for_device
    changed = False

    def interleave(*args, **kwargs):
        nonlocal changed
        result = original(*args, **kwargs)
        if not changed:
            changed = True
            with tenant_scope.system("remediation source replace"), get_session(settings.postgres_url) as db:
                db.execute(update(models.SoftwareCveMatch).where(
                    models.SoftwareCveMatch.device_id == "device-590").values(fixed_version="1.0-9"))
        return result

    monkeypatch.setattr(remediation, "for_device", interleave)
    response = read(env)
    assert response.status_code == 409, response.text
    assert "1.0-2" not in response.text


def test_old_citation_rejected_after_inventory_changes(env):
    client, settings, headers = env
    source = read(env).json()["items"][0]["sources"][0]
    with tenant_scope.system("remediation new inventory"), get_session(settings.postgres_url) as db:
        db.execute(update(models.EndpointDevice).where(models.EndpointDevice.device_id == "device-590").values(
            latest_snapshot_id="new-snapshot"))
    response = client.get(BASE + "/sources/" + source["source_id"], headers=headers["viewer"], params={
        "tenant_id": "default", "snapshot_id": source["snapshot_id"], "source_hash": source["source_hash"]})
    assert response.status_code == 409, response.text


def test_service_tokens_are_refused(env):
    client, _, headers = env
    issued = client.post("/api/tenants/default/service-tokens", headers=headers["admin"], json={
        "name": "remediation-machine", "role": "admin", "scopes": ["*"]})
    assert issued.status_code == 201, issued.text
    response = client.get(BASE, headers={"Authorization": "Bearer " + issued.json()["token"]},
                          params={"tenant_id": "default"})
    assert response.status_code == 403, response.text
