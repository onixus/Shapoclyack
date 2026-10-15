"""ServiceNow reads are bounded, tenant-safe and preserve operator context."""
import io
import json
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.schemas import AssetConnectorRequest
from api.services import asset_connector as connector, crypto
from api.services.integrations import delivery
from tests.conftest import configured_client, make_settings, auth_headers, requires_postgres


def row(**extra):
    return SimpleNamespace(base_url="https://snow.example", table="cmdb_ci_computer",
        field_mapping={"ip": "ip_address", "owner_email": "owned_by.email"},
        token_encrypted="local-test-token", tenant_id="default", **extra)


@pytest.fixture
def wire(monkeypatch):
    monkeypatch.setattr(delivery, "validate_url", lambda url, **kw: url)
    calls = []
    def install(pages):
        pages = iter(pages)
        def request(*args, **kwargs):
            calls.append((args, kwargs))
            return delivery.DeliveryResult(ok=True, status_code=200, error=None, retryable=False,
                duration_seconds=0, body=json.dumps({"result": next(pages)}))
        monkeypatch.setattr(delivery, "request", request)
        return calls
    return install


@pytest.mark.parametrize("url", ["http://snow.example", "https://user:pw@snow.example", "https://snow.example/path", "https://snow.example?x=1", "https://snow.example#x"])
def test_https_origin_only(url):
    with pytest.raises(ValueError):
        connector.validate_config(url, "cmdb_ci", {"ip": "ip_address"})


@pytest.mark.parametrize("mapping", [{"asset_id": "sys_id"}, {"ip": "x^ORactive=true"}, {"owner_email": "owned_by.email"}, {"ip": "ip_address", "tag:bad key": "sys_id"}])
def test_mapping_cannot_override_asset_pk_or_inject_queries(mapping):
    with pytest.raises(ValueError):
        connector.validate_config("https://snow.example", "cmdb_ci", mapping)


def test_fetch_uses_bounded_pinned_transport_and_reference_value(wire):
    calls = wire([[{"sys_id": "ci1", "ip_address": "10.1.1.1", "owned_by.email": {"value": "ada@example.com", "display_value": "Administrator"}}]])
    content = json.loads(connector.fetch(row()))
    assert content == [{"ip": "10.1.1.1", "owner_email": "ada@example.com"}]
    assert calls[0][1]["allow_private"] is False
    assert calls[0][1]["response_limit_bytes"] == connector.MAX_PAGE_BYTES
    query = parse_qs(urlsplit(calls[0][0][1]).query)
    assert query["sysparm_query"] == ["ORDERBYsys_id"]
    assert query["sysparm_limit"] == ["200"]


def test_failed_wire_does_not_leak_remote_error(monkeypatch, wire):
    wire([])
    monkeypatch.setattr(delivery, "request", lambda *a, **kw: delivery.DeliveryResult(ok=False,
        status_code=403, error="echo-secret-token", retryable=False, duration_seconds=0))
    with pytest.raises(ValueError, match="HTTP 403") as exc:
        connector.fetch(row())
    assert "echo-secret" not in str(exc.value)


def test_pagination_repetition_aborts_before_import(monkeypatch, wire):
    monkeypatch.setattr(connector, "PAGE_SIZE", 1)
    wire([[{"sys_id": "ci1", "ip_address": "10.1.1.1"}]] * 2)
    with pytest.raises(ValueError, match="repeated"):
        connector.fetch(row())


def test_response_capture_ceiling_and_default_excerpt():
    response = io.BytesIO(b"x" * 1000)
    assert len(delivery._read_error_excerpt(response, deadline=10**20)) == 500
    with pytest.raises(ValueError, match="byte limit"):
        delivery._read_error_excerpt(io.BytesIO(b"x" * 11), deadline=10**20, response_limit_bytes=10)
    assert delivery._read_error_excerpt(io.BytesIO(b'{"result":[]}'), deadline=10**20,
        response_limit_bytes=20) == '{"result":[]}'


@requires_postgres
def test_api_save_preview_apply_and_operator_edit(tmp_path, monkeypatch, wire):
    client = configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    crypto.configure()
    headers = auth_headers(client, "admin")
    payload = {"base_url": "https://snow.example", "field_mapping": {"ip": "ip_address", "owner_email": "owned_by.email"}, "token": "local-test-token"}
    wire([])
    saved = client.put("/api/assets/import/connector", headers=headers, json=payload)
    assert saved.status_code == 200, saved.text
    assert "token" not in saved.text and saved.json()["credential_configured"] is True
    info = client.get("/api/assets/import/connector", headers=headers).json()
    assert info["ldap_ad"]["available"] is False and info["ldap_ad"]["dependency"] == "#317"
    pages = [[{"sys_id": "ci1", "ip_address": "10.1.1.1", "owned_by.email": "ada@example.com"}]]
    wire(pages)
    preview = client.post("/api/assets/import/connector/run", headers=headers, json={})
    assert preview.status_code == 200, preview.text
    assert preview.json()["counts"]["create"] == 1
    wire(pages)
    applied = client.post("/api/assets/import/connector/run", headers=headers, json={"dry_run": False})
    assert applied.status_code == 200, applied.text
    asset_id = applied.json()["rows"][0]["asset_id"]
    assert client.patch(f"/api/assets/{asset_id}", headers=headers, json={"owner_email": "operator@example.com"}).status_code == 200
    wire(pages)
    conflict = client.post("/api/assets/import/connector/run", headers=headers, json={"dry_run": False})
    assert conflict.json()["codes"]["operator_override"] == 1
    with get_session(make_settings(tmp_path).postgres_url) as session:
        saved_row = session.get(models.AssetImportConnector, "default")
        assert crypto.is_encrypted(saved_row.token_encrypted)
        assert session.get(models.Asset, asset_id).owner_email == "operator@example.com"


@requires_postgres
def test_scheduled_run_rechecks_disabled_after_reservation(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    configured_client(tmp_path, monkeypatch, settings=settings)
    with get_session(settings.postgres_url) as session:
        session.add(models.AssetImportConnector(tenant_id="default", base_url="https://snow.example", table="cmdb_ci", field_mapping={"ip": "ip_address"}, token_encrypted="test", enabled=False))
    monkeypatch.setattr(connector, "fetch", lambda *a, **kw: pytest.fail("disabled scheduled connector reached network"))
    assert connector.run(settings, "default", scheduled=True, dry_run=False) is None
    with get_session(settings.postgres_url) as session:
        saved = session.get(models.AssetImportConnector, "default")
        saved.enabled = True
        saved.next_run_at = connector.now() + timedelta(hours=1)
    assert connector.run(settings, "default", scheduled=True, expected_next_run=connector.now(), dry_run=False) is None


@requires_postgres
def test_origin_change_requires_fresh_credential_and_tenant_scope(tmp_path, monkeypatch, wire):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    monkeypatch.setenv("OCTO_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    crypto.configure()
    wire([])
    body = AssetConnectorRequest(base_url="https://snow.example", field_mapping={"ip": "ip_address"}, token="fresh-test-token")
    connector.save(settings, "default", body)
    changed = body.model_copy(update={"base_url": "https://other.example", "token": None})
    with pytest.raises(ValueError, match="replacement token"):
        connector.save(settings, "default", changed)
    assert connector.get(settings, "other-tenant") is None
    for role in ["viewer", "operator"]:
        response = client.get("/api/assets/import/connector", headers=auth_headers(client, role))
        assert response.status_code == 403
    with get_session(settings.postgres_url) as session:
        saved = session.get(models.AssetImportConnector, "default")
        assert saved.base_url == "https://snow.example"
        assert crypto.decrypt_secret(saved.token_encrypted, context="asset-import:default") == "fresh-test-token"
        with pytest.raises(Exception):
            crypto.decrypt_secret(saved.token_encrypted, context="asset-import:other-tenant")


@requires_postgres
def test_connector_key_rotation_and_startup_fail_closed(tmp_path, monkeypatch, wire):
    import base64
    from api.db import reencrypt_secrets
    from api.services.crypto import startup
    from api.settings import InsecureConfigurationError
    settings = make_settings(tmp_path)
    configured_client(tmp_path, monkeypatch, settings=settings)
    first = base64.b64encode(b"a" * 32).decode()
    second = base64.b64encode(b"b" * 32).decode()
    monkeypatch.setenv("OCTO_MASTER_KEY", first)
    crypto.configure()
    wire([])
    body = AssetConnectorRequest(base_url="https://snow.example", field_mapping={"ip": "ip_address"}, token="rotate-test-token")
    connector.save(settings, "default", body)
    monkeypatch.setenv("OCTO_MASTER_KEY", second)
    monkeypatch.setenv("OCTO_MASTER_KEY_PREVIOUS", first)
    crypto.configure()
    result = reencrypt_secrets.run(settings.postgres_url, rotate=True)
    assert result.failed == 0 and result.changed == 1
    monkeypatch.delenv("OCTO_MASTER_KEY_PREVIOUS")
    crypto.configure()
    with get_session(settings.postgres_url) as session:
        saved = session.get(models.AssetImportConnector, "default")
        assert crypto.decrypt_secret(saved.token_encrypted, context="asset-import:default") == "rotate-test-token"
    monkeypatch.delenv("OCTO_MASTER_KEY")
    settings.env = "prod"
    with pytest.raises(InsecureConfigurationError):
        startup.bootstrap(settings)


@requires_postgres
def test_connector_database_rls_hides_other_tenant_without_predicate(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    configured_client(tmp_path, monkeypatch, settings=settings)
    with get_session(settings.postgres_url) as session:
        session.add(models.AssetImportConnector(tenant_id="default", base_url="https://snow.example", table="cmdb_ci", field_mapping={"ip": "ip_address"}, token_encrypted="test"))
    with get_session(settings.postgres_url) as session:
        session.execute(__import__('sqlalchemy').text("SET LOCAL ROLE shapoclyack_tenant"))
        session.execute(__import__('sqlalchemy').text("SELECT set_config('shapoclyack.tenant_id', 'different-tenant', true)"))
        assert list(session.scalars(select(models.AssetImportConnector))) == []


@requires_postgres
def test_schedule_failure_is_delayed_and_error_is_credential_free(tmp_path, monkeypatch):
    import threading
    settings = make_settings(tmp_path)
    configured_client(tmp_path, monkeypatch, settings=settings)
    monkeypatch.setattr(connector, "_stop", threading.Event())
    with get_session(settings.postgres_url) as session:
        session.add(models.AssetImportConnector(tenant_id="default", base_url="https://snow.example", table="cmdb_ci", field_mapping={"ip": "ip_address"}, token_encrypted="test", enabled=True, next_run_at=connector.now() - timedelta(minutes=1)))
    calls = []
    def fail(*args, **kwargs):
        calls.append(kwargs)
        raise ValueError("upstream echoed super-secret-token")
    monkeypatch.setattr(connector, "run", fail)
    connector.tick(settings)
    state = connector.get(settings, "default")
    assert state["next_run_at"] > connector.now()
    assert "super-secret" not in state["last_error"]
    assert len(calls) == 1 and calls[0]["scheduled"] is True
    connector.tick(settings)
    assert len(calls) == 1
