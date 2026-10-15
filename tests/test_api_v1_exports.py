from datetime import UTC, datetime
import csv
import io
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from api.db import models
from api.db.engine import get_session
from api.services import api_exports
from api.versioning import ApiVersionMiddleware
from tests.conftest import configured_client, login, make_settings


@pytest.fixture
def setup(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path,
        postgres_url=f"sqlite:///{tmp_path / 'test.db'}",
        cors_origins=["https://console.example"],
        api_deprecated_at="2026-10-15T00:00:00Z",
        api_sunset_at="2027-10-15T00:00:00Z",
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Tenant(
                tenant_id="other", name="Other", status="active", created_at=now
            )
        )
        for tenant, key in [
            ("default", "a"),
            ("default", "b"),
            ("default", "c"),
            ("other", "z"),
        ]:
            session.add(
                models.Asset(
                    asset_id=key,
                    tenant_id=tenant,
                    first_seen=now,
                    last_seen=now,
                    owner_email=" =HYPERLINK(1)",
                )
            )
            session.add(
                models.Vulnerability(
                    vuln_id=key,
                    tenant_id=tenant,
                    asset_id=key,
                    finding_key=key,
                    title="=1+1",
                    first_seen_at=now,
                    last_seen_at=now,
                    state_changed_at=now,
                    sla_started_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
    headers = {"Authorization": "Bearer " + login(client)}
    return settings, client, headers


@pytest.mark.parametrize(
    "resource,key", [("assets", "asset_id"), ("vulnerabilities", "vuln_id")]
)
def test_pages_and_tenant_cursor_scope(setup, resource, key):
    settings, client, headers = setup
    response = client.get(f"/api/v1/{resource}/export?limit=2", headers=headers)
    assert response.status_code == 200, response.text
    assert [json.loads(row)[key] for row in response.text.splitlines()] == ["a", "b"]
    cursor = response.headers["X-Next-Cursor"]
    other = "vulnerabilities" if resource == "assets" else "assets"
    assert (
        client.get(
            f"/api/v1/{other}/export", params={"cursor": cursor}, headers=headers
        ).status_code
        == 422
    )
    with pytest.raises(ValueError):
        api_exports.export_page(
            settings, tenant_id="other", resource=resource, cursor=cursor, limit=2
        )
    assert (
        client.get(
            f"/api/v1/{resource}/export",
            params={"cursor": cursor + "x"},
            headers=headers,
        ).status_code
        == 422
    )
    response = client.get(
        f"/api/v1/{resource}/export",
        params={"cursor": cursor, "limit": 2},
        headers=headers,
    )
    assert [json.loads(row)[key] for row in response.text.splitlines()] == ["c"]
    assert "X-Next-Cursor" not in response.headers
    assert (
        client.get(f"/api/v1/{resource}/export?limit=1001", headers=headers).status_code
        == 422
    )
    assert client.get(f"/api/v1/{resource}/export").status_code == 401


def test_csv_safe_and_headers_available_to_browser(setup):
    _, client, headers = setup
    response = client.get(
        "/api/v1/assets/export?limit=1&format=csv",
        headers={**headers, "Origin": "https://console.example"},
    )
    assert response.status_code == 200
    assert (
        list(csv.DictReader(io.StringIO(response.text)))[0]["owner_email"]
        == "' =HYPERLINK(1)"
    )
    exposed = response.headers["access-control-expose-headers"].lower()
    for header in ("x-next-cursor", "api-version", "deprecation", "sunset", "link"):
        assert header in exposed
    assert response.headers["api-version"] == "1"
    assert "deprecation" not in response.headers
    legacy = client.get("/api/assets/export?limit=1", headers=headers)
    assert legacy.headers["deprecation"].startswith("@")
    assert legacy.headers["sunset"] == "Fri, 15 Oct 2027 00:00:00 GMT"


def test_all_schema_aliases_and_permission_parity(setup):
    _, client, headers = setup
    paths = client.app.openapi()["paths"]
    for path in paths:
        if path.startswith("/api/") and not path.startswith("/api/v1/"):
            assert "/api/v1/" + path[len("/api/") :] in paths
    for prefix in ("/api", "/api/v1"):
        assert client.get(prefix + "/assets", headers=headers).status_code == 200
        assert (
            client.patch(
                prefix + "/assets/a", headers=headers, json={"owner_email": "x"}
            ).status_code
            == 403
        )
        assert client.get(prefix + "/users", headers=headers).status_code == 403


def test_nested_prefix_never_reaches_security_guards():
    app = FastAPI()
    app.add_middleware(ApiVersionMiddleware)

    @app.get("/api/v1/users")
    def trap():
        pytest.fail("Nested alias reached forbidden resource")

    client = TestClient(app)
    assert (
        client.get(
            "/api/v1/v1/users", headers={"Authorization": "Bearer wildcard-token"}
        ).status_code
        == 404
    )


def test_alias_normalizes_before_every_inner_middleware():
    app = FastAPI()

    @app.middleware("http")
    async def guard(request: Request, call_next):
        assert request.url.path == "/api/assets"
        assert request.scope["raw_path"] == b"/api/assets"
        return await call_next(request)

    @app.get("/api/assets")
    def endpoint():
        return {}

    app.add_middleware(ApiVersionMiddleware)
    assert TestClient(app).get("/api/v1/assets").status_code == 200


def test_cursor_from_one_tenant_rejected_for_another_principal(setup):
    settings, client, headers = setup
    from api.services import service_tokens

    page = client.get("/api/v1/assets/export?limit=1", headers=headers)
    cursor = page.headers["X-Next-Cursor"]
    issued = service_tokens.create_token(
        settings,
        tenant_id="other",
        name="other-reader",
        scopes=["assets:read"],
        role="viewer",
        issuer_role="admin",
        issuer_is_platform_admin=True,
    )
    other = {"Authorization": "Bearer " + issued["token"]}
    own = client.get("/api/v1/assets/export", headers=other)
    assert own.status_code == 200, own.text
    assert [json.loads(row)["asset_id"] for row in own.text.splitlines()] == ["z"]
    stolen = client.get("/api/v1/assets/export", params={"cursor": cursor}, headers=other)
    assert stolen.status_code == 422


def test_trailing_slash_redirect_keeps_version_prefix(setup):
    _, client, headers = setup
    for prefix, expected in (("/api/v1", "/api/v1/assets/export"), ("/api", "/api/assets/export")):
        response = client.get(
            prefix + "/assets/export/", headers=headers, follow_redirects=False
        )
        assert response.status_code == 307
        assert urlsplit(response.headers["location"]).path == expected
        assert client.get(response.headers["location"], headers=headers).status_code == 200


def test_versioned_location_leaves_other_hosts_alone():
    from api.versioning import versioned_location

    assert versioned_location("/api/assets") == "/api/v1/assets"
    assert versioned_location("http://api.test/api/assets", "api.test") == "http://api.test/api/v1/assets"
    assert versioned_location("https://other.example/api/x", "api.test") == "https://other.example/api/x"


def test_schedule_dates_are_trimmed_and_errors_name_the_variable():
    middleware = ApiVersionMiddleware(
        None, deprecated_at=" 2026-01-01T00:00:00Z\n", sunset_at=" 2027-01-01T00:00:00Z "
    )
    assert middleware.headers["Sunset"].endswith("GMT")
    with pytest.raises(ValueError, match="OCTO_API_DEPRECATED_AT.*ISO 8601"):
        ApiVersionMiddleware(None, deprecated_at="next friday", sunset_at="2027-01-01T00:00:00Z")
    with pytest.raises(ValueError, match="OCTO_API_SUNSET_AT.*timezone"):
        ApiVersionMiddleware(None, deprecated_at="2026-01-01T00:00:00Z", sunset_at="2027-01-01")
    with pytest.raises(ValueError, match="OCTO_API_SUNSET_AT.*OCTO_API_DEPRECATED_AT"):
        ApiVersionMiddleware(None, deprecated_at="2026-01-01T00:00:00Z", sunset_at="2026-06-01T00:00:00Z")


def test_schedule_requires_twelve_months_and_timezone():
    with pytest.raises(ValueError):
        ApiVersionMiddleware(
            None, deprecated_at="2026-01-01T00:00:00Z", sunset_at="2026-12-31T00:00:00Z"
        )
    with pytest.raises(ValueError):
        ApiVersionMiddleware(
            None, deprecated_at="2026-01-01T00:00:00", sunset_at="2027-01-01T00:00:00"
        )
    with pytest.raises(ValueError):
        ApiVersionMiddleware(None, deprecated_at="2026-01-01T00:00:00Z")


def test_expired_cursor_and_spreadsheet_whitespace():
    cursor = api_exports._encode(
        {"v": 1, "tenant": "default", "resource": "assets", "after": "a", "expires": 0},
        "secret",
    )
    with pytest.raises(ValueError):
        api_exports._decode(
            cursor, tenant_id="default", resource="assets", secret="secret"
        )
    for value in ["=1", "+1", "-1", "@SUM(1)", "  =1", "\ttext", "\rtext", "\ntext"]:
        text = "".join(api_exports.stream_rows("assets", [{"asset_id": value}], "csv"))
        assert next(csv.DictReader(io.StringIO(text)))["asset_id"] == "'" + value


def test_sdk_generated_methods_and_redirect_protection(setup, monkeypatch):
    client_app_paths = setup[1].app.openapi()["paths"]
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "sdk"))
    from shapoclyack import Client
    from shapoclyack.client import _NoRedirect
    from shapoclyack.operations import OPERATIONS

    schema_paths = {
        path
        for path in client_app_paths
        if path.startswith("/api/v1/")
    }
    assert {spec["path"] for spec in OPERATIONS.values()} == schema_paths
    for name in OPERATIONS:
        assert callable(getattr(Client, name))
    sdk_client = Client("https://api.example", "secret", tenant_id="a")
    operation = next(
        name
        for name, spec in OPERATIONS.items()
        if spec["path"] == "/api/v1/assets/export"
    )
    with pytest.raises(ValueError):
        sdk_client.request(operation, query={"tenant_id": "b"})
    assert (
        _NoRedirect().redirect_request(
            None, None, None, None, None, "https://elsewhere"
        )
        is None
    )


def test_service_scope_and_nested_alias_guards(setup):
    settings, client, _ = setup
    from api.services import service_tokens

    issued = service_tokens.create_token(
        settings,
        tenant_id="default",
        name="integration",
        scopes=["*"],
        role="admin",
        issuer_role="admin",
        issuer_is_platform_admin=True,
    )
    headers = {"Authorization": "Bearer " + issued["token"]}
    assert client.get("/api/v1/assets/export", headers=headers).status_code == 200
    for path in ["users", "auth/me", "tenants"]:
        assert client.get("/api/v1/" + path, headers=headers).status_code == 403
        assert client.get("/api/v1/v1/" + path, headers=headers).status_code == 404
    # PUT /config exists; a "*" token is refused by the write scope itself.
    response = client.put("/api/v1/config", json={}, headers=headers)
    assert response.status_code == 403
    assert "not scoped for 'config:write'" in response.json()["detail"]
    issued = service_tokens.create_token(
        settings,
        tenant_id="default",
        name="assets-only",
        scopes=["assets:read"],
        role="viewer",
        issuer_role="admin",
    )
    headers = {"Authorization": "Bearer " + issued["token"]}
    assert client.get("/api/v1/assets/export", headers=headers).status_code == 200
    assert (
        client.get("/api/v1/vulnerabilities/export", headers=headers).status_code == 403
    )


def test_generator_deterministic_and_rejects_empty_or_duplicate_ids(setup):
    import importlib.util

    script = Path(__file__).resolve().parents[1] / "scripts/generate-api-client.py"
    spec = importlib.util.spec_from_file_location("generate_api_client", script)
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    settings, client, _ = setup
    # The checked-in manifest covers every optional router (docs/api-versioning.md).
    for flag in (
        "reports_enabled",
        "webhooks_enabled",
        "notification_channels_enabled",
        "endpoint_inventory_enabled",
        "service_tokens_enabled",
    ):
        assert getattr(settings, flag) is True
    output = script.parents[1] / "sdk/shapoclyack/operations.py"
    assert generator.generate(client.app.openapi()) == output.read_text()
    operation = {"operationId": "read_asset", "parameters": []}
    schema = {
        "paths": {
            "/api/v1/assets": {"get": operation},
            "/api/assets": {"get": operation},
        }
    }
    assert generator.generate(schema) == generator.generate(
        json.loads(json.dumps(schema))
    )
    with pytest.raises(ValueError):
        generator.generate({"paths": {}})
    schema["paths"]["/api/v1/other"] = {"get": operation}
    with pytest.raises(ValueError):
        generator.generate(schema)


def test_disabled_features_not_enabled_by_alias(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path,
        postgres_url=f"sqlite:///{tmp_path / 'disabled.db'}",
        reports_enabled=False,
        webhooks_enabled=False,
        notification_channels_enabled=False,
        endpoint_inventory_enabled=False,
        service_tokens_enabled=False,
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    paths = client.app.openapi()["paths"]
    for prefix in ("/api", "/api/v1"):
        for suffix in (
            "/reports",
            "/webhooks",
            "/notification-channels",
            "/endpoint/inventory",
            "/tenants/{tenant_id}/service-tokens",
        ):
            assert prefix + suffix not in paths
    assert client.get("/api/v1/reports").status_code == 404


def test_sdk_builds_encoded_requests_and_preserves_stream_ownership(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "sdk"))
    from shapoclyack import Client
    from shapoclyack.operations import OPERATIONS

    client = Client("https://api.example", "test-token")

    class Response(io.BytesIO):
        def __init__(self, content, content_type):
            super().__init__(content)
            self.headers = {"Content-Type": content_type}

    responses = []
    requests = []
    served = [(b'{"ok":true}', "application/json")]

    def open_request(request, timeout):
        requests.append(request)
        response = Response(*served[-1])
        responses.append(response)
        return response

    monkeypatch.setattr(client._opener, "open", open_request)
    read = next(
        name
        for name, spec in OPERATIONS.items()
        if spec["path"] == "/api/v1/assets/export"
    )
    with client.request(read, raw=True) as response:
        assert not response.closed
        assert response.read() == b'{"ok":true}'
    assert responses[-1].closed
    assert requests[-1].headers["Authorization"] == "Bearer test-token"
    assert client.request(read) == {"ok": True}
    assert responses[-1].closed
    # A multi-line NDJSON export page is not one JSON document: without
    # raw=True the transport hands back the bytes instead of failing to parse.
    ndjson = b'{"asset_id":"a"}\n{"asset_id":"b"}\n'
    served.append((ndjson, "application/x-ndjson"))
    assert client.request(read, query={"format": "ndjson"}) == ndjson
    assert responses[-1].closed
    served.append((b"asset_id\r\na\r\n", "text/csv; charset=utf-8"))
    assert client.request(read, query={"format": "csv"}) == b"asset_id\r\na\r\n"
    served.append((b'{"ok":true}', "application/json"))
    upload = next(
        name
        for name, spec in OPERATIONS.items()
        if "multipart/form-data" in (spec.get("requestBody") or {}).get("content", {})
    )
    path = {
        parameter["name"]: "example"
        for parameter in OPERATIONS[upload]["parameters"]
        if parameter.get("in") == "path"
    }
    with pytest.raises(ValueError):
        client.request(upload, path=path, body={})
    client.request(
        upload,
        path=path,
        data=b"encoded-body",
        content_type="multipart/form-data; boundary=example",
    )
    assert requests[-1].data == b"encoded-body"
    assert (
        requests[-1].headers["Content-type"] == "multipart/form-data; boundary=example"
    )


def test_existing_v1_provisioning_exchange_stays_reachable(setup):
    _, client, _ = setup
    assert "/api/v1/v1/auth/exchange" not in client.app.openapi()["paths"]
    for path in ("/api/auth/exchange", "/api/v1/auth/exchange"):
        response = client.post(path, json={"provisioning_key": "invalid-key"})
        assert response.status_code == 401, response.text
