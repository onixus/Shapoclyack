from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth import TenantPrincipal, get_settings
from api.routes import mcp
from api.services.local_operator import mcp as service
from tests.conftest import make_settings

HEADERS = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": service.PROTOCOL_VERSION}


def client(tmp_path, *, enabled=True, authenticate=True, origins=None, tenant="a", platform_admin=False):
    app = FastAPI()
    settings = make_settings(tmp_path)
    settings.mcp_enabled = enabled
    settings.mcp_allowed_origins = origins or []
    app.dependency_overrides[get_settings] = lambda: settings
    if authenticate:
        app.dependency_overrides[mcp.principal_dependency] = lambda: TenantPrincipal(
            username="reader", tenant_id=tenant, role="viewer", is_platform_admin=platform_admin)
    app.include_router(mcp.router, prefix="/api")
    return TestClient(app), settings


def rpc(c, method, params=None, **kwargs):
    body = {"jsonrpc": "2.0", "id": 7, "method": method}
    if params is not None:
        body["params"] = params
    return c.post("/api/mcp", json=body, headers=HEADERS, **kwargs)


def write_run(settings, run_id, tenant):
    root = settings.output_dir / "runs" / run_id
    root.mkdir(parents=True)
    (root / "tenant.json").write_text(json.dumps({"tenant_id": tenant}))
    (root / "summary.json").write_text(json.dumps({"alive_hosts": 2, "secret": "never expose", "potential_vulnerabilities": 1}))


def test_initialize_tools_and_ping(tmp_path):
    c, _ = client(tmp_path)
    response = rpc(c, "initialize", {"protocolVersion": "future", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
    assert response.json()["result"]["protocolVersion"] == service.PROTOCOL_VERSION
    assert "mcp-session-id" not in response.headers
    assert rpc(c, "ping").json()["result"] == {}
    tools = rpc(c, "tools/list").json()["result"]["tools"]
    assert {tool["name"] for tool in tools} == {"list_runs", "get_run_summary"}
    assert all(tool["inputSchema"]["additionalProperties"] is False for tool in tools)
    assert rpc(c, "scan/start").json()["error"]["code"] == -32601


def test_real_evidence_tenant_isolation_even_platform_admin(tmp_path):
    c, settings = client(tmp_path, platform_admin=True)
    write_run(settings, "own", "a")
    write_run(settings, "foreign", "b")
    result = rpc(c, "tools/call", {"name": "list_runs", "arguments": {}}).json()["result"]
    rows = json.loads(result["content"][0]["text"])
    assert [row["run_id"] for row in rows["items"]] == ["own"]
    assert "path" not in rows["items"][0]
    own = rpc(c, "tools/call", {"name": "get_run_summary", "arguments": {"run_id": "own"}}).json()["result"]
    assert "never expose" not in json.dumps(own)
    assert json.loads(own["content"][0]["text"])["counts"]["alive_hosts"] == 2
    for run_id in ("foreign", "missing"):
        missing = rpc(c, "tools/call", {"name": "get_run_summary", "arguments": {"run_id": run_id}}).json()["result"]
        assert missing["isError"] is True
        assert json.loads(missing["content"][0]["text"]) == {"error": "Run not found"}


@pytest.mark.parametrize("arguments", [{"tenant_id": "b"}, {"limit": True}, {"limit": 51}, {"limit": "2"}, {"offset": -1}, {"role": "admin"}])
def test_tool_arguments_reject_authority_and_invalid_values(tmp_path, arguments):
    c, _ = client(tmp_path)
    assert rpc(c, "tools/call", {"name": "list_runs", "arguments": arguments}).json()["error"]["code"] == -32602


def test_readonly_allowlist_and_traversal(tmp_path):
    c, _ = client(tmp_path)
    for name, arguments in [("start_scan", {}), ("get_run_summary", {"run_id": "../foreign"})]:
        assert rpc(c, "tools/call", {"name": name, "arguments": arguments}).json()["error"]["code"] == -32602


def test_disabled_precedes_auth_and_all_supported_methods(tmp_path):
    c, _ = client(tmp_path, enabled=False, authenticate=False)
    for method in ("get", "post", "delete"):
        assert getattr(c, method)("/api/mcp").status_code == 404


def test_auth_required_on_each_transport_method(tmp_path):
    c, _ = client(tmp_path, authenticate=False)
    for method in ("get", "post", "delete"):
        assert getattr(c, method)("/api/mcp").status_code == 401


def test_origins_version_session_and_stream(tmp_path):
    c, _ = client(tmp_path, origins=["https://console.example"])
    for origin in ("https://evil.example", "null", "https://console.example/", "http://["):
        assert c.get("/api/mcp", headers={"origin": origin}).status_code == 403
    assert c.get("/api/mcp", headers={"origin": "https://console.example"}).status_code == 405
    assert c.delete("/api/mcp").status_code == 405
    for headers in ({"mcp-session-id": "unexpected"}, {"mcp-protocol-version": "wrong"}):
        assert c.get("/api/mcp", headers=headers).status_code == 400
    assert c.post("/api/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"accept": HEADERS["Accept"]}).status_code == 400


@pytest.mark.parametrize("body, code", [(b"{", -32700), (b'{}', -32600), (b'[]', -32600), (b'{"jsonrpc":"2.0","jsonrpc":"2.0"}', -32700), (b'{"jsonrpc":"2.0","id":null,"method":"ping"}', -32600), (b'{"jsonrpc":"2.0","id":true,"method":"ping"}', -32600)])
def test_malformed_json_rpc(tmp_path, body, code):
    c, _ = client(tmp_path)
    response = c.post("/api/mcp", content=body, headers={**HEADERS, "Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == code


def test_notifications_never_execute_tools(tmp_path, monkeypatch):
    c, _ = client(tmp_path)
    monkeypatch.setattr(service, "call_tool", lambda *a: pytest.fail("notification executed a tool"))
    response = c.post("/api/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=HEADERS)
    assert response.status_code == 202 and response.content == b""
    response = c.post("/api/mcp", json={"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "list_runs"}}, headers=HEADERS)
    assert response.status_code == 400 and response.content == b""


def test_transport_limits_and_safe_errors(tmp_path, monkeypatch):
    c, _ = client(tmp_path)
    assert c.post("/api/mcp", json={}, headers={"Accept": "application/json"}).status_code == 406
    assert c.post("/api/mcp", content="x", headers=HEADERS).status_code == 415
    assert c.post("/api/mcp", content="x" * (mcp.MAX_REQUEST_BYTES + 1), headers={**HEADERS, "Content-Type": "application/json"}).status_code == 413
    monkeypatch.setattr(service.runs, "list_runs", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("secret-db-url")))
    response = rpc(c, "tools/call", {"name": "list_runs"})
    assert response.json()["error"]["code"] == -32603
    assert "secret-db-url" not in response.text
    assert service.result({"large": "x" * service.MAX_RESULT_BYTES})["isError"] is True


def test_role_gate_is_applied_after_authentication(tmp_path, monkeypatch):
    from api import auth
    c, _ = client(tmp_path, authenticate=False)
    c.app.dependency_overrides[auth.get_current_user] = lambda: auth.TokenUser(username="no-reader", role=auth.Role.viewer)
    monkeypatch.setattr(auth, "resolve_tenant_principal", lambda *a: TenantPrincipal(username="no-reader", tenant_id="a", role="custom-no-access", rank=0))
    assert rpc(c, "tools/list").status_code == 403


from tests.conftest import requires_postgres  # noqa: E402


@requires_postgres
def test_live_membership_revocation_and_suspension(tmp_path, monkeypatch):
    from tests.conftest import auth_headers, configured_client
    settings = make_settings(tmp_path, mcp_enabled=True)
    c = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(c, "admin")
    for tenant in ("mcp-a", "mcp-b"):
        response = c.post("/api/tenants", headers=admin, json={"name": tenant, "tenant_id": tenant})
        assert response.status_code == 201, response.text
    response = c.put("/api/tenants/mcp-a/members/viewer", headers=admin, json={"role": "viewer"})
    assert response.status_code == 200, response.text
    viewer = {**HEADERS, **auth_headers(c, "viewer")}
    message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    def read(tenant):
        return c.post("/api/mcp", params={"tenant_id": tenant}, json=message, headers=viewer)
    assert read("mcp-a").status_code == 200
    assert read("mcp-b").status_code == 403
    assert c.delete("/api/tenants/mcp-a/members/viewer", headers=admin).status_code == 204
    assert read("mcp-a").status_code == 403
    assert c.put("/api/tenants/mcp-a/members/viewer", headers=admin, json={"role": "viewer"}).status_code == 200
    response = c.post("/api/tenants/mcp-a/suspend", headers=admin, json={"reason": "MCP authorization regression"})
    assert response.status_code == 200, response.text
    # Suspension revokes existing sessions; this bearer token is now invalid.
    assert read("mcp-a").status_code == 401


def test_json_rpc_transport_is_excluded_from_rest_openapi(tmp_path):
    c, _ = client(tmp_path)
    assert "/api/mcp" not in c.app.openapi()["paths"]
