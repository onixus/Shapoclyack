"""Admin-edited operator endpoint: overlay rules, API, connection test, discovery, readiness."""

from __future__ import annotations

import asyncio
import dataclasses
import json

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.auth import get_settings
from api.routes import operator_settings
from api.routes._audit import audit_context
from api.services.local_operator import connection, overrides, runtime
from api.services.local_operator.config import OperatorConfig, OperatorConfigurationError
from api.services.local_operator.providers import InferenceProvider, OperatorProviderError
from api.settings import Settings


@pytest.fixture(autouse=True)
def master_key():
    """A stored credential needs a master key; the refusal test removes it."""
    from api.services.crypto import envelope
    envelope.configure(envelope.LocalKeyProvider(b"m" * 32))
    yield
    envelope.reset_for_tests()


@pytest.fixture
def settings(tmp_path):
    runtime.reset_cache()
    return Settings(env="dev", postgres_url=f"sqlite:///{tmp_path}/operator.db", operator_enabled=True)


def _models(*ids, status=200):
    def handler(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(status, json={"data": [{"id": value, "context_length": 32768} for value in ids]})
        return httpx.Response(200, json={"choices": [{"message": {"content": "OK"}, "finish_reason": "stop"}]})
    return httpx.MockTransport(handler)


async def _public(host, port):
    return ["93.184.216.34"]


# --- overlay rules ---------------------------------------------------------

def test_no_override_is_the_deployment(settings):
    assert overrides.effective_settings(settings) is settings


def test_no_database_means_no_override_and_no_writes():
    plain = Settings(operator_enabled=True)
    assert overrides.effective_settings(plain) is plain
    with pytest.raises(overrides.OperatorSettingsError, match="storage_unavailable"):
        overrides.update(plain, {"model": "m"})


def test_local_edit_applies_and_needs_private_ip_literal(settings):
    overrides.update(settings, {"base_url": "http://192.168.1.20:11434/v1", "model": "qwen3:8b"})
    effective = overrides.effective_settings(settings)
    assert (effective.operator_base_url, effective.operator_model) == ("http://192.168.1.20:11434/v1", "qwen3:8b")
    for url in ("http://ollama.lan:11434/v1", "http://8.8.8.8/v1", "http://169.254.169.254/v1"):
        with pytest.raises(overrides.OperatorSettingsError, match="private_ip_literal"):
            overrides.update(settings, {"base_url": url})


def test_deployment_key_never_follows_an_edited_endpoint(settings):
    settings.operator_api_key = "deployment-key"
    overrides.update(settings, {"model": "other"})
    assert overrides.effective_settings(settings).operator_api_key == "deployment-key"
    overrides.update(settings, {"base_url": "http://10.0.0.9:8080/v1"})
    assert overrides.effective_settings(settings).operator_api_key == ""


def test_hosted_needs_deployment_egress_permission(settings):
    with pytest.raises(overrides.OperatorSettingsError, match="not_permitted_by_deployment"):
        overrides.update(settings, {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                                    "api_key": "k", "allow_external": True})


@pytest.mark.parametrize("changes,code", [
    ({"provider": "openai_compatible", "base_url": "https://llm.example.com/v1", "api_key": "k"}, "opt_in_and_key"),
    ({"provider": "openai_compatible", "base_url": "https://llm.example.com/v1", "allow_external": True}, "opt_in_and_key"),
    ({"provider": "openai_compatible", "base_url": "http://llm.example.com/v1", "api_key": "k", "allow_external": True}, "requires_https"),
    ({"provider": "openai_compatible", "base_url": "https://10.1.2.3/v1", "api_key": "k", "allow_external": True}, "public_host"),
    ({"provider": "openai_compatible", "base_url": "https://llm.internal/v1", "api_key": "k", "allow_external": True}, "public_host"),
    ({"provider": "openai_compatible", "api_key": "k", "allow_external": True}, "invalid_operator_base_url"),
    ({"provider": "openrouter", "base_url": "https://evil.example/v1", "api_key": "k", "allow_external": True}, "openrouter"),
    ({"bogus": 1}, "not_an_editable"),
])
def test_hosted_edits_keep_every_constraint(settings, changes, code):
    settings.operator_allow_external = True
    with pytest.raises(overrides.OperatorSettingsError, match=code):
        overrides.update(settings, changes)
    assert overrides.load(settings)[0] == {}


def test_hosted_edit_with_consent_key_and_public_https(settings):
    settings.operator_allow_external = True
    overrides.update(settings, {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                                "model": "gpt-x", "api_key": "sk-secret", "allow_external": True})
    config = OperatorConfig.from_settings(overrides.effective_settings(settings))
    assert (config.provider, config.api_key, config.allow_external) == ("openai_compatible", "sk-secret", True)
    # Revoking the deployment's permission disables the stored hosted endpoint, not just hides it.
    settings.operator_allow_external = False
    with pytest.raises(OperatorConfigurationError, match="opt_in_and_key"):
        OperatorConfig.from_settings(overrides.effective_settings(settings))


def test_stored_key_is_dropped_when_endpoint_moves_without_it(settings):
    settings.operator_allow_external = True
    base = {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1", "api_key": "sk-1", "allow_external": True}
    overrides.update(settings, base)
    overrides.update(settings, {**base, "api_key": None, "model": "m2"})
    assert overrides.effective_settings(settings).operator_api_key == "sk-1"
    with pytest.raises(overrides.OperatorSettingsError, match="opt_in_and_key"):
        overrides.update(settings, {**base, "api_key": None, "base_url": "https://attacker.example.net/v1"})
    assert overrides.effective_settings(settings).operator_api_key == "sk-1"


def test_snapshot_never_returns_credentials(settings):
    settings.operator_allow_external = True
    settings.operator_api_key = "deployment-secret"
    overrides.update(settings, {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                                "api_key": "override-secret", "allow_external": True})
    snap = overrides.snapshot(settings)
    text = json.dumps(snap)
    assert "override-secret" not in text and "deployment-secret" not in text
    assert snap["effective"]["api_key_source"] == "override" and snap["override"]["api_key_set"] is True
    assert snap["valid"] and snap["external_permitted"]


def test_unreadable_store_fails_closed(settings, monkeypatch):
    def broken(_url):
        raise RuntimeError("db down")
    monkeypatch.setattr(overrides, "get_session", broken)
    with pytest.raises(OperatorConfigurationError, match="operator_settings_unavailable"):
        overrides.effective_settings(settings)


def test_stored_key_is_sealed_when_encryption_is_configured(settings):
    from api.services.crypto import envelope
    envelope.configure(envelope.LocalKeyProvider(b"k" * 32))
    try:
        settings.operator_allow_external = True
        overrides.update(settings, {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                                    "api_key": "sk-plain", "allow_external": True})
        stored = overrides.load(settings)[0]["api_key"]
        assert stored != "sk-plain" and envelope.is_encrypted(stored)
        assert overrides.effective_settings(settings).operator_api_key == "sk-plain"
    finally:
        envelope.reset_for_tests()


# --- discovery, connection test, readiness ----------------------------------

def _hosted():
    return OperatorConfig(provider="openai_compatible", base_url="https://llm.example.com/v1", model="gpt-x",
                          api_key="k", allow_external=True)


def test_discovery_returns_sanitized_ids_and_sends_key():
    seen = {}
    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"data": [{"id": "gpt-x", "context_length": 128000}, {"id": "bad\x00id"},
                                                  {"id": 7}, "junk", {"id": "llama", "meta": {"n_ctx": 8192}}]})
    models = asyncio.run(InferenceProvider(_hosted(), transport=httpx.MockTransport(handler), resolver=_public).list_models())
    assert [(m.id, m.context_tokens) for m in models] == [("gpt-x", 128000), ("llama", 8192)]
    assert seen["auth"] == "Bearer k"


@pytest.mark.parametrize("status,code", [(401, "unauthorized"), (403, "unauthorized"), (404, "models_unsupported"), (500, "upstream_rejected")])
def test_discovery_status_codes_are_stable(status, code):
    with pytest.raises(OperatorProviderError, match=code):
        asyncio.run(InferenceProvider(_hosted(), transport=_models(status=status), resolver=_public).list_models())


def test_discovery_refuses_hosted_name_resolving_privately():
    async def private(host, port):
        return ["10.0.0.1"]
    transport = httpx.MockTransport(lambda _: pytest.fail("reached transport"))
    result = asyncio.run(connection.check(_hosted(), transport=transport, resolver=private))
    assert result["error"] == "operator_endpoint_not_public" and not result["reachable"] and not result["ok"]


def test_connection_test_reports_model_presence_and_completion():
    ok = asyncio.run(connection.check(_hosted(), transport=_models("gpt-x"), resolver=_public, completion=True))
    assert ok["ok"] and ok["model_listed"] and ok["completion"] == "ok" and ok["authenticated"]
    missing = asyncio.run(connection.check(_hosted(), transport=_models("other"), resolver=_public))
    assert not missing["ok"] and missing["error"] == "operator_model_not_listed" and missing["models"][0]["id"] == "other"
    denied = asyncio.run(connection.check(_hosted(), transport=_models(status=401), resolver=_public, completion=True))
    assert denied["authenticated"] is False and denied["completion"] == "not_checked"


def test_server_without_models_route_is_ready_only_after_a_completion():
    local = OperatorConfig(base_url="http://10.0.0.5:8000/v1", model="m")
    assert not asyncio.run(connection.check(local, transport=_models(status=404)))["ok"]
    assert asyncio.run(connection.check(local, transport=_models(status=404), completion=True))["ok"]


def test_endpoint_readiness_for_arbitrary_local_server():
    settings = Settings(operator_enabled=True, operator_base_url="http://10.0.0.5:8000/v1", operator_model="m")
    assert runtime.endpoint_probe(settings, transport=_models("m"))["endpoint_status"] == "ready"
    assert runtime.endpoint_probe(settings, transport=_models("x")) == {
        "endpoint_status": "unavailable", "endpoint_error": "operator_model_not_listed"}
    broken = dataclasses.replace(settings, operator_provider="openrouter", operator_base_url="")
    assert runtime.endpoint_probe(broken)["endpoint_error"] == "operator_configuration_invalid"


# --- API -------------------------------------------------------------------

def _client(settings, *, admin=True):
    app = FastAPI()
    app.include_router(operator_settings.router, prefix="/api")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[audit_context] = lambda: None
    if admin:
        checker = operator_settings.PlatformAdmin.__metadata__[0].dependency
        app.dependency_overrides[checker] = lambda: type("U", (), {"username": "root"})()
    return TestClient(app)


def test_api_requires_platform_admin(settings):
    with _client(settings, admin=False) as client:
        for method, path in (("get", ""), ("put", ""), ("delete", ""), ("post", "/test"), ("get", "/models")):
            kwargs = {"json": {}} if method in {"put", "post"} else {}
            assert getattr(client, method)(f"/api/operator/settings{path}", **kwargs).status_code in (401, 403)


def test_api_edit_reset_and_errors(settings):
    with _client(settings) as client:
        body = client.get("/api/operator/settings").json()
        assert body["override"] is None and body["effective"]["provider"] == "local"
        put = client.put("/api/operator/settings", json={"base_url": "http://10.0.0.7:8080/v1", "model": "m"})
        assert put.status_code == 200 and put.json()["effective"]["base_url"] == "http://10.0.0.7:8080/v1"
        bad = client.put("/api/operator/settings", json={"base_url": "http://example.com/v1"})
        assert bad.status_code == 422 and bad.json()["detail"] == "local_operator_requires_private_ip_literal"
        assert client.put("/api/operator/settings", json={"provider": "gemini"}).status_code == 422
        assert client.put("/api/operator/settings", json={"timeout_seconds": 500}).status_code == 422
        assert client.delete("/api/operator/settings").status_code == 204
        assert client.get("/api/operator/settings").json()["override"] is None


def test_api_put_never_echoes_key_and_test_uses_candidate(settings, monkeypatch):
    settings.operator_allow_external = True
    captured = {}
    async def fake_check(config, *, completion=False, **_):
        captured["config"], captured["completion"] = config, completion
        return {"ok": True}
    monkeypatch.setattr(connection, "check", fake_check)
    from api.services import audit as audit_service
    monkeypatch.setattr(audit_service, "_require_settings", lambda: settings)
    candidate = {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                 "api_key": "sk-never", "allow_external": True, "model": "gpt-x"}
    with _client(settings) as client:
        tested = client.post("/api/operator/settings/test", json={**candidate, "completion": True})
        assert tested.status_code == 200 and captured["config"].base_url == "https://llm.example.com/v1"
        assert captured["completion"] is True and overrides.load(settings)[0] == {}
        put = client.put("/api/operator/settings", json=candidate)
        assert put.status_code == 200 and "sk-never" not in put.text
        refused = client.post("/api/operator/settings/test", json={**candidate, "base_url": "https://127.0.0.1/v1"})
        assert refused.status_code == 422 and refused.json()["detail"] == "hosted_operator_requires_public_host"


def test_api_model_discovery_maps_upstream_failure(settings, monkeypatch):
    async def denied(self):
        raise OperatorProviderError("operator_upstream_unauthorized")
    monkeypatch.setattr(InferenceProvider, "list_models", denied)
    with _client(settings) as client:
        response = client.get("/api/operator/settings/models")
    assert response.status_code == 502 and response.json()["detail"] == "operator_upstream_unauthorized"


def test_status_uses_override_and_live_endpoint_readiness(settings, monkeypatch):
    from types import SimpleNamespace

    from api.routes.local_operator import operator_principal, router as status_router

    settings.operator_worker_enabled = True
    overrides.update(settings, {"base_url": "http://10.0.0.7:8080/v1", "model": "edited"})
    seen = []
    def probe(effective, **_):
        seen.append((effective.operator_base_url, effective.operator_model))
        return {"endpoint_status": "ready", "endpoint_error": None}
    monkeypatch.setattr(runtime, "endpoint_probe", probe)
    app = FastAPI()
    app.include_router(status_router, prefix="/api")
    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[operator_principal] = lambda: SimpleNamespace(tenant_id="t")
    with TestClient(app) as client:
        body = client.get("/api/operator/status").json()
    assert seen == [("http://10.0.0.7:8080/v1", "edited")]
    assert body["model"] == "edited" and body["endpoint_status"] == "ready" and body["analysis_available"] is True
    assert body["runtime_status"] == "not_checked" and "base_url" not in body


def test_url_path_case_change_does_not_reuse_deployment_key(settings):
    settings.operator_api_key = "deployment-key"
    settings.operator_base_url = "http://10.0.0.9/TEAM/v1"
    overrides.update(settings, {"base_url": "http://10.0.0.9/team/v1"})
    assert overrides.effective_settings(settings).operator_api_key == ""


def test_null_provider_inherits_deployment(settings):
    overrides.update(settings, {"provider": None, "model": "edited"})
    assert overrides.effective_settings(settings).operator_provider == "local"


def test_completion_auth_failure_is_not_authenticated():
    def handler(request):
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "gpt-x"}]})
        return httpx.Response(401, json={"error": "secret upstream body"})
    result = asyncio.run(connection.check(_hosted(), transport=httpx.MockTransport(handler), resolver=_public, completion=True))
    assert not result["ok"] and result["authenticated"] is False
    assert result["error"] == "operator_upstream_unauthorized"
    assert "secret upstream" not in json.dumps(result)


@pytest.mark.parametrize("response,code", [
    (httpx.Response(302, headers={"Location": "http://127.0.0.1/secrets"}), "operator_upstream_rejected"),
    (httpx.Response(200, content=b"x" * (1048576 + 1)), "operator_response_too_large"),
    (httpx.Response(200, json={"data": {}}), "operator_invalid_response"),
    (httpx.Response(200, content=b"not-json"), "operator_invalid_response"),
])
def test_discovery_bounds_and_redirects(response, code):
    seen = []
    def handler(request):
        seen.append(request)
        return response
    with pytest.raises(OperatorProviderError, match=code):
        asyncio.run(InferenceProvider(_hosted(), transport=httpx.MockTransport(handler), resolver=_public).list_models())
    assert len(seen) == 1


def test_worker_receives_effective_endpoint(settings, monkeypatch):
    from api.services.local_operator import gateway, planner
    settings.operator_worker_enabled = True
    overrides.update(settings, {"base_url": "http://10.0.0.7:8080/v1", "model": "edited"})
    seen = []
    async def execute(effective, task):
        seen.append((effective.operator_base_url, effective.operator_model))
        return {"ok": True}
    monkeypatch.setattr(planner, "execute", execute)
    assert asyncio.run(gateway.execute_task(settings, {"kind": "plan_request"})) == {"ok": True}
    assert seen == [("http://10.0.0.7:8080/v1", "edited")]


def test_api_validation_never_echoes_submitted_credentials(settings):
    with _client(settings) as client:
        for suffix in ("", "/test"):
            method = client.post if suffix else client.put
            for body in ({"api_key": "private-token-" * 400}, {"unexpected": {"api_key": "private-token"}}):
                result = method(f"/api/operator/settings{suffix}", json=body)
                assert result.status_code == 422 and "private-token" not in result.text
            result = method(f"/api/operator/settings{suffix}", content='{"api_key": "private-token", broken}',
                            headers={"content-type": "application/json"})
            assert result.status_code == 422 and "private-token" not in result.text


def test_cloud_readiness_and_cache_follows_configuration(settings, monkeypatch):
    settings.operator_allow_external = True
    overrides.update(settings, {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
                                "model": "gpt-x", "api_key": "k", "allow_external": True})
    effective = overrides.effective_settings(settings)
    assert runtime.endpoint_probe(effective, transport=_models("gpt-x"), resolver=_public)["endpoint_status"] == "ready"
    calls = []
    def probe(value):
        calls.append(value.operator_model)
        return {"endpoint_status": "ready", "endpoint_error": None}
    monkeypatch.setattr(runtime, "endpoint_probe", probe)
    runtime.endpoint_cached(effective)
    runtime.endpoint_cached(effective)
    runtime.endpoint_cached(dataclasses.replace(effective, operator_model="changed"))
    assert calls == ["gpt-x", "changed"]


# --- review follow-ups -----------------------------------------------------

_HOSTED = {"provider": "openai_compatible", "base_url": "https://llm.example.com/v1",
           "api_key": "sk-plain", "allow_external": True}


def test_key_is_refused_without_a_master_key_instead_of_stored_as_typed(settings):
    from api.services.crypto import envelope
    envelope.reset_for_tests()
    settings.operator_allow_external = True
    assert overrides.snapshot(settings)["secret_storage_available"] is False
    with pytest.raises(overrides.OperatorSettingsError, match="operator_master_key_required"):
        overrides.update(settings, _HOSTED)
    assert overrides.load(settings)[0] == {}
    # No credential in the edit: nothing to protect, so it is still accepted.
    overrides.update(settings, {"model": "other"})
    assert overrides.load(settings)[0] == {"model": "other"}


def test_concurrent_edit_is_refused_instead_of_overwriting(settings):
    overrides.update(settings, {"model": "first"})
    stale = {}  # what a second admin read before the first edit landed
    with pytest.raises(overrides.OperatorSettingsError, match="operator_settings_changed_concurrently"):
        overrides._write(settings, {"model": "second"}, stale, username="b", audit=None)
    assert overrides.load(settings)[0] == {"model": "first"}


def test_changed_concurrently_is_a_conflict_over_http(settings, monkeypatch):
    settings.operator_allow_external = True
    def conflict(*args, **kwargs):
        raise overrides.OperatorSettingsError("operator_settings_changed_concurrently")
    monkeypatch.setattr(overrides, "update", conflict)
    with _client(settings) as client:
        response = client.put("/api/operator/settings", json={"model": "x"})
    assert response.status_code == 409 and response.json()["detail"] == "operator_settings_changed_concurrently"


def test_connection_test_is_audited_without_url_path_or_key(settings, monkeypatch):
    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session
    from api.services import audit as audit_service
    settings.operator_allow_external = True
    async def fake_check(config, **_):
        return {"ok": True}
    monkeypatch.setattr(connection, "check", fake_check)
    monkeypatch.setattr(audit_service, "_require_settings", lambda: settings)
    with _client(settings) as client:
        response = client.post("/api/operator/settings/test", json={
            **_HOSTED, "base_url": "https://llm.example.com/secret/path/v1", "model": "gpt-x"})
    assert response.status_code == 200
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(select(models.AuditEvent).where(models.AuditEvent.action == overrides.ACTION_TEST)).all()
        assert len(rows) == 1
        assert rows[0].after == {"provider": "openai_compatible", "host": "llm.example.com",
                                 "completion": False, "credential": "set"}
        assert "sk-plain" not in json.dumps(rows[0].after) and "secret" not in json.dumps(rows[0].after)


def test_pinned_backend_dials_the_checked_address_not_the_name():
    from api.services.local_operator.providers import _PinnedBackend

    dialed = []
    class Inner:
        async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
            dialed.append((host, port))
            return object()
        async def sleep(self, seconds):
            pass
    asyncio.run(_PinnedBackend("93.184.216.34", Inner()).connect_tcp("rebind.example", 443))
    assert dialed == [("93.184.216.34", 443)]
    with pytest.raises(OperatorProviderError):
        asyncio.run(_PinnedBackend("93.184.216.34", Inner()).connect_unix_socket("/tmp/s"))


def test_real_pinned_transport_replaces_the_network_backend():
    from api.services.local_operator.providers import _PinnedBackend, _pinned_transport

    transport = _pinned_transport("93.184.216.34")
    assert isinstance(transport._pool._network_backend, _PinnedBackend)
    assert transport._pool._network_backend._address == "93.184.216.34"


def test_hosted_provider_connects_to_the_address_it_validated(monkeypatch):
    from api.services.local_operator import providers
    seen = []
    def pinned(address):
        seen.append(address)
        return _models("gpt-x")
    monkeypatch.setattr(providers, "_pinned_transport", pinned)
    config = OperatorConfig(enabled=True, provider="openai_compatible", base_url="https://llm.example.com/v1",
                            model="gpt-x", api_key="k", allow_external=True)
    models = asyncio.run(InferenceProvider(config, resolver=_public).list_models())
    assert [m.id for m in models] == ["gpt-x"] and seen == ["93.184.216.34"]
