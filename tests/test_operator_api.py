"""Real-Postgres operator API isolation, authorization and durable polling."""

from __future__ import annotations

import pytest

from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path, operator_enabled=True, operator_worker_enabled=False
    )
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    return (
        client,
        settings,
        auth_headers(client, "admin"),
        auth_headers(client, "operator"),
    )


def _session(client, headers, tenant="default"):
    response = client.post(
        f"/api/operator/sessions?tenant_id={tenant}", headers=headers, json={}
    )
    assert response.status_code == 201, response.text
    return response.json()["session_id"]


def test_explicit_tenant_required_even_for_admin_and_no_viewer_spending(env):
    client, settings, admin, operator = env
    for headers in (admin, operator):
        for query in ("", "?tenant_id=%20"):
            assert (
                client.get(f"/api/operator/status{query}", headers=headers).status_code
                == 422
            )
    viewer = auth_headers(client, "viewer")
    assert (
        client.get("/api/operator/status?tenant_id=default", headers=viewer).status_code
        == 200
    )
    assert (
        client.post(
            "/api/operator/sessions?tenant_id=default", headers=viewer, json={}
        ).status_code
        == 403
    )
    status = client.get(
        "/api/operator/status?tenant_id=default", headers=operator
    ).json()
    assert status["durable_sessions_available"]
    assert not status["analysis_available"]
    assert status["quality_status"] == "quality_unverified"


def test_sessions_are_personal_including_admin_and_cross_tenant(env):
    client, settings, admin, operator = env
    session_id = _session(client, operator)
    base = f"/api/operator/sessions/{session_id}"
    assert client.get(base + "?tenant_id=default", headers=operator).status_code == 200
    assert client.get(base + "?tenant_id=default", headers=admin).status_code == 404
    assert client.get(
        "/api/operator/sessions?tenant_id=default", headers=admin
    ).json() == {"items": [], "total": 0}
    created = client.post(
        "/api/tenants", headers=admin, json={"tenant_id": "other", "name": "other"}
    )
    assert created.status_code == 201, created.text
    assert client.get(base + "?tenant_id=other", headers=operator).status_code == 403
    assert client.get(base + "?tenant_id=other", headers=admin).status_code == 404
    assert (
        client.delete(base + "?tenant_id=default", headers=operator).status_code == 204
    )
    assert client.get(base + "?tenant_id=default", headers=operator).status_code == 404


def test_membership_revocation_and_suspension_apply_to_existing_sessions(env):
    client, settings, admin, operator = env
    assert (
        client.post(
            "/api/tenants", headers=admin, json={"tenant_id": "acme", "name": "acme"}
        ).status_code
        == 201
    )
    member = "/api/tenants/acme/members/operator"
    assert (
        client.put(member, headers=admin, json={"role": "operator"}).status_code == 200
    )
    session_id = _session(client, operator, "acme")
    url = f"/api/operator/sessions/{session_id}?tenant_id=acme"
    assert client.delete(member, headers=admin).status_code == 204
    assert client.get(url, headers=operator).status_code == 403
    assert (
        client.put(member, headers=admin, json={"role": "operator"}).status_code == 200
    )
    assert client.get(url, headers=operator).status_code == 200
    suspended = client.post(
        "/api/tenants/acme/suspend",
        headers=admin,
        json={"reason": "test", "revoke_credentials": False},
    )
    assert suspended.status_code == 200, suspended.text
    assert client.get(url, headers=operator).status_code == 401


def test_task_replay_cancel_poll_and_strict_bounded_input(env, monkeypatch):
    client, settings, admin, operator = env
    session_id = _session(client, operator)
    url = f"/api/operator/sessions/{session_id}/tasks?tenant_id=default"
    # Enabling submission here does not start a background worker in TestClient.
    settings.operator_worker_enabled = True
    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    from api.services.runs import write_run_tenant

    assert write_run_tenant(settings, "run-1", "default")
    headers = {**operator, "Idempotency-Key": "summary-1"}
    body = {"tool": "summarize_run", "run_id": "run-1", "language": "ru"}
    response = client.post(url, headers=headers, json=body)
    assert response.status_code == 202, response.text
    task_id = response.json()["task_id"]
    settings.operator_queue_limit = 1
    assert (
        client.post(
            url, headers={**operator, "Idempotency-Key": "queue-overflow"}, json=body
        ).status_code
        == 429
    )
    assert (
        client.delete(
            f"/api/operator/sessions/{session_id}?tenant_id=default", headers=operator
        ).status_code
        == 409
    )
    assert (
        client.post(
            url, headers=headers, json={**body, "run_id": "missing"}
        ).status_code
        == 404
    )
    replay = client.post(url, headers=headers, json=body)
    assert replay.status_code == 202 and replay.json()["task_id"] == task_id
    assert (
        client.post(url, headers=headers, json={**body, "language": "en"}).status_code
        == 409
    )
    task_url = f"/api/operator/tasks/{task_id}?tenant_id=default"
    assert client.get(task_url, headers=admin).status_code == 404
    assert client.get(task_url, headers=operator).status_code == 200
    cancelled = client.post(
        f"/api/operator/tasks/{task_id}/cancel?tenant_id=default", headers=operator
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["status"] == "cancelled"
    assert client.post(url, headers=operator, json=body).status_code == 422
    for invalid in (
        {**body, "prompt": "arbitrary"},
        {**body, "tool": "fetch_url"},
        {**body, "language": "de"},
        {**body, "run_id": "../escape"},
    ):
        assert (
            client.post(
                url, headers={**operator, "Idempotency-Key": "other"}, json=invalid
            ).status_code
            == 422
        )
    assert (
        client.get(
            "/api/operator/sessions?tenant_id=default&limit=101", headers=operator
        ).status_code
        == 422
    )


def test_service_tokens_fail_closed_even_with_wildcard_scope(env):
    client, settings, admin, operator = env
    issued = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "machine", "role": "admin", "scopes": ["*"]},
    )
    assert issued.status_code == 201, issued.text
    headers = {"Authorization": "Bearer " + issued.json()["token"]}
    for path in ("status", "sessions"):
        assert (
            client.get(
                f"/api/operator/{path}?tenant_id=default", headers=headers
            ).status_code
            == 403
        )


def test_feature_disabled_hides_every_authenticated_endpoint(env):
    client, settings, admin, operator = env
    settings.operator_enabled = False
    for method, path, body in (
        ("get", "status", None),
        ("get", "sessions", None),
        ("post", "sessions", {}),
        ("get", "sessions/id", None),
        ("delete", "sessions/id", None),
        ("get", "tasks/id", None),
        ("post", "tasks/id/cancel", None),
    ):
        response = client.request(
            method,
            f"/api/operator/{path}?tenant_id=default",
            headers=operator,
            json=body,
        )
        assert response.status_code == 404, response.text


def test_authenticated_write_cannot_resurrect_state_after_account_recreation(
    env, monkeypatch
):
    from api.db import tenant_scope
    from api.services import users
    from api.services.local_operator import store

    client, settings, admin, operator = env
    original = store.create_session
    captured = {}

    def delete_recreate_then_write(
        settings, tenant_id, username, *, auth_session_id=None
    ):
        # The request already authenticated; interleave account deletion before
        # its mutation transaction begins. Recreated accounts start at version 0.
        captured["sid"] = auth_session_id
        with tenant_scope.system("operator stale authenticated write regression"):
            assert users.delete_user(username)
            users.create_user(
                username=username, password="replacement-password-1234", role="operator"
            )
        return original(settings, tenant_id, username, auth_session_id=auth_session_id)

    monkeypatch.setattr(store, "create_session", delete_recreate_then_write)
    response = client.post(
        "/api/operator/sessions?tenant_id=default", headers=operator, json={}
    )
    assert captured["sid"]
    assert response.status_code == 403, response.text
    with tenant_scope.system("operator stale write regression inspection"):
        assert store.list_sessions(settings, "default", "operator")["total"] == 0


def test_authenticated_read_cannot_inherit_recreated_accounts_history(env, monkeypatch):
    from api.db import tenant_scope
    from api.services import users
    from api.services.local_operator import store

    client, settings, admin, operator = env
    original = store.list_sessions
    captured = {}

    def delete_recreate_then_read(
        settings, tenant_id, username, limit=20, offset=0, *, auth_session_id=None
    ):
        captured["sid"] = auth_session_id
        with tenant_scope.system("operator stale authenticated read regression"):
            assert users.delete_user(username)
            users.create_user(
                username=username, password="replacement-password-1234", role="operator"
            )
            created = store.create_session(settings, tenant_id, username)
            captured["replacement_session"] = created["session_id"]
        return original(
            settings,
            tenant_id,
            username,
            limit=limit,
            offset=offset,
            auth_session_id=auth_session_id,
        )

    monkeypatch.setattr(store, "list_sessions", delete_recreate_then_read)
    response = client.get("/api/operator/sessions?tenant_id=default", headers=operator)
    assert captured["sid"]
    assert response.status_code == 403, response.text
    assert captured["replacement_session"] not in response.text


def test_status_probe_is_cached_so_viewers_cannot_exhaust_the_thread_pool(env, monkeypatch):
    from api.services.local_operator import runtime

    client, settings, admin, operator = env
    viewer = auth_headers(client, "viewer")
    calls = []
    clock = [1000.0]

    def counted(_settings):
        calls.append(1)
        return {"runtime_status": "ready", "runtime_verified": True, "manifest_attested": True,
                "model_integrity": "manifest_attested"}

    monkeypatch.setattr(runtime, "probe", counted)
    monkeypatch.setattr(runtime, "monotonic", lambda: clock[0])
    runtime.reset_cache()
    for _ in range(25):
        response = client.get("/api/operator/status?tenant_id=default", headers=viewer)
        assert response.status_code == 200, response.text
        assert response.json()["manifest_attested"] is True
        assert response.json()["runtime_verified"] is True  # deprecated alias
    assert len(calls) == 1
    clock[0] += runtime.STATUS_TTL_SECONDS - 1
    client.get("/api/operator/status?tenant_id=default", headers=viewer)
    assert len(calls) == 1
    clock[0] += 2
    client.get("/api/operator/status?tenant_id=default", headers=viewer)
    assert len(calls) == 2
    runtime.reset_cache()
    client.get("/api/operator/status?tenant_id=default", headers=viewer)
    assert len(calls) == 3
    runtime.reset_cache()


def test_status_cache_is_dropped_when_operator_configuration_changes(monkeypatch):
    from types import SimpleNamespace
    from api.services.local_operator import runtime

    calls = []
    monkeypatch.setattr(runtime, "probe", lambda s: calls.append(s.operator_model) or {"runtime_status": "ready"})
    runtime.reset_cache()
    first = SimpleNamespace(operator_model="a", operator_runtime_manifest_sha256="1" * 64, unrelated=1)
    runtime.probe_cached(first)
    runtime.probe_cached(first)
    first.unrelated = 2
    runtime.probe_cached(first)
    assert calls == ["a"]
    first.operator_model = "b"
    runtime.probe_cached(first)
    assert calls == ["a", "b"]
    runtime.reset_cache()


def test_failed_probe_is_cached_only_briefly(monkeypatch):
    from types import SimpleNamespace
    from api.services.local_operator import runtime

    clock = [0.0]
    calls = []
    monkeypatch.setattr(runtime, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime, "probe", lambda s: calls.append(1) or {"runtime_status": "unavailable"})
    runtime.reset_cache()
    settings = SimpleNamespace(operator_model="x")
    runtime.probe_cached(settings)
    runtime.probe_cached(settings)
    assert len(calls) == 1
    clock[0] += runtime.FAILURE_TTL_SECONDS + 0.1
    runtime.probe_cached(settings)
    assert len(calls) == 2
    runtime.reset_cache()
