from __future__ import annotations


from tests.conftest import api_client, requires_postgres

pytestmark = requires_postgres



def test_health_is_public():
    client = api_client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_and_me():
    client = api_client()
    login = client.post("/api/auth/login", json={"username": "viewer", "password": "viewer-change-me"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert login.json()["role"] == "viewer"

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    # /auth/me now also carries the tenant context the UI switcher needs (P0);
    # a user with no memberships falls back to the default tenant.
    assert me.json() == {
        "username": "viewer",
        "role": "viewer",
        "tenants": ["default"],
        "default_tenant": "default",
        "is_platform_admin": False,
    }


def test_login_rejects_bad_password():
    client = api_client()
    response = client.post("/api/auth/login", json={"username": "viewer", "password": "wrong"})
    assert response.status_code == 401


def test_runs_require_auth():
    client = api_client()
    assert client.get("/api/runs").status_code == 401
