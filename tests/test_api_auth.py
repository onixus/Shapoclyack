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
        # The role inside ``default_tenant`` and what it grants (#318). A
        # viewer holds no named permission at all: reading findings is the
        # rank, and every permission in the catalogue is something more than
        # that.
        "tenant_role": "viewer",
        "permissions": [],
        # Which tenant those two describe: the request named none, so the
        # default one. The console sends the tenant its switcher is on, and
        # this is how it tells a scoped answer from a stale one (#318).
        "scoped_tenant": "default",
        # Second-factor state of the account and of this session (#315). All
        # three false on an installation that has not configured MFA, which is
        # what "nothing changes on upgrade" looks like from the console's side.
        "mfa_enabled": False,
        "mfa_required": False,
        "mfa_pending": False,
    }


def test_login_rejects_bad_password():
    client = api_client()
    response = client.post("/api/auth/login", json={"username": "viewer", "password": "wrong"})
    assert response.status_code == 401


def test_runs_require_auth():
    client = api_client()
    assert client.get("/api/runs").status_code == 401
