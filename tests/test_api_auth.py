from __future__ import annotations

from fastapi.testclient import TestClient

from api.app import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def test_health_is_public():
    client = _client()
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_login_and_me():
    client = _client()
    login = client.post("/api/auth/login", json={"username": "viewer", "password": "viewer-change-me"})
    assert login.status_code == 200
    token = login.json()["access_token"]
    assert login.json()["role"] == "viewer"

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json() == {"username": "viewer", "role": "viewer"}


def test_login_rejects_bad_password():
    client = _client()
    response = client.post("/api/auth/login", json={"username": "viewer", "password": "wrong"})
    assert response.status_code == 401


def test_runs_require_auth():
    client = _client()
    assert client.get("/api/runs").status_code == 401
