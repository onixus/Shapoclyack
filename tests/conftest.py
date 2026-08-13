"""Shared test fixtures, constants, and API-client helpers.

Phase 7 made the tenant store Postgres-backed (api/services/tenants.py) —
unlike the opt-in NATS/ClickHouse sidecars, any test that builds a FastAPI
app now needs a real, migrated Postgres reachable at OCTO_POSTGRES_URL. CI
provides this via a postgres:16-alpine service container (.github/workflows/
ci.yml); locally, tests needing it are skipped when the env var is unset,
matching how tests/test_nats_live.py gates on OCTO_NATS_URL.

The helpers below replace per-module copies of the same three things —
``_settings``, ``_client``, and a login helper — which had drifted into a
dozen near-identical definitions across the suite. They are plain functions
rather than pytest fixtures on purpose: the call sites build a client *inside*
the test body (often several times, with different settings), which a fixture
cannot express without restructuring every test.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi.testclient import TestClient

    from api.settings import Settings

POSTGRES_URL = (os.environ.get("OCTO_POSTGRES_URL") or os.environ.get("POSTGRES_URL") or "").strip()

requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="OCTO_POSTGRES_URL not set — tenant store is Postgres-backed (Phase 7); "
    "run `alembic -c api/db/alembic.ini upgrade head` against a local Postgres first.",
)

# The seeded development accounts from OCTO_API_USERS' default. Tests assert
# against roles, not credentials, so the passwords live here once instead of
# being retyped at ~40 call sites.
TEST_USERS: dict[str, str] = {
    "viewer": "viewer-change-me",
    "operator": "operator-change-me",
    "admin": "admin-change-me",
}

TEST_JWT_SECRET = "test-secret"
TEST_AGENT_TOKEN = "test-agent-token"


def make_settings(tmp_path: Path, **overrides: Any) -> "Settings":
    """Baseline API ``Settings`` for tests, with per-test overrides.

    Defaults to local job execution and the legacy agent token set; tests that
    exercise agent mode or JWT-only auth pass ``job_execution_mode="agent"`` /
    ``agent_token=""`` explicitly, so the deviation is visible at the call site
    instead of buried in a per-module copy of this function.
    """
    from api.settings import Settings

    base = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
        agent_token=TEST_AGENT_TOKEN,
        agent_stale_seconds=120,
        jwt_secret=TEST_JWT_SECRET,
        postgres_url=POSTGRES_URL,
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def reset_service_state(settings: "Settings") -> None:
    """Truncate the per-test Postgres stores and point the services at ``settings``.

    Since ROADMAP P1.2 jobs and agents are rows like everything else, so
    ``tenants.reset_for_tests`` clears them along with the tables they
    reference — no module-level dicts left to clear.
    """
    from api.services import agents as agents_service
    from api.services import scan_schedules
    from api.services import tenants as tenants_service
    from api.services import wordlists as wordlists_service
    from api.services.integrations import webhooks as webhooks_service

    agents_service.configure(settings)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    scan_schedules.configure(settings)
    scan_schedules.reset_for_tests()
    webhooks_service.configure(settings)
    webhooks_service.reset_for_tests()
    wordlists_service.configure(settings)


def api_client() -> "TestClient":
    """A client over the app's ambient settings (whatever the env provides)."""
    from fastapi.testclient import TestClient

    from api.app import create_app

    return TestClient(create_app())


def configured_client(tmp_path: Path, monkeypatch, **overrides: Any) -> "TestClient":
    """A client over test-owned ``Settings``, with service state reset.

    Patches both ``api.auth.load_settings`` and ``api.app.get_settings``: the
    auth layer resolves settings independently of the app, so patching only one
    leaves requests authenticating against a different config than they run on.
    """
    from fastapi.testclient import TestClient

    from api.app import create_app

    settings = make_settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    reset_service_state(settings)
    return TestClient(create_app())


def login(client: "TestClient", username: str = "viewer", password: str | None = None) -> str:
    """Log in and return the bearer token. Asserts success — callers testing a
    *failed* login should post to ``/api/auth/login`` directly."""
    if password is None:
        password = TEST_USERS[username]
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200, f"login failed for {username}: {response.text}"
    return response.json()["access_token"]


def auth_headers(
    client: "TestClient", username: str = "viewer", password: str | None = None
) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client, username, password)}"}


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
