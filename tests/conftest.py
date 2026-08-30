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

import dataclasses
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi.testclient import TestClient

    from api.settings import Settings

# The suite runs against the built-in demo accounts and the default JWT secret
# on purpose (see TEST_USERS below), which is exactly what OCTO_ENV=prod refuses
# to start with. Declaring the suite a dev environment is the honest statement of
# that, and it is set at import time because api_client() resolves the ambient
# environment while building the app. A test that wants to exercise the
# fail-closed checks themselves sets OCTO_ENV explicitly via monkeypatch —
# setdefault also leaves a deliberate `OCTO_ENV=prod pytest` run alone.
os.environ.setdefault("OCTO_ENV", "dev")

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
        # Matches the OCTO_ENV=dev set at import: the suite logs in as the demo
        # accounts, and since #156 those are seeded into the users table only in
        # a dev environment. Left at the "prod" dataclass default, create_app()
        # would refuse to start for having no console account — correctly, but
        # in every test.
        env="dev",
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        config_path=Path("scanner/config/default.yaml"),
        allow_scan_start=True,
        agent_token=TEST_AGENT_TOKEN,
        agent_stale_seconds=120,
        jwt_secret=TEST_JWT_SECRET,
        postgres_url=POSTGRES_URL,
    )
    known = {f.name for f in dataclasses.fields(base)}
    for key, value in overrides.items():
        # A typo used to be applied silently — ``setattr`` on a dataclass
        # invents the attribute, the app keeps the default, and the test reads
        # as if it had configured something (#254).
        if key not in known:
            raise TypeError(f"unknown Settings field: {key!r}")
        setattr(base, key, value)
    return base


def reset_service_state(settings: "Settings") -> None:
    """Truncate the per-test Postgres stores and point the services at ``settings``.

    Since ROADMAP P1.2 jobs and agents are rows like everything else, so
    ``tenants.reset_for_tests`` clears them along with the tables they
    reference — no module-level dicts left to clear.
    """
    from api.services import agent_deployer
    from api.services import agents as agents_service
    from api.services import auth_audit
    from api.services import oidc as oidc_service
    from api.services import scan_schedules
    from api.services import service_tokens as service_tokens_service
    from api.services import tenants as tenants_service
    from api.services import users as users_service
    from api.services import wordlists as wordlists_service
    from api.services.integrations import webhooks as webhooks_service

    agents_service.configure(settings)
    # Before anything is truncated: a deployment worker left running by the
    # previous test writes stage rows and re-seeds nothing, so it races both
    # the truncation below and create_app()'s user bootstrap after it (#257).
    # Daemon threads made that invisible -- the test that started one passed,
    # and a later, unrelated test failed.
    assert agent_deployer.join_workers(), "a deployment worker outlived its test"
    agent_deployer.configure(settings)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    # Users are cleared here and re-seeded by create_app()'s bootstrap, which
    # runs after this in configured_client(). Clearing them cascades the
    # user_tenants grants (FK, migration 0013), so a membership from a previous
    # test cannot survive its user.
    users_service.configure(settings)
    users_service.reset_for_tests()
    scan_schedules.configure(settings)
    scan_schedules.reset_for_tests()
    webhooks_service.configure(settings)
    webhooks_service.reset_for_tests()
    wordlists_service.configure(settings)
    # Login attempts are rows now (#157), so a previous test's failed logins
    # would otherwise count against this one's rate limit.
    auth_audit.configure(settings)
    auth_audit.reset_for_tests()
    # Service tokens are rows on the tenants the reset above truncated, and the
    # OIDC caches are process-global — a discovery document or an in-flight
    # authorization request from a previous test would otherwise leak into this
    # one (ROADMAP Track E).
    service_tokens_service.configure(settings)
    oidc_service.reset_for_tests()


def approve_scan_scope(
    settings: "Settings",
    tenant_id: str = "default",
    entries: list[dict[str, Any]] | None = None,
) -> None:
    """Give a tenant an approved scanning scope (#226).

    Since #226 a tenant with no approved scope starts no scans at all, which
    would be every test in this suite. Real installations get the same thing
    from migration 0025, which grandfathers an explicit allow-all scope onto
    the tenants that predate the table; this is that scope, for the tenants
    tests create at runtime. Tests about the check itself pass their own
    ``entries`` — or none, to exercise a tenant that was never approved.
    """
    from api.services import scan_scopes

    if entries is None:
        entries = [
            {"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"},
            {"effect": "allow", "kind": "cidr", "value": "::/0"},
            {"effect": "allow", "kind": "domain", "value": "*"},
        ]
    scan_scopes.replace_scope(
        settings, tenant_id=tenant_id, entries=entries, approved_by="tests"
    )


def approve_scan_scope_via_api(
    client: "TestClient", tenant_id: str, admin_headers: dict[str, str]
) -> None:
    """Approve an allow-all scan scope for ``tenant_id`` over the admin API.

    The counterpart of :func:`approve_scan_scope` for tests that create their
    tenants through ``POST /api/tenants`` and have no Settings object at hand.
    """
    response = client.put(
        f"/api/tenants/{tenant_id}/scan-scope",
        headers=admin_headers,
        json={
            "entries": [
                {"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"},
                {"effect": "allow", "kind": "cidr", "value": "::/0"},
                {"effect": "allow", "kind": "domain", "value": "*"},
            ]
        },
    )
    assert response.status_code == 200, f"scope approval failed: {response.text}"


def api_client() -> "TestClient":
    """A client over the app's ambient settings (whatever the env provides)."""
    from fastapi.testclient import TestClient

    from api.app import create_app

    return TestClient(create_app())


def configured_client(
    tmp_path: Path,
    monkeypatch,
    settings: "Settings | None" = None,
    **overrides: Any,
) -> "TestClient":
    """A client over test-owned ``Settings``, with service state reset.

    Patches both ``api.auth.load_settings`` and ``api.app.get_settings``: the
    auth layer resolves settings independently of the app, so patching only one
    leaves requests authenticating against a different config than they run on.

    A test that needs the same object the app runs on — to read ``agent_token``
    off it, or to hand it to :func:`approve_scan_scope` — builds it with
    :func:`make_settings` and passes it as ``settings``; anything else passes
    field overrides. Passing both is a contradiction, not a merge: before #254
    ``settings=`` fell into ``**overrides`` and the ready object was dropped.
    """
    from fastapi.testclient import TestClient

    from api.app import create_app

    if settings is not None and overrides:
        raise TypeError(
            "pass either a ready Settings object or field overrides, not both: "
            f"{sorted(overrides)}"
        )
    if settings is None:
        settings = make_settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    reset_service_state(settings)
    client = TestClient(create_app())
    # create_app() seeds the default tenant; approving its scan scope here
    # keeps every pre-#226 test starting scans the way it did.
    approve_scan_scope(settings)
    return client


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
