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
    from datetime import datetime

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
NATS_URL = (os.environ.get("OCTO_NATS_URL") or os.environ.get("NATS_URL") or "").strip()

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
    from api.services import audit as audit_service
    from api.services import auth_audit
    from api.services import idempotency as idempotency_service
    from api.services import oidc as oidc_service
    from api.services import scan_schedules
    from api.services import service_tokens as service_tokens_service
    from api.services import tenants as tenants_service
    from api.services import users as users_service
    from api.services import wordlists as wordlists_service
    from api.services.crypto import envelope as crypto_envelope
    from api.services.integrations import channels as channels_service
    from api.services.integrations import webhooks as webhooks_service

    # The KEK provider is process-global (#310). Clearing it here means a test
    # that configures a master key cannot leave later tests writing ciphertext
    # they never asked for — create_app() re-resolves it from the environment.
    crypto_envelope.reset_for_tests()
    agents_service.configure(settings)
    # Before anything is truncated: a deployment worker left running by the
    # previous test writes stage rows and re-seeds nothing, so it races both
    # the truncation below and create_app()'s user bootstrap after it (#257).
    # Daemon threads made that invisible -- the test that started one passed,
    # and a later, unrelated test failed.
    assert agent_deployer.join_workers(), "a deployment worker outlived its test"
    agent_deployer.configure(settings)
    # Same reasoning for the notification fan-out (#351): since it moved off
    # the request thread, a send still recording ``last_status`` would race
    # this truncation and the next test's channels.
    assert channels_service.join_senders(), "a notification fan-out outlived its test"
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
    # The administrative trail (#327) is append-only in the database, so it is
    # emptied through the same privileged function retention uses — a plain
    # DELETE is refused by migration 0037's trigger, which is the point of it.
    audit_service.configure(settings)
    audit_service.reset_for_tests()
    # Idempotency records (#346) have no foreign key to ``tenants``, so they do
    # not vanish with the truncation above: a key one test used would 409 the
    # next test that reached for the same name.
    idempotency_service.reset_for_tests(settings)
    # Service tokens are rows on the tenants the reset above truncated, and the
    # OIDC caches are process-global — a discovery document or an in-flight
    # authorization request from a previous test would otherwise leak into this
    # one (ROADMAP Track E).
    service_tokens_service.configure(settings)
    # Since #321 the in-flight authorization requests are rows rather than a
    # process dict, so clearing them needs the settings that name the database.
    oidc_service.reset_for_tests(settings)


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


def accept_risk(
    settings: "Settings",
    *,
    tenant_id: str,
    vuln_id: str,
    until: "datetime",
    reason: str = "accepted by tests",
    requester: str = "requester",
    approver: str = "approver",
) -> dict[str, Any]:
    """Put an acceptance in force the way the platform does since #348.

    Two calls and two names, because there is no longer one: a request and
    somebody else's approval. Tests that only need a finding whose SLA clock is
    suspended use this; the ones about the workflow itself call the two service
    functions directly, and the whole point of this helper is that they are the
    only ones that have to know the order.
    """
    from api.services import vulnerabilities as vulns_service

    vulns_service.request_exception(
        settings,
        tenant_id=tenant_id,
        vuln_id=vuln_id,
        until=until,
        reason=reason,
        actor=requester,
    )
    approved = vulns_service.approve_exception(
        settings, tenant_id=tenant_id, vuln_id=vuln_id, actor=approver
    )
    assert approved is not None, f"no such finding: {vuln_id}"
    return approved


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


# ---------------------------------------------------------------------------
# Integration gate
#
# Skipping is the right default on a laptop, but it makes an exit code
# ambiguous: `pytest` prints the same green whether the Postgres-backed suites
# ran or were skipped wholesale, so CI proving "exit 0" proved nothing about
# tenant isolation or row locks — 1232 of 3025 collected tests are gated on
# OCTO_POSTGRES_URL alone.
#
# Setting OCTO_REQUIRE_INTEGRATION=1 (scripts/ci-pytest.sh does) declares the
# infrastructure available, and the session then has to show for it: the run
# fails before collection if a URL is missing, and fails at the end if any
# gated test was skipped anyway, or if fewer of them ran than the floor.
# ---------------------------------------------------------------------------

REQUIRE_INTEGRATION = os.environ.get("OCTO_REQUIRE_INTEGRATION", "").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Suite name -> (the variable its skip reason names, how many of its tests must
# have run). The suites are recognised by that variable appearing in the skipif
# reason rather than by a marker of their own: the reasons are already written
# for humans, and tagging 307 call sites a second time would be a worse thing
# to keep correct than this.
#
# The floors sit well below the current counts (1232 Postgres, 5 NATS at this
# commit) on purpose. They are not a coverage target — they catch "the mark
# stopped applying and the gate passed on an empty set", which the skipped
# count alone cannot. Raise them deliberately, not to track growth.
INTEGRATION_SUITES: dict[str, tuple[str, int]] = {
    "postgres": ("OCTO_POSTGRES_URL", 1000),
    "nats": ("OCTO_NATS_URL", 5),
}

_integration_collected: dict[str, set[str]] = {name: set() for name in INTEGRATION_SUITES}
_integration_skipped: dict[str, set[str]] = {name: set() for name in INTEGRATION_SUITES}


def integration_gate_problems(counts: dict[str, tuple[int, int]]) -> list[str]:
    """Describe why ``counts`` fails the gate, or return an empty list.

    ``counts`` maps a suite name to ``(collected, skipped)``. Kept separate from
    the hooks so the gate's own arithmetic is testable without a nested pytest
    session (tests/test_ci_checks.py).
    """
    problems: list[str] = []
    for name, (var, floor) in INTEGRATION_SUITES.items():
        collected, skipped = counts.get(name, (0, 0))
        ran = collected - skipped
        if skipped:
            # Belt to the floor's braces. With the current marks nothing can
            # skip once the URL is set — pytest_configure already refused that
            # run — but a future gate that probes reachability rather than
            # env presence would skip with the URL set, and that has to be red.
            problems.append(
                f"{name}: {skipped} of {collected} tests skipped although {var} "
                "is declared available"
            )
        if ran < floor:
            problems.append(f"{name}: only {ran} tests ran, floor is {floor} ({var})")
    return problems


def _integration_counts() -> dict[str, tuple[int, int]]:
    return {
        name: (len(_integration_collected[name]), len(_integration_skipped[name]))
        for name in INTEGRATION_SUITES
    }


def pytest_configure(config) -> None:  # noqa: ARG001 - pytest hook signature
    """Refuse a declared-integration run that has nothing to run against.

    Fails here rather than at the end: the matrix stage takes minutes, and a
    missing URL is knowable before the first test.
    """
    if not REQUIRE_INTEGRATION:
        return
    missing = [
        var
        for var, url in (("OCTO_POSTGRES_URL", POSTGRES_URL), ("OCTO_NATS_URL", NATS_URL))
        if not url
    ]
    if missing:
        raise pytest.UsageError(
            f"OCTO_REQUIRE_INTEGRATION declares the integration infrastructure "
            f"available, but {', '.join(missing)} is unset. Point it at the test "
            "database/broker, or drop the flag — a run that skips those suites "
            "must not report success."
        )


def pytest_collection_modifyitems(config, items) -> None:  # noqa: ARG001 - pytest hook signature
    for item in items:
        reasons = " ".join(str(mark.kwargs.get("reason", "")) for mark in item.iter_markers("skipif"))
        for name, (var, _floor) in INTEGRATION_SUITES.items():
            if var in reasons:
                _integration_collected[name].add(item.nodeid)


def pytest_runtest_logreport(report) -> None:
    # Only the setup phase: that is where a skipif mark takes effect, and
    # counting call/teardown too would double-count nothing but confuse later.
    if report.when != "setup" or not report.skipped:
        return
    for name, nodes in _integration_collected.items():
        if report.nodeid in nodes:
            _integration_skipped[name].add(report.nodeid)


def pytest_terminal_summary(terminalreporter, exitstatus, config) -> None:  # noqa: ARG001
    if not REQUIRE_INTEGRATION:
        return
    counts = _integration_counts()
    problems = integration_gate_problems(counts)
    terminalreporter.section("integration gate")
    for name, (collected, skipped) in sorted(counts.items()):
        terminalreporter.write_line(
            f"{name}: {collected - skipped} ran, {skipped} skipped, {collected} collected"
        )
    for problem in problems:
        terminalreporter.write_line(f"FAILED {problem}", red=True)


def pytest_sessionfinish(session, exitstatus) -> None:  # noqa: ARG001 - pytest hook signature
    if not REQUIRE_INTEGRATION:
        return
    if integration_gate_problems(_integration_counts()):
        # Only ever upgrades green to red: a run already failing for its own
        # reasons keeps the status that names the real cause.
        if session.exitstatus == 0:
            session.exitstatus = 1
