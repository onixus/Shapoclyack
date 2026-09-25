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
import threading
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
    from api.services import config_override as config_service
    from api.services import idempotency as idempotency_service
    from api.services import oidc as oidc_service
    from api.services import run_publisher
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
    # The installation-wide config overrides are one row keyed by scope, with
    # no tenant to cascade from either. Left behind, the next test to PUT the
    # same override writes it over itself — a change that changed nothing, so
    # the audit diff is empty and the row that says the override was recorded
    # never appears. It outlived the whole session, too: the database is shared
    # between runs, so running one file on its own was enough to fail the next
    # full run.
    config_service.reset_for_tests(settings)
    # Owed run publications carry a tenant id but no foreign key to it either,
    # and since #425 they are read through the API: a ``dead`` row one test
    # left would sit in the next test's job card and health check.
    run_publisher.reset_for_tests(settings)
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


def _ambient_egress_vars() -> tuple[str, ...]:
    """Every variable that can reroute or re-trust this process's outgoing HTTP.

    Taken from the egress modules themselves, so a variable either of them
    starts reading is cleared here without anyone remembering to. The rest are
    what the standard library's ``getproxies()`` and httpx's ``trust_env`` read
    even though egress does not -- uppercase ``HTTP_PROXY`` is refused there
    for httpoxy, not absent from a developer's shell.
    """
    from agent import egress as agent_egress
    from api.services import egress as api_egress

    names = {"HTTP_PROXY", "ALL_PROXY", "all_proxy"}
    for module in (api_egress, agent_egress):
        names.update(module._HTTP_PROXY_VARS)
        names.update(module._HTTPS_PROXY_VARS)
        names.update(module._NO_PROXY_VARS)
        names.add(module.CA_BUNDLE_VAR)
    return tuple(sorted(names))


#: How long a thread a test started is given to finish once the test is over.
#: Generous on purpose: this is not there to police slow work but to catch the
#: writer that is never coming back, so a healthy test pays nothing for it and
#: a leak pays it once.
_THREAD_JOIN_TIMEOUT = 30.0

#: Threads that are process-global by design, whichever test happens to start
#: them first. ``octo-*`` are the application's own workers, owned by
#: ``start_worker``/``stop_worker`` and the app lifespan rather than by a test;
#: ``octo-nats`` in particular is a lazily-created singleton that only
#: ``shutdown_bus`` stops, and ``asyncio_N`` are the idle workers of the default
#: executor its event loop keeps. Neither holds a transaction across tests, and
#: neither is the test's to join.
#:
#: Not hypothetical tidiness: with ``OCTO_NATS_URL`` set -- which is CI, and not
#: a default local run -- the first test to publish anything starts the bus, and
#: without this that test was the one blamed for it.
_PROCESS_GLOBAL_THREADS = ("octo-", "asyncio_")


@pytest.fixture(autouse=True)
def _no_thread_outlives_its_test():
    """Fail the test that leaves a thread running, not the one it corrupts.

    Several tests here drive a real second writer on a connection of its own,
    because that is the only honest way to test a lock: two requests for one
    group name, two replicas accepting the same run, eight racing webhook
    creates. Every one of them ends in ``join(timeout=...)`` and then carries
    on regardless of what the join returned -- and the threads are daemons, so
    a join that timed out leaves a transaction open with nothing to say so.

    What that costs is paid by somebody else. The abandoned writer commits, or
    deadlocks, against whatever runs next, which is almost always
    ``reset_service_state``'s ``DELETE FROM tenants``: Postgres kills one of
    the two, and either the truncation silently does not happen or the writer's
    rows land *after* it and survive into tests that never created them. The
    database log for 2026-09-21 has six such deadlocks, between
    ``DELETE FROM tenants`` and an ``UPDATE agents``, an
    ``INSERT INTO scan_schedules``, an ``INSERT INTO vulnerabilities`` -- none
    of which belonged to the test that was running at the time.

    So the check is here rather than at each call site: joining every thread
    the test started, and failing if one will not come back, names the test
    that started it. Threads that were already running when the test began are
    left alone -- the workers a previous ``create_app`` lifespan owns are that
    lifespan's business, and ``reset_service_state`` has its own assertions for
    the deployment and notification fan-outs. So are the ones named in
    :data:`_PROCESS_GLOBAL_THREADS`, which outlive every test on purpose.
    """
    before = {thread.ident for thread in threading.enumerate()}
    yield
    started_here = [
        thread
        for thread in threading.enumerate()
        if thread.ident not in before
        and not thread.name.startswith(_PROCESS_GLOBAL_THREADS)
    ]
    for thread in started_here:
        thread.join(timeout=_THREAD_JOIN_TIMEOUT)
    outlived = sorted(thread.name for thread in started_here if thread.is_alive())
    assert not outlived, f"a thread outlived its test: {outlived}"


@pytest.fixture(autouse=True)
def _stop_local_scans(_no_thread_outlives_its_test):
    """Put down the scans a test started before the next test begins.

    Starting a scan in local execution mode -- the default for this suite --
    launches a real ``scanner.main`` subprocess from a daemon thread, and
    nothing in the API ever stops one: ``cancel_job`` refuses a running local
    job by design, because the only thing that could signal it is the thread
    that spawned it. Most tests that start a scan are not about the scan at
    all (they assert a 202, a tenant id, or an RBAC refusal) and are done
    while it is still in its first stage.

    Left alone, those scans kept running. A session on 2026-09-21 held seven
    ``scanner.main`` processes at once, aged 1:37 to 5:56, belonging to tests
    that had passed minutes earlier, and finished in 15 minutes against 13:36
    for the same suite -- the difference being the machine scanning on behalf
    of nobody. Some outlived pytest itself: a daemon thread is not joined at
    exit, so its child is simply reparented.

    Autouse and here rather than inside ``reset_service_state`` so it covers
    every test, including the ones that build ``Settings`` themselves and
    never go through :func:`configured_client`. The deliberately abandoned job
    -- ``test_an_abandoned_local_job_is_failed_not_requeued`` and friends --
    is unaffected: the row it examines is already written, and what this drops
    is the process, after the assertions.

    Requesting :func:`_no_thread_outlives_its_test` is an ordering statement,
    not a dependency: a fixture is torn down before the ones it requested, so
    this puts the scans down *first* and the thread check then sees a process
    whose scan threads have already been let go rather than reporting them as
    leaks.
    """
    yield
    from api.services import jobs as jobs_service

    assert jobs_service.stop_local_scans(), (
        f"a local scan outlived its test: {jobs_service.live_local_scans()}"
    )


@pytest.fixture(autouse=True)
def _no_ambient_egress(_stop_local_scans, monkeypatch):
    """No test inherits the proxy or CA bundle of the shell that ran pytest.

    A developer behind a corporate proxy, or a cloud container with an egress
    proxy, exports ``HTTPS_PROXY`` -- and every delivery test that monkeypatches
    the direct dial then watched the request go to the proxy instead: 13 of the
    40 in ``test_webhook_delivery.py`` failed there and nowhere else. A test
    about proxy behaviour sets its own values with ``monkeypatch.setenv``, which
    runs after this and is undone with it.

    Requesting :func:`_stop_local_scans` is again an ordering statement. This
    fixture is the first user of ``monkeypatch`` in every test, so whatever
    requests it earliest decides when *all* of a test's patches are undone.
    Asked for before the scan fixture, it kept them in place through that
    teardown -- and a test that pins ``time.monotonic`` to a short iterator
    (``test_webhook_worker``) then broke ``stop_local_scans`` with a
    ``StopIteration`` that was not its own.
    """
    for name in _ambient_egress_vars():
        monkeypatch.delenv(name, raising=False)


# ---------------------------------------------------------------------------
# Integration gate
#
# The hooks live in tests/integration_gate.py so a test can drive them through a
# real pytest session; importing them here is what registers them for this
# repository's own runs, and tests/test_ci_checks.py asserts that this import is
# still the same objects. See that module for what the gate refuses and why.
# ---------------------------------------------------------------------------

from tests.integration_gate import (  # noqa: E402,F401 - imported to register the hooks
    pytest_collection_modifyitems,
    pytest_configure,
    pytest_runtest_logreport,
    pytest_sessionfinish,
    pytest_terminal_summary,
)
