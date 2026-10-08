"""General request rate limiting and the global body cap (#320).

Before this the login route was the only one with a limiter, and only the
inventory and results uploads had a body cap: an authenticated principal could
call anything as often as it liked, with a body as large as it liked. The
tests below are the issue's acceptance criteria — 429 with ``Retry-After``,
per-principal and per-tenant buckets, one bucket across replicas, a body cap
that holds for chunked bodies too — plus the two promises the change makes to
operators: a sensor or endpoint fleet is not throttled by the defaults, and
the probes and ``/metrics`` are never limited.
"""

from __future__ import annotations

import argparse
import json
import logging
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from api.services import metrics as metrics_service
from api.services import rate_limit
from api.settings import Settings
from tests.conftest import (
    POSTGRES_URL,
    auth_headers,
    bearer,
    configured_client,
    login,
    requires_postgres,
)

pytestmark = requires_postgres

#: A refill so slow that nothing comes back within a test.
TRICKLE = 0.001


def _limited(scope: str) -> float:
    return metrics_service.RATE_LIMITED_TOTAL.labels(scope)._value.get()


# --------------------------------------------------------------------------
# 1. A principal that runs out gets 429 and is told when to come back.
# --------------------------------------------------------------------------


def test_principal_over_its_bucket_gets_429_with_retry_after(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_principal_burst=3,
        rate_limit_principal_per_second=TRICKLE,
    )
    # The login itself is unauthenticated and is not charged.
    headers = auth_headers(client, "viewer")
    before = _limited(rate_limit.SCOPE_USER)

    for _ in range(3):
        assert client.get("/api/auth/me", headers=headers).status_code == 200
    refused = client.get("/api/auth/me", headers=headers)

    assert refused.status_code == 429, refused.text
    retry_after = int(refused.headers["Retry-After"])
    # One token at 0.001/s is due in ~1000 s; the header says so rather than a
    # constant, which is what makes it something a client can act on.
    assert 900 <= retry_after <= 1000
    assert _limited(rate_limit.SCOPE_USER) == before + 1


def test_buckets_are_per_principal(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_principal_burst=2,
        rate_limit_principal_per_second=TRICKLE,
    )
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    for _ in range(2):
        assert client.get("/api/auth/me", headers=viewer).status_code == 200
    assert client.get("/api/auth/me", headers=viewer).status_code == 429

    # Somebody else's loop is not this account's problem.
    assert client.get("/api/auth/me", headers=operator).status_code == 200


def test_tenant_bucket_is_shared_by_its_users_but_not_by_the_platform_admin(
    tmp_path, monkeypatch
):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_tenant_burst=3,
        rate_limit_tenant_per_second=TRICKLE,
    )
    viewer = auth_headers(client, "viewer")
    operator = auth_headers(client, "operator")
    admin = auth_headers(client, "admin")

    assert client.get("/api/endpoint/devices", headers=viewer).status_code == 200
    assert client.get("/api/endpoint/devices", headers=viewer).status_code == 200
    assert client.get("/api/endpoint/devices", headers=operator).status_code == 200
    # The fourth request of the tenant, from a user whose own bucket is full.
    refused = client.get("/api/endpoint/devices", headers=operator)
    assert refused.status_code == 429, refused.text
    assert int(refused.headers["Retry-After"]) >= 1

    # The platform admin acts for the installation and is not charged to the
    # tenant it happens to be looking at.
    assert client.get("/api/endpoint/devices", headers=admin).status_code == 200


def test_a_route_with_several_tenant_gates_charges_the_tenant_once(tmp_path, monkeypatch):
    """``resolve_tenant_principal`` runs once per gate a route declares.

    No route in the tree declares two today, so the test mounts one: two rank
    gates are two distinct dependencies, which FastAPI does not cache together.
    """
    from fastapi import Depends

    from api import auth

    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_tenant_burst=2,
        rate_limit_tenant_per_second=TRICKLE,
    )

    @client.app.get("/api/test-only/two-gates")
    def _two_gates(
        _viewer=Depends(auth.require_tenant(auth.Role.viewer)),
        _operator=Depends(auth.require_tenant(auth.Role.operator)),
    ) -> dict:
        return {}

    resolved = 0
    real_resolve = auth.resolve_tenant_principal

    def _counting_resolve(*args, **kwargs):
        nonlocal resolved
        resolved += 1
        return real_resolve(*args, **kwargs)

    monkeypatch.setattr(auth, "resolve_tenant_principal", _counting_resolve)
    operator = auth_headers(client, "operator")

    assert client.get("/api/test-only/two-gates", headers=operator).status_code == 200
    # The premise: both gates resolved the tenant for this one request.
    assert resolved == 2
    assert client.get("/api/test-only/two-gates", headers=operator).status_code == 200
    assert client.get("/api/test-only/two-gates", headers=operator).status_code == 429


def test_service_tokens_are_charged_to_their_own_bucket(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_principal_burst=2,
        rate_limit_principal_per_second=TRICKLE,
    )
    admin = auth_headers(client, "admin")
    created = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["runs:read"], "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    token = bearer(created.json()["token"])
    before = _limited(rate_limit.SCOPE_SERVICE_TOKEN)

    for _ in range(2):
        assert client.get("/api/runs", headers=token).status_code == 200
    refused = client.get("/api/runs", headers=token)

    assert refused.status_code == 429, refused.text
    assert _limited(rate_limit.SCOPE_SERVICE_TOKEN) == before + 1


def test_probes_and_metrics_are_never_limited(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_principal_burst=1,
        rate_limit_principal_per_second=TRICKLE,
        rate_limit_tenant_burst=1,
        rate_limit_tenant_per_second=TRICKLE,
        rate_limit_agent_burst=1,
        rate_limit_agent_per_second=TRICKLE,
    )
    for _ in range(5):
        for path in ("/livez", "/readyz", "/api/health", "/metrics"):
            response = client.get(path)
            assert response.status_code in (200, 503), (path, response.status_code)


def test_the_login_limiter_still_answers_for_failed_logins(tmp_path, monkeypatch):
    """The two limiters count different things and neither replaces the other."""
    client = configured_client(
        tmp_path, monkeypatch, login_rate_limit_max_failures=2
    )
    for _ in range(2):
        failed = client.post("/api/auth/login", json={"username": "viewer", "password": "nope"})
        assert failed.status_code == 401
    locked = client.post("/api/auth/login", json={"username": "viewer", "password": "nope"})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_disabled_limiter_charges_nothing(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_enabled=False,
        rate_limit_principal_burst=1,
        rate_limit_principal_per_second=TRICKLE,
    )
    headers = auth_headers(client, "viewer")
    for _ in range(5):
        assert client.get("/api/auth/me", headers=headers).status_code == 200


def test_unreachable_buckets_fail_open_with_a_warning(tmp_path, monkeypatch, caplog):
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_principal_burst=1,
        rate_limit_principal_per_second=TRICKLE,
    )
    headers = auth_headers(client, "viewer")

    def _down(self, key, limit):
        raise OperationalError("SELECT 1", {}, Exception("connection refused"))

    monkeypatch.setattr(rate_limit.DatabaseBuckets, "take", _down)
    monkeypatch.setattr(rate_limit, "_last_warning", 0.0)
    with caplog.at_level(logging.WARNING, logger="api.services.rate_limit"):
        for _ in range(3):
            assert client.get("/api/auth/me", headers=headers).status_code == 200
    warnings = [r for r in caplog.records if "rate limit buckets unavailable" in r.getMessage()]
    # Once, not per request: an outage is one event, not a log flood.
    assert len(warnings) == 1


def _memory_limiter(monkeypatch, **overrides) -> None:
    """The service configured with ``overrides``, its buckets in process memory."""
    # Recorded first, so the test leaves the module as it found it.
    monkeypatch.setattr(rate_limit, "_settings", rate_limit._settings)
    monkeypatch.setattr(rate_limit, "_buckets", rate_limit._buckets)
    rate_limit.configure(Settings(postgres_url=POSTGRES_URL, **overrides))
    monkeypatch.setattr(rate_limit, "_buckets", rate_limit.MemoryBuckets())


def test_refusals_are_logged_once_a_minute_per_principal(monkeypatch, caplog):
    """A client looping on an empty bucket is one line, not one per request."""
    _memory_limiter(
        monkeypatch, rate_limit_principal_burst=1, rate_limit_principal_per_second=TRICKLE
    )
    with caplog.at_level(logging.INFO, logger="api.services.rate_limit"):
        for key in ("loop", "other"):
            rate_limit.charge(rate_limit.SCOPE_USER, key)
            for _ in range(50):
                with pytest.raises(rate_limit.RateLimited):
                    rate_limit.charge(rate_limit.SCOPE_USER, key)
    lines = [r.getMessage() for r in caplog.records if "rate limited" in r.getMessage()]
    # One per principal: the second offender is still named while the first
    # one's line is being held back.
    assert len(lines) == 2, lines
    assert "loop" in lines[0] and "other" in lines[1]


def test_a_failed_prune_does_not_turn_a_refusal_into_a_pass(monkeypatch):
    """The decision is made before the prune, and a prune error cannot undo it."""
    _memory_limiter(
        monkeypatch, rate_limit_principal_burst=1, rate_limit_principal_per_second=TRICKLE
    )

    def _broken(self, horizon_seconds):
        raise OperationalError("DELETE", {}, Exception("lock timeout"))

    monkeypatch.setattr(rate_limit.MemoryBuckets, "prune", _broken)
    monkeypatch.setattr(rate_limit, "_last_prune", 0.0)
    rate_limit.charge(rate_limit.SCOPE_USER, "pruned")
    # Due again, so the prune runs — and fails — right after this refusal.
    monkeypatch.setattr(rate_limit, "_last_prune", 0.0)
    with pytest.raises(rate_limit.RateLimited):
        rate_limit.charge(rate_limit.SCOPE_USER, "pruned")


# --------------------------------------------------------------------------
# 2. One bucket, however many replicas spend from it.
# --------------------------------------------------------------------------


@pytest.fixture
def replica():
    """Build limiters on engines of their own, as separate API processes have.

    Not the application's engine singleton: two limiters sharing one pool
    would prove only that a process agrees with itself.
    """
    engines = []

    def _build() -> rate_limit.DatabaseBuckets:
        engine = create_engine(POSTGRES_URL, pool_size=8, future=True)
        engines.append(engine)
        return rate_limit.DatabaseBuckets(sessionmaker(bind=engine, future=True))

    yield _build
    for engine in engines:
        engine.dispose()


def test_two_replicas_spend_from_one_bucket(replica):
    first, second = replica(), replica()
    first.clear()
    limit = rate_limit.Limit(per_second=TRICKLE, burst=4)

    assert first.take("user:shared", limit) is None
    assert second.take("user:shared", limit) is None
    assert first.take("user:shared", limit) is None
    assert second.take("user:shared", limit) is None
    # Four tokens, spent two and two: neither replica has any left, and both
    # agree on how long until one is due.
    wait_first = first.take("user:shared", limit)
    wait_second = second.take("user:shared", limit)
    assert wait_first is not None and wait_second is not None
    assert wait_first > 900 and wait_second > 900
    first.clear()


def test_concurrent_replicas_grant_exactly_the_burst(replica):
    """No read-modify-write race: the row lock serialises the charges."""
    replicas = [replica() for _ in range(2)]
    replicas[0].clear()
    limit = rate_limit.Limit(per_second=TRICKLE, burst=25)
    granted: list[bool] = []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def _hammer(buckets: rate_limit.DatabaseBuckets) -> None:
        start.wait()
        for _ in range(10):
            ok = buckets.take("tenant:contended", limit) is None
            with lock:
                granted.append(ok)

    threads = [threading.Thread(target=_hammer, args=(replicas[i % 2],)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert len(granted) == 80
    assert granted.count(True) == 25
    replicas[0].clear()


def test_a_refused_request_costs_nothing(replica):
    """Hammering an empty bucket must not push its next token further away."""
    buckets = replica()
    buckets.clear()
    limit = rate_limit.Limit(per_second=TRICKLE, burst=1)
    assert buckets.take("user:hammer", limit) is None
    first_wait = buckets.take("user:hammer", limit)
    for _ in range(20):
        later = buckets.take("user:hammer", limit)
    assert first_wait is not None and later is not None
    assert later <= first_wait
    buckets.clear()


def test_a_charge_never_rewinds_the_bucket_clock(replica):
    """A replica whose statement started before a peer's commit carries an
    older ``statement_timestamp()``; writing it back would credit the interval
    between the two a second time on the next charge."""
    buckets = replica()
    buckets.clear()
    engine = create_engine(POSTGRES_URL, future=True)
    try:
        with engine.begin() as connection:
            # As a peer left it: tokens to spare, its clock 100 s ahead of ours.
            connection.execute(
                text(
                    "INSERT INTO rate_limit_buckets (bucket_key, tokens, refilled_at)"
                    " VALUES ('user:ahead', 5, EXTRACT(EPOCH FROM now()) + 100)"
                )
            )
        assert buckets.take("user:ahead", rate_limit.Limit(per_second=1.0, burst=10)) is None
        with engine.connect() as connection:
            ahead = connection.execute(
                text(
                    "SELECT refilled_at - EXTRACT(EPOCH FROM now()) FROM rate_limit_buckets"
                    " WHERE bucket_key = 'user:ahead'"
                )
            ).scalar_one()
        assert ahead > 90
    finally:
        engine.dispose()
        buckets.clear()


def test_prune_keeps_buckets_that_are_still_refilling(replica):
    buckets = replica()
    buckets.clear()
    limit = rate_limit.Limit(per_second=TRICKLE, burst=1)
    assert buckets.take("user:recent", limit) is None
    buckets.prune(horizon_seconds=3600)
    assert buckets.take("user:recent", limit) is not None
    buckets.prune(horizon_seconds=-1)
    # Gone, so full again: only safe past the refill time, which is why the
    # service raises the horizon to the slowest configured refill.
    assert buckets.take("user:recent", limit) is None
    buckets.clear()


def test_prune_horizon_covers_the_slowest_refill():
    settings = Settings(rate_limit_tenant_per_second=0.1, rate_limit_tenant_burst=2000)
    assert rate_limit._prune_horizon(settings) == pytest.approx(20000)


def test_memory_fallback_refills_and_is_not_shared():
    """The SQLite fallback's honest limits: per process, from its own clock."""
    now = [0.0]
    one, other = rate_limit.MemoryBuckets(clock=lambda: now[0]), rate_limit.MemoryBuckets(
        clock=lambda: now[0]
    )
    limit = rate_limit.Limit(per_second=1.0, burst=2)
    assert one.take("k", limit) is None
    assert one.take("k", limit) is None
    assert one.take("k", limit) == pytest.approx(1.0)
    # A second process has a bucket of its own: this is the caveat the docs
    # state, not a property to rely on.
    assert other.take("k", limit) is None
    now[0] = 1.0
    assert one.take("k", limit) is None


# --------------------------------------------------------------------------
# 3. The fleet is not throttled by the defaults.
# --------------------------------------------------------------------------


def _idle_sensor_calls(monkeypatch, tmp_path, *, poll_interval: float, seconds: float) -> list[float]:
    """When an idle sensor calls the API, taken from ``agent/worker.py``'s own loop.

    Not a cadence written down here: the loop is run against a fake client on
    a fake clock, so a change to what it sends per iteration — a heartbeat on
    every poll, not every 60 s, is what it does today — moves these numbers.
    HTTP claim mode, which is the busier one: under NATS the claim is a pull.
    """
    from agent import worker

    clock = [0.0]
    calls: list[float] = []

    class _Client:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs) -> dict:
            # Once per process, not part of the cadence.
            return {"agent_id": "sensor", "hostname": "sensor", "tenant_id": "default"}

        def heartbeat(self, agent_id: str, **kwargs) -> dict:
            if clock[0] >= seconds:
                raise KeyboardInterrupt
            calls.append(clock[0])
            return {"agent_id": agent_id}

        def claim(self, agent_id: str, **kwargs) -> None:
            calls.append(clock[0])
            return None

    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="static-token",
        timeout=1.0,
        provisioning_key="",
        jwt_refresh_seconds=1800,
        agent_id="sensor",
        hostname="sensor",
        label=None,
        nats_url="",
        poll_interval=poll_interval,
        config="scanner/config/default.yaml",
        output_dir=str(tmp_path / "agent-out"),
        scan_timeout=1.0,
    )
    with monkeypatch.context() as patch:
        patch.setattr(worker, "AgentClient", _Client)
        patch.setattr(worker.time, "sleep", lambda delay: clock.__setitem__(0, clock[0] + delay))
        patch.setattr(worker.time, "time", lambda: clock[0])
        assert worker.run_loop(args) == 0
    return calls


def _default_poll_interval(monkeypatch) -> float:
    from agent import worker

    monkeypatch.delenv("OCTO_AGENT_POLL_INTERVAL", raising=False)
    return float(worker.build_parser().get_default("poll_interval"))


def test_one_sensor_has_headroom_even_at_a_one_second_poll(monkeypatch, tmp_path):
    """The agent bucket refills at least twice as fast as the busiest sensor.

    At ``OCTO_AGENT_POLL_INTERVAL=1`` an idle sensor makes a heartbeat and a
    claim every second. A bucket refilling at exactly that rate is empty for
    good once its burst is gone, and the next busy heartbeat or retry is a 429.
    """
    calls = _idle_sensor_calls(monkeypatch, tmp_path, poll_interval=1.0, seconds=600)
    observed = len(calls) / 600
    assert observed == pytest.approx(2.0, rel=0.01)
    limit = rate_limit.principal_limit(Settings(), rate_limit.SCOPE_AGENT)
    assert limit.per_second >= 2 * observed


def test_default_agent_bucket_carries_a_day_of_sensor_and_lariska_traffic(monkeypatch, tmp_path):
    """A sensor at the shipped poll interval and Lariska, on the shipped limit.

    Lariska heartbeats every 60 s and submits its inventory hourly; the
    sensor's cadence is its loop's. After an
    outage both come back with a backlog of retries at once, which is what the
    burst is for.
    """
    poll = _default_poll_interval(monkeypatch)
    sensor = _idle_sensor_calls(monkeypatch, tmp_path, poll_interval=poll, seconds=3600)
    settings = Settings()
    limit = rate_limit.principal_limit(settings, rate_limit.SCOPE_AGENT)
    now = [0.0]
    buckets = rate_limit.MemoryBuckets(clock=lambda: now[0])

    refused = 0
    for hour in range(24):
        for at in sensor:
            now[0] = hour * 3600 + at
            refused += buckets.take("agent:sensor", limit) is not None
        for second in range(0, 3600, 60):
            now[0] = hour * 3600 + second
            due = 1 + (second == 0)
            for _ in range(due):
                refused += buckets.take("agent:lariska", limit) is not None
    assert refused == 0

    # Coming back from an outage: a minute of a 1 s poll interval, at once.
    now[0] += 1
    assert all(buckets.take("agent:sensor", limit) is None for _ in range(60))


@pytest.mark.parametrize("poll", [None, 1.0], ids=["default-poll", "one-second-poll"])
def test_a_legacy_fleet_behind_one_address_is_not_throttled_by_the_defaults(
    monkeypatch, tmp_path, poll
):
    """Ten shared-token sensors behind one ingress or NAT, for an hour.

    The shared token names no agent, so its bucket is the source address —
    and without ``OCTO_TRUSTED_PROXIES`` every sensor behind an ingress has the
    ingress's. Each charge here goes through the real authentication path;
    only the bucket's clock is fake. At the default poll interval ten sensors
    fit even one sensor's bucket; at a 1 s poll they need the fleet-sized one.
    """
    from fastapi import HTTPException
    from fastapi.security import HTTPAuthorizationCredentials
    from starlette.requests import Request

    from api import auth
    from api.db import tenant_scope
    from tests.conftest import make_settings

    settings = make_settings(tmp_path, job_execution_mode="agent")
    poll = poll or _default_poll_interval(monkeypatch)
    one_sensor = _idle_sensor_calls(monkeypatch, tmp_path, poll_interval=poll, seconds=3600)
    fleet = sorted(
        (at + index * poll / 10, index) for index in range(10) for at in one_sensor
    )
    monkeypatch.setattr(rate_limit, "_settings", rate_limit._settings)
    monkeypatch.setattr(rate_limit, "_buckets", rate_limit._buckets)
    rate_limit.configure(settings)
    now = [0.0]
    monkeypatch.setattr(rate_limit, "_buckets", rate_limit.MemoryBuckets(clock=lambda: now[0]))
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=settings.agent_token)

    refused = 0
    for at, index in fleet:
        now[0] = at
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/agent/heartbeat",
                "query_string": b"",
                "headers": [],
                # One address, as the API sees it behind an ingress.
                "client": ("10.0.0.1", 40000 + index),
            }
        )
        scope_token = tenant_scope.bind_request()
        try:
            auth.require_agent(request, credentials, settings)
        except HTTPException as exc:
            assert exc.status_code == 429
            refused += 1
        finally:
            tenant_scope.reset_request(scope_token)
    # A heartbeat and a claim per poll, per sensor, for the hour.
    assert len(fleet) == 10 * 2 * round(3600 / poll)
    assert refused == 0


def test_agents_are_not_charged_to_the_tenant_bucket(tmp_path, monkeypatch):
    """A fleet larger than the tenant bucket still heartbeats."""
    client = configured_client(
        tmp_path,
        monkeypatch,
        job_execution_mode="agent",
        agent_token="",
        rate_limit_tenant_burst=1,
        rate_limit_tenant_per_second=TRICKLE,
    )
    admin = login(client, "admin")
    key = client.post(
        "/api/tenants/default/provisioning-keys", headers=bearer(admin), json={"label": "fleet"}
    )
    assert key.status_code == 201, key.text
    provisioning_key = key.json()["key"]

    for index in range(20):
        agent_id = f"fleet-{index:02d}"
        token = client.post(
            "/api/auth/agent/token",
            json={"provisioning_key": provisioning_key, "agent_id": agent_id},
        ).json()["access_token"]
        registered = client.post(
            "/api/agent/register", headers=bearer(token), json={"hostname": agent_id}
        )
        assert registered.status_code == 200, registered.text
        for _ in range(3):
            beat = client.post(
                "/api/agent/heartbeat", headers=bearer(token), json={"agent_id": agent_id}
            )
            assert beat.status_code == 200, beat.text


def test_one_agent_over_its_own_bucket_gets_429(tmp_path, monkeypatch):
    client = configured_client(
        tmp_path,
        monkeypatch,
        job_execution_mode="agent",
        agent_token="",
        rate_limit_agent_burst=3,
        rate_limit_agent_per_second=TRICKLE,
    )
    admin = login(client, "admin")
    provisioning_key = client.post(
        "/api/tenants/default/provisioning-keys", headers=bearer(admin), json={"label": "one"}
    ).json()["key"]
    token = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": provisioning_key, "agent_id": "noisy"},
    ).json()["access_token"]
    sibling = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": provisioning_key, "agent_id": "quiet"},
    ).json()["access_token"]
    before = _limited(rate_limit.SCOPE_AGENT)

    assert client.post(
        "/api/agent/register", headers=bearer(token), json={"hostname": "noisy"}
    ).status_code == 200
    for _ in range(2):
        assert client.post(
            "/api/agent/heartbeat", headers=bearer(token), json={"agent_id": "noisy"}
        ).status_code == 200
    refused = client.post("/api/agent/heartbeat", headers=bearer(token), json={"agent_id": "noisy"})
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1
    assert _limited(rate_limit.SCOPE_AGENT) == before + 1

    # The agent next to it is unaffected.
    assert client.post(
        "/api/agent/register", headers=bearer(sibling), json={"hostname": "quiet"}
    ).status_code == 200


def test_a_results_upload_is_not_charged_to_the_agent_bucket(tmp_path, monkeypatch):
    """The result of a whole scan is not a request to throttle.

    It arrives once per claimed job and is fenced by the claim's attempt, so a
    429 there protects nothing — and refusing it loses the scan, because the
    sensor's retries are bounded and the run is swept once they give up.
    """
    client = configured_client(
        tmp_path,
        monkeypatch,
        job_execution_mode="agent",
        agent_token="",
        rate_limit_agent_burst=2,
        rate_limit_agent_per_second=TRICKLE,
    )
    admin = login(client, "admin")
    provisioning_key = client.post(
        "/api/tenants/default/provisioning-keys", headers=bearer(admin), json={"label": "one"}
    ).json()["key"]
    token = bearer(
        client.post(
            "/api/auth/agent/token",
            json={"provisioning_key": provisioning_key, "agent_id": "busy"},
        ).json()["access_token"]
    )
    assert client.post("/api/agent/register", headers=token, json={"hostname": "busy"}).status_code == 200
    assert client.post("/api/agent/heartbeat", headers=token, json={"agent_id": "busy"}).status_code == 200
    assert client.post("/api/agent/heartbeat", headers=token, json={"agent_id": "busy"}).status_code == 429

    uploaded = client.post(
        "/api/agent/jobs/no-such-job/results",
        headers=token,
        data={"agent_id": "busy", "exit_code": "0"},
        files={"archive": ("run.tar.gz", b"", "application/gzip")},
    )
    # Past the limiter, to the route's own answer about a job it never issued.
    assert uploaded.status_code == 404, uploaded.text


def test_legacy_shared_token_is_charged_per_address(tmp_path, monkeypatch):
    """One shared token is not one principal: each host gets its own bucket."""
    from tests.conftest import TEST_AGENT_TOKEN, make_settings, reset_service_state

    from api.app import create_app

    settings = make_settings(
        tmp_path,
        job_execution_mode="agent",
        rate_limit_agent_burst=1,
        rate_limit_agent_per_second=TRICKLE,
        # One sensor's bucket per address, so the second request is over it.
        rate_limit_legacy_agents_per_address=1,
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    reset_service_state(settings)
    app = create_app()
    first = TestClient(app, client=("10.0.0.1", 40000))
    second = TestClient(app, client=("10.0.0.2", 40000))
    headers = bearer(TEST_AGENT_TOKEN)
    before = _limited(rate_limit.SCOPE_LEGACY_AGENT)

    assert first.post("/api/agent/register", headers=headers, json={"hostname": "a", "agent_id": "a"}).status_code == 200
    refused = first.post("/api/agent/heartbeat", headers=headers, json={"agent_id": "a"})
    assert refused.status_code == 429
    # Counted apart from the per-agent buckets: an operator seeing this climb
    # is looking at an address, not at one sensor.
    assert _limited(rate_limit.SCOPE_LEGACY_AGENT) == before + 1
    assert second.post("/api/agent/register", headers=headers, json={"hostname": "b", "agent_id": "b"}).status_code == 200


# --------------------------------------------------------------------------
# 4. The body cap, with and without Content-Length.
# --------------------------------------------------------------------------

ONE_MIB = 1024 * 1024
#: A route with no cap of its own, so the global one is what answers.
UNCAPPED = "/api/assets/bulk"


def _chunks(total: int, size: int = 64 * 1024):
    sent = 0
    while sent < total:
        piece = min(size, total - sent)
        sent += piece
        yield b" " * piece


def _big_target_list() -> str:
    """45 000 domains, a certificate-transparency export for one large customer."""
    return "\n".join(f"host{index:06d}.corp-example.com" for index in range(45_000))


def test_body_over_the_global_cap_is_refused_from_content_length(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")
    body = json.dumps({"asset_ids": ["x" * 40] * 60_000, "payload": {}})
    assert len(body) > 2 * ONE_MIB
    refused = client.post(
        UNCAPPED, headers={**headers, "Content-Type": "application/json"}, content=body
    )
    assert refused.status_code == 413, refused.text
    assert "exceeds limit 1048576" in refused.json()["detail"]


def test_an_oversized_content_length_is_refused_before_the_body_is_read():
    """Not read and then cut off: the app never runs and ``receive`` is never called."""
    import asyncio

    from api.middleware import RequestBodyLimitMiddleware

    reached: list[bool] = []
    pulled: list[bool] = []
    sent: list[dict] = []

    async def _app(scope, receive, send):
        reached.append(True)

    async def _receive():
        pulled.append(True)
        return {"type": "http.request", "body": b"x" * 10, "more_body": False}

    async def _send(message):
        sent.append(message)

    layer = RequestBodyLimitMiddleware(_app, max_bytes=100)
    scope = {"type": "http", "path": "/api/anything", "headers": [(b"content-length", b"1000")]}
    asyncio.run(layer(scope, _receive, _send))

    assert sent[0]["status"] == 413
    assert reached == [] and pulled == []


def test_chunked_body_without_content_length_is_cut_off_at_the_cap(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = {**auth_headers(client, "operator"), "Content-Type": "application/json"}

    refused = client.post(UNCAPPED, headers=headers, content=_chunks(2 * ONE_MIB))
    assert refused.request.headers.get("transfer-encoding") == "chunked"
    assert "content-length" not in refused.request.headers
    assert refused.status_code == 413, refused.text

    # Under the cap the same streamed body reaches the route, which then has
    # its own opinion of a JSON document made of spaces.
    accepted = client.post(UNCAPPED, headers=headers, content=_chunks(ONE_MIB // 2))
    assert accepted.status_code == 422, accepted.text


def test_chunked_upload_to_a_multipart_route_is_cut_off_too(tmp_path, monkeypatch):
    """The cap holds for routes that read with request.form(), not only JSON."""
    client = configured_client(tmp_path, monkeypatch, wordlist_max_body_bytes=ONE_MIB)
    headers = {
        **auth_headers(client, "operator"),
        "Content-Type": "multipart/form-data; boundary=xyz",
    }

    def _multipart():
        yield b'--xyz\r\nContent-Disposition: form-data; name="file"; filename="w.txt"\r\n\r\n'
        yield from _chunks(3 * ONE_MIB)

    refused = client.post("/api/wordlists", headers=headers, content=_multipart())
    assert refused.status_code == 413, refused.text


def test_a_large_target_list_is_accepted_by_scans_and_schedules(tmp_path, monkeypatch):
    """Launching a scan of a 1.3 MB target list was a 202 before the body cap."""
    client = configured_client(tmp_path, monkeypatch)
    headers = {**auth_headers(client, "operator"), "Content-Type": "application/json"}
    domains = _big_target_list()

    started = client.post(
        "/api/jobs", headers=headers, content=json.dumps({"domains": domains, "mode": "safe"})
    )
    assert len(started.request.content) > ONE_MIB
    assert started.status_code == 202, started.text[:300]

    scheduled = client.post(
        "/api/schedules",
        headers=headers,
        content=json.dumps({"name": "ct", "interval_seconds": 86400, "domains": domains}),
    )
    assert scheduled.status_code == 201, scheduled.text[:300]
    updated = client.patch(
        f"/api/schedules/{scheduled.json()['schedule_id']}",
        headers=headers,
        content=json.dumps({"domains": domains + "\nlast.corp-example.com"}),
    )
    assert updated.status_code == 200, updated.text[:300]


def test_a_target_list_over_its_own_cap_is_still_refused(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, target_list_max_body_bytes=2 * ONE_MIB)
    headers = {**auth_headers(client, "operator"), "Content-Type": "application/json"}
    body = json.dumps({"domains": _big_target_list() * 2})
    assert len(body) > 2 * ONE_MIB
    refused = client.post("/api/jobs", headers=headers, content=body)
    assert refused.status_code == 413, refused.text
    assert f"exceeds limit {2 * ONE_MIB}" in refused.json()["detail"]


def test_every_route_that_takes_a_target_list_has_the_target_list_cap():
    """The routes whose bodies carry targets or scope entries, under both prefixes."""
    from api.app import _body_limit_overrides
    from api.middleware import RequestBodyLimitMiddleware

    settings = Settings()
    layer = RequestBodyLimitMiddleware(
        None, max_bytes=settings.max_body_bytes, overrides=_body_limit_overrides(settings)
    )
    for path in (
        "/api/jobs",
        "/api/schedules",
        "/api/schedules/sched-1",
        "/api/maintenance-windows",
        "/api/maintenance-windows/mw-1",
        "/api/tenants/acme/scan-scope",
        "/api/v1/tenants/acme/scan-scope",
    ):
        assert layer.limit_for(path) == settings.target_list_max_body_bytes, path
    # ...and nothing next to them: a job's own sub-routes take no target list.
    assert layer.limit_for("/api/jobs/job-1/cancel") == settings.max_body_bytes
    assert layer.limit_for("/api/tenants/acme/members") == settings.max_body_bytes


def test_upload_routes_keep_their_own_larger_caps(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, wordlist_max_words=200_000)
    headers = auth_headers(client, "operator")
    words = "\n".join(f"w{index:07d}" for index in range(140_000)).encode()
    assert len(words) > ONE_MIB

    uploaded = client.post(
        "/api/wordlists",
        headers=headers,
        files={"file": ("big.txt", words, "text/plain")},
        data={"kind": "subdomain", "name": "big"},
    )
    # Stored: not the body layer's 413, and not the route's own 413 or 422.
    assert uploaded.status_code == 201, uploaded.text


def test_an_asset_import_escaped_past_one_mib_reaches_the_route(tmp_path, monkeypatch):
    """A Cyrillic CSV inside the import's own 2 MiB limit, sent by a client that
    escapes non-ASCII, is past the global cap on the wire (#350 x #320)."""
    client = configured_client(tmp_path, monkeypatch)
    rows = "\n".join(
        f"10.9.{index // 250}.{index % 250 + 1},Отдел эксплуатации {'Ж' * 60}"
        for index in range(3000)
    )
    content = "ip,business_unit\n" + rows
    assert len(content.encode("utf-8")) < 2 * ONE_MIB
    body = json.dumps({"format": "csv", "content": content, "dry_run": True})
    assert len(body) > ONE_MIB
    previewed = client.post(
        "/api/assets/import",
        headers={**auth_headers(client, "admin"), "Content-Type": "application/json"},
        content=body,
    )
    # The dry run itself, not the body layer's 413.
    assert previewed.status_code == 200, previewed.text[:300]


def test_a_compliance_import_escaped_past_one_mib_reaches_the_route(tmp_path, monkeypatch):
    """A Cyrillic catalogue well inside the definition limit, sent by a client
    that escapes non-ASCII, is six bytes on the wire per character."""
    client = configured_client(tmp_path, monkeypatch)
    document = {
        "framework_id": "custom-big-v1",
        "name": "Большой каталог",
        "version": "1",
        "scope_note": "Technical observations only.",
        "controls": [
            {
                "control_id": f"АНЗ.{index}",
                "title": "Известные уязвимости",
                "signals": ["unpatched_cve"],
                "rationale": "Ж" * 2000,
            }
            for index in range(100)
        ],
    }
    body = json.dumps({"format": "json", "content": json.dumps(document, ensure_ascii=False)})
    assert len(body) > ONE_MIB
    imported = client.post(
        "/api/compliance/frameworks/import",
        headers={**auth_headers(client, "admin"), "Content-Type": "application/json"},
        content=body,
    )
    assert imported.status_code == 201, imported.text[:300]


def test_an_endpoint_agent_build_past_one_mib_is_stored(tmp_path, monkeypatch):
    from api.services import endpoint_agent_mgmt

    client = configured_client(tmp_path, monkeypatch)
    endpoint_agent_mgmt.reset_for_tests()
    from tests.test_endpoint_agent_management import _envelope

    build = b"MZ" + b"\x00" * (ONE_MIB + ONE_MIB // 2)
    uploaded = client.post(
        "/api/endpoint/agent/releases",
        data={
            "version": "0.3.0",
            "platform": "x86_64-pc-windows-msvc",
            "signed_manifest": json.dumps(_envelope(build, version="0.3.0")),
        },
        files={"binary": ("lariska.exe", build, "application/octet-stream")},
        headers=auth_headers(client, "admin"),
    )
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["size_bytes"] == len(build)


def test_overrides_never_drop_below_the_global_cap():
    from api.app import _body_limit_overrides

    settings = Settings(max_body_bytes=512 * ONE_MIB, wordlist_max_body_bytes=ONE_MIB)
    assert all(limit >= 512 * ONE_MIB for _, limit in _body_limit_overrides(settings))
