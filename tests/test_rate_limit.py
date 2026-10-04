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

import json
import logging
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
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
    """``resolve_tenant_principal`` may run more than once per request."""
    client = configured_client(
        tmp_path,
        monkeypatch,
        rate_limit_tenant_burst=2,
        rate_limit_tenant_per_second=TRICKLE,
    )
    viewer = auth_headers(client, "viewer")
    assert client.get("/api/endpoint/devices", headers=viewer).status_code == 200
    assert client.get("/api/endpoint/devices", headers=viewer).status_code == 200
    assert client.get("/api/endpoint/devices", headers=viewer).status_code == 429


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


def test_default_agent_bucket_carries_a_day_of_sensor_and_lariska_traffic():
    """Simulated against the shipped defaults, on a fake clock.

    A sensor heartbeats every 60 s and polls the claim route every 5 s
    (agent/worker.py); Lariska heartbeats every 60 s and submits its inventory
    hourly. After an outage both come back with a backlog of retries at once,
    which is what the burst is for.
    """
    settings = Settings()
    limit = rate_limit.principal_limit(settings, rate_limit.SCOPE_AGENT)
    now = [0.0]
    buckets = rate_limit.MemoryBuckets(clock=lambda: now[0])

    refused = 0
    for second in range(24 * 3600):
        now[0] = float(second)
        due = (second % 60 == 0) + (second % 5 == 0) + (second % 3600 == 0)
        for _ in range(due):
            refused += buckets.take("agent:sensor", limit) is not None
    assert refused == 0

    # Coming back from an outage: a minute of a 1 s poll interval, at once.
    now[0] += 1
    assert all(buckets.take("agent:sensor", limit) is None for _ in range(60))


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


def test_legacy_shared_token_is_charged_per_address(tmp_path, monkeypatch):
    """One shared token is not one principal: each host gets its own bucket."""
    from tests.conftest import TEST_AGENT_TOKEN, make_settings, reset_service_state

    from api.app import create_app

    settings = make_settings(
        tmp_path,
        job_execution_mode="agent",
        rate_limit_agent_burst=1,
        rate_limit_agent_per_second=TRICKLE,
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

    assert first.post("/api/agent/register", headers=headers, json={"hostname": "a", "agent_id": "a"}).status_code == 200
    assert first.post("/api/agent/heartbeat", headers=headers, json={"agent_id": "a"}).status_code == 429
    assert second.post("/api/agent/register", headers=headers, json={"hostname": "b", "agent_id": "b"}).status_code == 200


# --------------------------------------------------------------------------
# 4. The body cap, with and without Content-Length.
# --------------------------------------------------------------------------

ONE_MIB = 1024 * 1024


def _chunks(total: int, size: int = 64 * 1024):
    sent = 0
    while sent < total:
        piece = min(size, total - sent)
        sent += piece
        yield b" " * piece


def test_body_over_the_global_cap_is_refused_from_content_length(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")
    body = json.dumps({"ranges": "x" * (2 * ONE_MIB)})
    refused = client.post(
        "/api/jobs", headers={**headers, "Content-Type": "application/json"}, content=body
    )
    assert refused.status_code == 413, refused.text
    assert "exceeds limit 1048576" in refused.json()["detail"]


def test_chunked_body_without_content_length_is_cut_off_at_the_cap(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = {**auth_headers(client, "operator"), "Content-Type": "application/json"}

    refused = client.post("/api/jobs", headers=headers, content=_chunks(2 * ONE_MIB))
    assert refused.request.headers.get("transfer-encoding") == "chunked"
    assert "content-length" not in refused.request.headers
    assert refused.status_code == 413, refused.text

    # Under the cap the same streamed body reaches the route, which then has
    # its own opinion of a JSON document made of spaces.
    accepted = client.post("/api/jobs", headers=headers, content=_chunks(ONE_MIB // 2))
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


def test_upload_routes_keep_their_own_larger_caps(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "operator")
    words = "\n".join(f"w{index:07d}" for index in range(140_000)).encode()
    assert len(words) > ONE_MIB

    uploaded = client.post(
        "/api/wordlists",
        headers=headers,
        files={"file": ("big.txt", words, "text/plain")},
        data={"kind": "subdomain", "name": "big"},
    )
    # Past the body layer: what answers is the route's own word-count check.
    assert uploaded.status_code != 413, uploaded.text


def test_overrides_never_drop_below_the_global_cap():
    from api.app import _body_limit_overrides

    settings = Settings(max_body_bytes=512 * ONE_MIB, wordlist_max_body_bytes=ONE_MIB)
    assert all(limit >= 512 * ONE_MIB for _, limit in _body_limit_overrides(settings))
