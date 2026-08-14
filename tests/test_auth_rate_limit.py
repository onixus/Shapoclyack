"""Login brute-force protection and the auth audit trail (#157).

The acceptance criteria from the issue, one test each: a series of wrong
passwords locks further attempts and leaves a record; the lock holds across API
replicas; the right password works again once the window passes, with no
operator involved; and a locked response does not say whether the account
exists.
"""

from __future__ import annotations

import time
from pathlib import Path

from tests.conftest import (
    TEST_USERS,
    auth_headers,
    make_settings,
    reset_service_state,
    requires_postgres,
)

pytestmark = requires_postgres

WRONG = "definitely-not-the-password"


def _client(tmp_path: Path, monkeypatch, *, host: str = "10.1.1.1", **overrides):
    """A client whose requests come from ``host``.

    Built here rather than via ``configured_client`` because these tests turn on
    the source address: the limiter keys on it, so two "different clients" have
    to actually differ in it.
    """
    from fastapi.testclient import TestClient

    from api.app import create_app

    settings = make_settings(tmp_path, **overrides)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("api.auth.load_settings", lambda: settings)
    monkeypatch.setattr("api.app.get_settings", lambda: settings)
    reset_service_state(settings)
    return TestClient(create_app(), client=(host, 40000))


def _fail(client, username: str = "viewer", password: str = WRONG):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def test_repeated_failures_lock_the_pair_and_leave_a_record(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=3)

    for _ in range(3):
        assert _fail(client).status_code == 401

    locked = _fail(client)
    assert locked.status_code == 429
    # Retry-After is what tells an honest client when to come back; without it
    # the only strategy left is to keep trying, which is the traffic the limit
    # exists to stop.
    assert int(locked.headers["Retry-After"]) > 0

    events = client.get(
        "/api/auth/events", headers=auth_headers(client, "admin"), params={"limit": 50}
    )
    assert events.status_code == 200
    outcomes = [e["outcome"] for e in events.json()["items"]]
    assert outcomes.count("failure") == 3
    assert outcomes.count("locked") == 1
    reasons = {e["reason"] for e in events.json()["items"] if e["outcome"] == "locked"}
    assert reasons == {"rate_limited_user_ip"}


def test_correct_password_is_refused_while_the_window_is_open(tmp_path, monkeypatch):
    """The lock is on the attempt, not on the credentials: a right password
    arriving mid-lockout is exactly what a successful guess looks like."""
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=2)

    for _ in range(2):
        _fail(client)

    blocked = _fail(client, password=TEST_USERS["viewer"])
    assert blocked.status_code == 429


def test_window_decays_without_operator_intervention(tmp_path, monkeypatch):
    """No unlock endpoint, no admin action — the counted failures simply age
    out. A lock an attacker could make permanent by failing on purpose would be
    a denial of service against a known username."""
    client = _client(
        tmp_path,
        monkeypatch,
        login_rate_limit_max_failures=2,
        login_rate_limit_window_seconds=1,
    )

    for _ in range(2):
        _fail(client)
    assert _fail(client).status_code == 429

    time.sleep(1.2)
    ok = client.post(
        "/api/auth/login", json={"username": "viewer", "password": TEST_USERS["viewer"]}
    )
    assert ok.status_code == 200


def test_lock_is_shared_by_every_replica(tmp_path, monkeypatch):
    """The counter is a table, not a process. Two apps over one database are
    the two API replicas ROADMAP P1.6 made legal to run."""
    from fastapi.testclient import TestClient

    from api.app import create_app

    replica_a = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=3)
    # Same settings, same database, second process — and crucially the same
    # source address, since that is half the limiter's key.
    replica_b = TestClient(create_app(), client=("10.1.1.1", 40001))

    assert _fail(replica_a).status_code == 401
    assert _fail(replica_b).status_code == 401
    assert _fail(replica_a).status_code == 401

    assert _fail(replica_b).status_code == 429


def test_locked_response_does_not_reveal_whether_the_account_exists(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=2)

    for username in ("viewer", "no-such-user"):
        for _ in range(2):
            _fail(client, username=username)

    real = _fail(client, username="viewer")
    fake = _fail(client, username="no-such-user")
    assert real.status_code == fake.status_code == 429
    assert real.json() == fake.json()


def test_a_second_address_is_not_locked_by_the_first(tmp_path, monkeypatch):
    """The pair is the key. Locking every source of a username would let one
    attacker lock the account's real owner out."""
    from fastapi.testclient import TestClient

    from api.app import create_app

    first = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=2)
    for _ in range(2):
        _fail(first)
    assert _fail(first).status_code == 429

    elsewhere = TestClient(create_app(), client=("198.51.100.9", 40002))
    ok = elsewhere.post(
        "/api/auth/login", json={"username": "viewer", "password": TEST_USERS["viewer"]}
    )
    assert ok.status_code == 200


def test_one_address_walking_a_username_list_is_capped(tmp_path, monkeypatch):
    """The per-pair limit alone never trips for an attacker who changes the
    username every attempt, which is what credential stuffing looks like."""
    client = _client(
        tmp_path,
        monkeypatch,
        login_rate_limit_max_failures=5,
        login_rate_limit_ip_max_failures=4,
    )
    # Taken before the address is capped: the per-IP limit applies to every
    # username from that address, the admin's included. That is the intended
    # (and costly) property, which is why the IP limit is an order of magnitude
    # looser than the per-account one.
    headers = auth_headers(client, "admin")

    for index in range(4):
        assert _fail(client, username=f"candidate-{index}").status_code == 401

    refused = _fail(client, username="candidate-99")
    assert refused.status_code == 429

    events = client.get(
        "/api/auth/events",
        headers=headers,
        params={"outcome": "locked"},
    )
    assert [e["reason"] for e in events.json()["items"]] == ["rate_limited_ip"]


def test_forwarded_for_is_ignored_unless_the_peer_is_a_trusted_proxy(tmp_path, monkeypatch):
    """Otherwise the limit is one attempt per header value the client invents."""
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=2)

    for index in range(2):
        _fail(client)
        assert client.post(
            "/api/auth/login",
            json={"username": "viewer", "password": WRONG},
            headers={"X-Forwarded-For": f"203.0.113.{index}"},
        ).status_code in (401, 429)

    assert _fail(client).status_code == 429


def test_trusted_proxy_makes_the_forwarded_client_the_limiter_key(tmp_path, monkeypatch):
    client = _client(
        tmp_path,
        monkeypatch,
        host="10.0.0.1",
        trusted_proxies=["10.0.0.0/8"],
        login_rate_limit_max_failures=2,
    )

    def attempt(source: str):
        return client.post(
            "/api/auth/login",
            json={"username": "viewer", "password": WRONG},
            headers={"X-Forwarded-For": source},
        )

    assert attempt("203.0.113.5").status_code == 401
    assert attempt("203.0.113.5").status_code == 401
    assert attempt("203.0.113.5").status_code == 429
    # A different real client behind the same proxy is unaffected.
    assert attempt("203.0.113.6").status_code == 401

    events = client.get(
        "/api/auth/events", headers=auth_headers(client, "admin"), params={"q": "203.0.113.6"}
    )
    assert events.json()["total"] == 1


def test_successful_login_is_recorded(tmp_path, monkeypatch):
    """'Someone guessed the admin password' has to look different from ordinary
    use somewhere, and this is the somewhere."""
    client = _client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")

    events = client.get("/api/auth/events", headers=headers, params={"outcome": "success"})
    items = events.json()["items"]
    assert [e["username"] for e in items] == ["admin"]
    assert items[0]["reason"] is None
    assert items[0]["client_ip"] == "10.1.1.1"


def test_repeated_locked_attempts_write_one_row_per_window(tmp_path, monkeypatch):
    """A locked-out client keeps trying, and each try is an unauthenticated
    write if recorded naively — the audit trail would be the amplification."""
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=1)

    _fail(client)
    for _ in range(10):
        assert _fail(client).status_code == 429

    events = client.get(
        "/api/auth/events", headers=auth_headers(client, "admin"), params={"outcome": "locked"}
    )
    assert events.json()["total"] == 1


def test_concurrent_guesses_cannot_outrun_the_counter(tmp_path, monkeypatch):
    """A parallel batch must not all pass a count taken before any of them was
    recorded — the check and the failure it produces are one operation."""
    import concurrent.futures

    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=3)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        statuses = [f.result().status_code for f in [pool.submit(_fail, client) for _ in range(12)]]

    # Three attempts reach the password check; every later one is refused,
    # whatever order the threads ran in.
    assert statuses.count(401) == 3
    assert statuses.count(429) == 9

    events = client.get(
        "/api/auth/events", headers=auth_headers(client, "admin"), params={"outcome": "failure"}
    )
    assert events.json()["total"] == 3


def test_failures_survive_a_retention_shorter_than_the_window(tmp_path, monkeypatch):
    """Retention and the limiter window are set independently; pruning must not
    delete failures the limiter still has to count."""
    client = _client(
        tmp_path,
        monkeypatch,
        login_rate_limit_max_failures=3,
        login_rate_limit_window_seconds=3600,
        # Shorter than the window, and short enough that "1 day ago" prunes.
        auth_event_retention_days=1,
    )
    for _ in range(3):
        _fail(client)
    # The next attempt runs a prune (first call in this process).
    assert _fail(client).status_code == 429
    assert _fail(client).status_code == 429


def test_events_are_admin_only(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    for role in ("viewer", "operator"):
        response = client.get("/api/auth/events", headers=auth_headers(client, role))
        assert response.status_code == 403
    assert client.get("/api/auth/events").status_code == 401


def test_events_are_newest_first_and_paginated(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=100)
    for index in range(5):
        _fail(client, username=f"user-{index}")
    headers = auth_headers(client, "admin")

    page = client.get("/api/auth/events", headers=headers, params={"limit": 2})
    body = page.json()
    assert body["total"] == 6  # five failures plus the admin login
    assert body["has_more"] is True
    assert [e["username"] for e in body["items"]] == ["admin", "user-4"]

    second = client.get("/api/auth/events", headers=headers, params={"limit": 2, "offset": 2})
    assert [e["username"] for e in second.json()["items"]] == ["user-3", "user-2"]


def test_metric_counts_attempts_by_outcome(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, login_rate_limit_max_failures=1)
    _fail(client)
    _fail(client)
    client.post("/api/auth/login", json={"username": "viewer", "password": TEST_USERS["viewer"]})

    body = client.get("/metrics").text
    assert 'octo_auth_attempts_total{outcome="failure"}' in body
    assert 'octo_auth_attempts_total{outcome="locked"}' in body
    assert 'octo_auth_attempts_total{outcome="success"}' in body


def test_limiter_can_be_switched_off(tmp_path, monkeypatch):
    """The audit trail is not the limiter: turning the limit off still records."""
    client = _client(
        tmp_path, monkeypatch, login_rate_limit_enabled=False, login_rate_limit_max_failures=1
    )
    for _ in range(4):
        assert _fail(client).status_code == 401

    events = client.get(
        "/api/auth/events", headers=auth_headers(client, "admin"), params={"outcome": "failure"}
    )
    assert events.json()["total"] == 4
