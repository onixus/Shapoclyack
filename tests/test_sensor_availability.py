"""A queued job nobody can run has to say so (#338 review).

With agent execution the Kubernetes default, three ordinary situations leave
the queue with no executor at all: the upgrade applied before the executor was
enrolled, a tenant other than the one the executor's key belongs to (an agent
only ever claims its own tenant's jobs), and the day the executor's
provisioning key expires. Before this, each of them looked exactly like a busy
queue: ``202``, ``queued``, and ``agent_group_unavailable`` false because that
flag only speaks for jobs addressed to a group.

``sensor_unavailable`` is its ungrouped counterpart, answered on read like the
group flag, and the fleet summary's ``scan_ready_agents`` is the number the
console's banners are drawn from.
"""

from __future__ import annotations

from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    login,
    requires_postgres,
)

pytestmark = requires_postgres

AGENT = {"Authorization": "Bearer test-agent-token"}


def _client(tmp_path, monkeypatch, **overrides):
    return configured_client(
        tmp_path, monkeypatch, **{"job_execution_mode": "agent", **overrides}
    )


def _start(client):
    response = client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "balanced", "ranges": "127.0.0.1\n", "domains": "\n"},
    )
    assert response.status_code == 202, response.text
    return response.json()


def _job(client, job_id: str) -> dict:
    return client.get(f"/api/jobs/{job_id}", headers=auth_headers(client, "operator")).json()


def _listed(client, job_id: str) -> dict:
    page = client.get("/api/jobs", headers=auth_headers(client, "operator")).json()
    rows = page["items"] if isinstance(page, dict) else page
    return next(row for row in rows if row["job_id"] == job_id)


def _register(client, hostname: str, **body) -> str:
    response = client.post(
        "/api/agent/register", headers=AGENT, json={"hostname": hostname, **body}
    )
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


def test_a_job_no_sensor_can_claim_says_so(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    started = _start(client)
    # On the start response too, so the launcher can say it at the moment the
    # operator is looking at it.
    assert started["sensor_unavailable"] is True
    assert _job(client, started["job_id"])["sensor_unavailable"] is True
    assert _listed(client, started["job_id"])["sensor_unavailable"] is True


def test_the_flag_clears_the_moment_a_sensor_is_online(tmp_path, monkeypatch):
    """Answered on read, never stored: the executor that enrolls a minute
    after the upgrade must not leave every job queued before it flagged."""
    client = _client(tmp_path, monkeypatch)
    started = _start(client)
    _register(client, "scanner-executor-0")
    assert _job(client, started["job_id"])["sensor_unavailable"] is False
    assert _listed(client, started["job_id"])["sensor_unavailable"] is False


def test_an_endpoint_agent_is_not_a_sensor(tmp_path, monkeypatch):
    """Endpoint agents report inventory and are refused scan jobs on claim."""
    client = _client(tmp_path, monkeypatch)
    started = _start(client)
    _register(client, "laptop-7", agent_kind="endpoint")
    assert _job(client, started["job_id"])["sensor_unavailable"] is True


def test_a_quarantined_sensor_is_not_a_sensor(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    started = _start(client)
    agent_id = _register(client, "scanner-executor-0")
    quarantined = client.patch(
        f"/api/agents/{agent_id}",
        headers=auth_headers(client, "admin"),
        json={"status": "quarantined", "reason": "wrong segment"},
    )
    assert quarantined.status_code == 200, quarantined.text
    assert _job(client, started["job_id"])["sensor_unavailable"] is True


def test_a_sensor_of_another_tenant_does_not_count(tmp_path, monkeypatch):
    """An agent claims only its own tenant's jobs, so the executor enrolled
    with the ``default`` key is no sensor for any other tenant's scans."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    created = client.post(
        "/api/tenants", headers=bearer(admin), json={"tenant_id": "acme", "name": "Acme"}
    )
    assert created.status_code in (200, 201), created.text
    key = client.post(
        "/api/tenants/acme/provisioning-keys", headers=bearer(admin), json={"label": "acme"}
    )
    assert key.status_code == 201, key.text
    token = client.post(
        "/api/auth/agent/token", json={"provisioning_key": key.json()["key"]}
    ).json()["access_token"]
    registered = client.post(
        "/api/agent/register", headers=bearer(token), json={"hostname": "acme-sensor"}
    )
    assert registered.status_code == 200, registered.text

    started = _start(client)  # the operator's tenant is ``default``
    assert _job(client, started["job_id"])["sensor_unavailable"] is True


def test_a_claimed_job_is_not_flagged(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    started = _start(client)
    agent_id = _register(client, "scanner-executor-0")
    claimed = client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=AGENT)
    assert claimed.status_code == 200, claimed.text
    assert _job(client, started["job_id"])["sensor_unavailable"] is False


def test_a_local_job_is_never_flagged(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, job_execution_mode="local")
    # The executor thread is not started: the test is about the job record,
    # and a real local scan would run the toolchain.
    from api.services import jobs as jobs_service
    from tests.test_jobs import _NoopThread

    monkeypatch.setattr(jobs_service.threading, "Thread", _NoopThread)
    started = _start(client)
    assert started["sensor_unavailable"] is False


def test_the_fleet_summary_counts_the_agents_that_can_take_a_scan(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    viewer = auth_headers(client, "viewer")

    def ready() -> int:
        summary = client.get("/api/agents/summary", headers=viewer)
        assert summary.status_code == 200, summary.text
        return summary.json()["scan_ready_agents"]

    assert ready() == 0
    _register(client, "laptop-7", agent_kind="endpoint")
    assert ready() == 0
    sensor = _register(client, "scanner-executor-0", capabilities=["scan_policy", "config_overlay.v1"])
    assert ready() == 1
    client.patch(
        f"/api/agents/{sensor}",
        headers=auth_headers(client, "admin"),
        json={"status": "quarantined", "reason": "wrong segment"},
    )
    assert ready() == 0


# ---------------------------------------------------------------------------
# Review round 2: a sensor that would be refused the job is no sensor for it
# ---------------------------------------------------------------------------

CURRENT = ["scan_policy", "config_overlay.v1"]


def _start_body(client, **body):
    response = client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "balanced", "ranges": "127.0.0.1\n", "domains": "\n", **body},
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_an_outdated_sensor_is_not_one_for_a_job_it_would_be_refused(tmp_path, monkeypatch):
    """API upgraded, sensors not yet: every console scan with an intent is
    refused on claim (426), and the job used to read as waiting for a busy
    sensor while the banner said one was ready."""
    client = _client(tmp_path, monkeypatch)
    _register(client, "old-sensor", capabilities=["scan_policy"])
    with_overlay = _start_body(client, intent="inventory")
    plain = _start_body(client)
    assert with_overlay["sensor_unavailable"] is True
    assert _job(client, with_overlay["job_id"])["sensor_unavailable"] is True
    assert _job(client, plain["job_id"])["sensor_unavailable"] is False
    summary = client.get("/api/agents/summary", headers=auth_headers(client, "viewer")).json()
    assert summary["online_agents"] == 1
    assert summary["scan_ready_agents"] == 0


def test_a_sensor_below_the_version_floor_is_not_a_sensor(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, agent_min_version="99.0")
    _register(client, "old-sensor", capabilities=CURRENT, version="0.3.2.1")
    started = _start_body(client)
    assert _job(client, started["job_id"])["sensor_unavailable"] is True


def test_a_platform_admin_is_told_about_the_tenant_they_are_in(tmp_path, monkeypatch):
    """Unscoped, the fleet summary counts every tenant's agents - right for
    the fleet tiles, wrong for "can a scan I start here run": a sensor of
    another tenant never claims it."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    assert client.post(
        "/api/tenants", headers=bearer(admin), json={"tenant_id": "acme", "name": "Acme"}
    ).status_code in (200, 201)
    key = client.post(
        "/api/tenants/acme/provisioning-keys", headers=bearer(admin), json={"label": "acme"}
    ).json()["key"]
    token = client.post("/api/auth/agent/token", json={"provisioning_key": key}).json()["access_token"]
    registered = client.post(
        "/api/agent/register",
        headers=bearer(token),
        json={"hostname": "acme-sensor", "capabilities": CURRENT},
    )
    assert registered.status_code == 200, registered.text

    summary = client.get("/api/agents/summary", headers=bearer(admin)).json()
    assert summary["online_agents"] == 1  # the fleet view is still fleet-wide
    assert summary["scan_ready_agents"] == 0  # but nothing takes a `default` scan


def test_a_refused_start_does_not_log_a_queued_job(tmp_path, monkeypatch, caplog):
    """The warning names a job id; one for a job that was never created
    sends the reader looking for it."""
    import logging

    client = _client(tmp_path, monkeypatch)
    with caplog.at_level(logging.WARNING):
        refused = client.post(
            "/api/jobs",
            headers=auth_headers(client, "operator"),
            json={"mode": "balanced", "ranges": "127.0.0.1\n", "domains": "\n", "wordlist_id": "wl-1"},
        )
    assert refused.status_code in (400, 422), refused.text
    assert not [r for r in caplog.records if "queued for agent execution" in r.getMessage()]

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        started = _start_body(client)
    assert [r for r in caplog.records if started["job_id"] in r.getMessage()]
