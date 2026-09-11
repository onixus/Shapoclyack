"""Stopping a scan that has already started (#360).

Until this, ``POST /api/jobs/{id}/cancel`` was legal only from ``queued`` and
the only bound on a running scan was the agent's own ``--scan-timeout`` — two
hours of traffic at a target an operator had already decided to leave alone.
The stop now travels on the heartbeat response, the job waits in ``cancelling``
until the agent confirms, and the grace period in ``reap_stale_cancellations``
is what keeps that wait from being forever.

Every test below fails on the pre-#360 code, most of them with a 409.
"""

from __future__ import annotations

import io
import tarfile
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from api.db import models
from api.db.engine import get_session
from api.services import agents as agents_service
from api.services import job_states
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

SETTINGS = {"job_execution_mode": "agent"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _archive(*names: str) -> bytes:
    """A run archive carrying one file per name — the partial output of a scan."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in names:
            data = b'{"partial": true}\n'
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _running_agent_job(client: TestClient, auth: dict[str, str]) -> tuple[str, str, str]:
    """Start a scan, let an agent claim it and report it running.

    Returns ``(agent_id, job_id, run_id)`` — the state every test here starts
    from, because a queued job could always be cancelled.
    """
    agent_id = client.post(
        "/api/agent/register", headers=_agent_headers(), json={"hostname": "worker"}
    ).json()["agent_id"]
    job_id = client.post("/api/jobs", headers=auth, json={"mode": "safe"}).json()["job_id"]
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers()
    )
    assert claimed.status_code == 200, claimed.text
    run_id = claimed.json()["run_id"]
    client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "busy", "current_job_id": job_id},
    )
    assert client.get(f"/api/jobs/{job_id}", headers=auth).json()["status"] == "running"
    return agent_id, job_id, run_id


def test_a_running_scan_is_stopped_through_the_agent_and_keeps_what_it_produced(
    tmp_path, monkeypatch
):
    """The whole loop: ask, hear it on the heartbeat, confirm with a result.

    The archive matters as much as the status. An agent that is signalled
    half-way has usually written something, and an operator who stops a scan
    asked for the scan to end, not for its findings so far to be thrown away.
    """
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)

    asked = client.post(f"/api/jobs/{job_id}/cancel", headers=auth)
    assert asked.status_code == 200, asked.text
    assert asked.json()["status"] == "cancelling"
    assert asked.json()["error"] == "Cancellation requested by operator"
    # Not terminal yet: nobody has said the scan stopped.
    assert asked.json()["finished_at"] is None

    beat = client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "busy", "current_job_id": job_id},
    )
    assert beat.status_code == 200
    assert beat.json()["cancel_requested"] is True

    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            # SIGTERM, i.e. exactly what a scan that was put down exits with.
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
            "error": "cancelled on the operator's request",
        },
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )
    assert done.status_code == 200, done.text
    # Not `failed`: the scan did what it was told, and filing an operator's
    # decision as a malfunction is what this issue is about.
    assert done.json()["status"] == "cancelled"
    assert done.json()["exit_code"] == 143

    settings = _settings(tmp_path)
    assert (settings.output_dir / "runs" / run_id / "findings.json").is_file()


def test_a_scan_that_finished_before_the_stop_reached_it_keeps_its_result(
    tmp_path, monkeypatch
):
    """`cancelling` is a request, not a verdict. The scan may have completed in
    the seconds between the operator's click and the agent's next heartbeat,
    and discarding a real result to make the console's wording come true would
    lose a whole run's findings."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={"agent_id": agent_id, "exit_code": "0", "run_id": run_id},
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "succeeded"


def test_an_agent_cannot_retire_a_job_nobody_asked_to_stop_as_cancelled(
    tmp_path, monkeypatch
):
    """`cancelled` is the API's decision, reported back. An agent that could
    set it on a job still `running` would be able to close any job it holds as
    an operator's choice — and a scan that stopped for the agent's own reasons
    is a failure, which is what its exit code already says."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)

    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
        },
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "failed"


def test_a_heartbeat_about_someone_elses_job_is_never_told_to_stop(tmp_path, monkeypatch):
    """The instruction is about one agent's work. An agent naming a job it does
    not hold must not be told to put down a scan its neighbour is running."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    _agent_id, job_id, _run_id = _running_agent_job(client, auth)
    other = client.post(
        "/api/agent/register", headers=_agent_headers(), json={"hostname": "worker-2"}
    ).json()["agent_id"]
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    beat = client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": other, "status": "busy", "current_job_id": job_id},
    )
    assert beat.json()["cancel_requested"] is False


def test_the_request_is_written_to_the_audit_trail(tmp_path, monkeypatch):
    """Stopping somebody's scan mid-flight is an operator action, so it leaves a
    row with who asked and what state the job was in when they did."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    _agent_id, job_id, _run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    events = client.get(
        "/api/audit", headers=auth_headers(client, "admin"), params={"action": "scan.cancel"}
    )
    assert events.status_code == 200, events.text
    rows = events.json()["items"]
    assert len(rows) == 1
    assert rows[0]["resource_id"] == job_id
    assert rows[0]["actor"] == "operator"
    assert rows[0]["before"]["status"] == "running"
    assert rows[0]["after"]["status"] == "cancelling"


def test_stopping_a_scan_is_gated_on_the_named_permission(tmp_path, monkeypatch):
    """`scan.cancel` (#318), not the operator rank: an auditor is rank 1 and was
    already refused, but a `scan-operator` — rank 2, and the role an
    installation grants for "runs scans" — has to be able to stop one."""
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    operator = auth_headers(client, "operator")

    def _member(username: str, role: str) -> dict[str, str]:
        password = f"{username}-password-1234"
        created = client.post(
            "/api/users",
            headers=admin,
            json={"username": username, "password": password, "role": "viewer"},
        )
        assert created.status_code == 201, created.text
        granted = client.put(
            f"/api/tenants/{tenants_service.DEFAULT_TENANT_ID}/members/{username}",
            headers=admin,
            json={"role": role},
        )
        assert granted.status_code == 200, granted.text
        return {"Authorization": f"Bearer {login(client, username, password)}"}

    auditor = _member("cancel-auditor", "auditor")
    scan_operator = _member("cancel-runner", "scan-operator")

    first = client.post("/api/jobs", headers=operator, json={"mode": "safe"}).json()["job_id"]
    refused = client.post(f"/api/jobs/{first}/cancel", headers=auditor)
    assert refused.status_code == 403
    assert "scan.cancel" in refused.json()["detail"]

    allowed = client.post(f"/api/jobs/{first}/cancel", headers=scan_operator)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["status"] == "cancelled"


# --- The service layer: the clocks around `cancelling` ----------------------


def _service_settings(tmp_path: Path) -> Settings:
    base = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="agent",
    )
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    approve_scan_scope(base)
    jobs_service.reset_for_tests(base)
    agents_service.configure(base)
    agents_service.reset_for_tests()
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return base


def _cancelling_job(settings: Settings) -> str:
    from api.schemas import StartScanRequest

    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="safe"), username="operator"
    )
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.mark_running(settings, job.job_id, agent_id="agent-1")
    jobs_service.cancel_job(settings, job.job_id, username="operator")
    assert jobs_service.get_job(settings, job.job_id).status == job_states.CANCELLING
    return job.job_id


def _age_cancellation(settings: Settings, job_id: str, seconds: int) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        row.cancel_requested_at = row.cancel_requested_at - timedelta(seconds=seconds)


def test_a_job_being_stopped_is_never_handed_to_a_second_agent(tmp_path):
    """The lease reaper requeues what it finds in flight. A job on its way down
    must not be one of them: a second agent would start the very scan an
    operator has just stopped."""
    settings = _service_settings(tmp_path)
    job_id = _cancelling_job(settings)

    assert jobs_service.reap_expired_leases(settings) == {"requeued": 0, "failed": 0}
    assert jobs_service.get_job(settings, job_id).status == job_states.CANCELLING
    # ...and there is nothing on the queue for anyone to take.
    assert jobs_service.claim_job(settings, "agent-1") is None


def test_a_cancellation_the_agent_never_confirms_is_finished_by_the_reaper(tmp_path):
    """An agent too old to read `cancel_requested` keeps scanning and keeps
    heartbeating, so nothing else would ever move this row. Past the grace
    period the job is `cancelled` and the reason says the agent stayed silent —
    the operator's decision stands, and the row does not pretend it was
    obeyed."""
    settings = _service_settings(tmp_path)
    settings.job_cancel_grace_seconds = 60
    job_id = _cancelling_job(settings)

    # Inside the grace period nothing happens: the agent is allowed to answer.
    assert jobs_service.reap_stale_cancellations(settings) == 0
    assert jobs_service.get_job(settings, job_id).status == job_states.CANCELLING

    _age_cancellation(settings, job_id, 120)
    assert jobs_service.reap_stale_cancellations(settings) == 1
    stopped = jobs_service.get_job(settings, job_id)
    assert stopped.status == job_states.CANCELLED
    assert stopped.finished_at is not None
    assert "did not confirm" in (stopped.error or "")
    # Terminal, so a late upload from that agent is refused rather than
    # rewriting the outcome.
    assert jobs_service.reap_stale_cancellations(settings) == 0


def test_a_local_scan_that_has_started_is_refused_with_the_reason(tmp_path):
    """A local scan is a subprocess in one replica's thread, and the replica
    answering this request may not be that one. There is no signal to send, so
    the API refuses instead of reporting a stop that never happened — and says
    why, rather than reading as a generic lifecycle conflict."""
    import pytest

    from api.schemas import StartScanRequest

    settings = _service_settings(tmp_path)
    job = jobs_service.start_scan(
        settings, StartScanRequest(mode="safe"), username="operator"
    )
    jobs_service.force_status(settings, job.job_id, job_states.RUNNING, execution="local")

    with pytest.raises(job_states.InvalidJobTransition) as exc:
        jobs_service.cancel_job(settings, job.job_id, username="operator")
    assert "local scan" in str(exc.value)
    assert jobs_service.get_job(settings, job.job_id).status == job_states.RUNNING
