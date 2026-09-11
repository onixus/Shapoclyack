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


# --- Asking twice, and the retry of the answer ------------------------------


def test_asking_a_second_time_does_not_stop_a_scan_nobody_stopped(tmp_path, monkeypatch):
    """The list refreshes every four seconds, so two operators — or one proxy
    retry — reach this endpoint on a job that is already `cancelling` all the
    time. `cancelling` is not in `IN_FLIGHT`, so the naive reading of that is
    "queued, cancel it outright": the API would write `cancelled` and clear the
    flag before the agent had read it, leaving a scan running for two hours
    under a row that says it stopped."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)

    first = client.post(f"/api/jobs/{job_id}/cancel", headers=auth)
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "cancelling"

    again = client.post(f"/api/jobs/{job_id}/cancel", headers=auth_headers(client, "admin"))
    assert again.status_code == 200, again.text
    body = again.json()
    assert body["status"] == "cancelling"
    # Not terminalized, and the reason still names whoever actually asked.
    assert body["finished_at"] is None
    assert body["error"] == "Cancellation requested by operator"

    # The instruction is still on its way: the agent has not been told yet, and
    # this is the only channel that can tell it.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=_agent_headers(),
        json={"agent_id": agent_id, "status": "busy", "current_job_id": job_id},
    )
    assert beat.json()["cancel_requested"] is True

    # ...and the confirmation is still accepted, with the results it carries.
    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
        },
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "cancelled"


def test_a_retried_confirmation_upload_is_answered_with_the_stored_outcome(
    tmp_path, monkeypatch
):
    """Confirming a cancellation *is* an upload now (#360), so it inherits the
    problem P1.5 solved for every other upload: the bytes land, the response is
    lost to a timeout, and the agent retries with the same deterministic key.
    Refusing that retry tells an agent that obeyed the stop that its upload
    failed, and the partial results it carries are dropped on the floor."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    def _upload() -> object:
        return client.post(
            f"/api/agent/jobs/{job_id}/results",
            headers=_agent_headers(),
            data={
                "agent_id": agent_id,
                "exit_code": "143",
                "run_id": run_id,
                "cancelled": "true",
                # What the worker derives from (agent, job, run, exit code), so
                # the retry of a lost response carries exactly this again.
                "idempotency_key": f"{agent_id}:{job_id}:{run_id}:143",
            },
            files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
        )

    first = _upload()
    assert first.status_code == 200, first.text
    assert first.json()["status"] == "cancelled"

    retry = _upload()
    assert retry.status_code == 200, retry.text
    assert retry.json()["status"] == "cancelled"
    assert retry.json()["finished_at"] == first.json()["finished_at"]


def test_a_late_result_for_a_cancellation_nobody_confirmed_is_still_refused(
    tmp_path, monkeypatch
):
    """The replay above is recognised by the key the first upload stored. An
    upload with no key — or a different one — arriving at a job the reaper
    finished is a different thing: nothing here produced that outcome, so it
    meets the transition check, and the refusal names what was reported rather
    than inventing a failure the agent never claimed.

    This one carries **no archive**, which is why it is still refused: there is
    nothing to keep, so accepting it would be accepting the verdict alone — a
    cancellation nobody confirmed. An upload that does carry one is the test
    below."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    settings = _settings(tmp_path)
    settings.job_cancel_grace_seconds = 1
    _age_cancellation(settings, job_id, 300)
    assert jobs_service.reap_stale_cancellations(settings) == 1

    late = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
            "idempotency_key": f"{agent_id}:{job_id}:{run_id}:143",
        },
    )
    assert late.status_code == 422, late.text
    detail = late.json()["detail"]
    assert "already cancelled" in detail
    # The agent reported a cancellation; telling it the job "cannot move ... to
    # failed" would name an outcome nobody claimed.
    assert "to failed" not in detail


def _age_finish(settings: Settings, job_id: str, seconds: int) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        row.finished_at = row.finished_at - timedelta(seconds=seconds)


def test_a_late_partial_archive_is_kept_without_confirming_the_cancellation(
    tmp_path, monkeypatch
):
    """The obedient agent that is simply slow. It signalled its scanner, packed
    a partial `runs/<run_id>` and started pushing it up a narrow link; the
    reaper wrote the row off first. Refusing the upload threw away an archive
    nobody can produce again, under a docs line promising partial results are
    kept.

    What is accepted is the bytes. The outcome stays the reaper's: `cancelled`,
    the same `finished_at`, no `exit_code`, and "did not confirm" still in
    `error` — because this upload proves the agent obeyed, not that it obeyed
    in time."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    settings = _settings(tmp_path)
    settings.job_cancel_grace_seconds = 1
    _age_cancellation(settings, job_id, 300)
    assert jobs_service.reap_stale_cancellations(settings) == 1
    reaped = jobs_service.get_job(settings, job_id)

    late = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
            "idempotency_key": f"{agent_id}:{job_id}:{run_id}:143",
        },
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )

    assert late.status_code == 200, late.text
    assert (settings.output_dir / "runs" / run_id / "findings.json").is_file()
    job = late.json()
    assert job["status"] == "cancelled"
    # Untouched: the reaper's verdict, not this upload's.
    assert job["exit_code"] is None
    assert job["finished_at"] == reaped.finished_at
    assert "did not confirm" in job["error"]
    # ...and the drawer says why a job that never confirmed has results.
    assert "partial results uploaded late" in job["error"]
    # The key the upload carried makes its retry a replay rather than a second
    # extraction into the same run directory.
    retry = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
            "idempotency_key": f"{agent_id}:{job_id}:{run_id}:143",
        },
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["error"].count("partial results uploaded late") == 1


def test_a_late_archive_from_an_agent_with_no_key_is_taken_once(tmp_path, monkeypatch):
    """The predicate says "no results key, so nothing has ever been ingested" —
    but a pre-P1.5 agent sends no key, and the late path used to write none, so
    that clause was true again the moment the first upload finished. The window
    is a whole `job_cancel_grace_seconds`, and inside it the agent could push a
    different archive into the same `runs/<run_id>`, re-publish it and re-upsert
    its assets, as often as it liked.

    The reservation is what closes it: an unkeyed late archive marks the row
    itself, so the second copy meets the ordinary transition check like any
    other straggler."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    settings = _settings(tmp_path)
    settings.job_cancel_grace_seconds = 1
    _age_cancellation(settings, job_id, 300)
    assert jobs_service.reap_stale_cancellations(settings) == 1

    def upload(*names: str):
        return client.post(
            f"/api/agent/jobs/{job_id}/results",
            headers=_agent_headers(),
            data={
                "agent_id": agent_id,
                "exit_code": "143",
                "run_id": run_id,
                "cancelled": "true",
            },
            files={"archive": ("run.tar.gz", _archive(*names), "application/gzip")},
        )

    first = upload("findings.json")
    second = upload("other.json")

    assert first.status_code == 200, first.text
    assert second.status_code == 422, second.text
    assert "already cancelled" in second.json()["detail"]
    # The run directory still holds the archive that was kept, and only it.
    run_dir = settings.output_dir / "runs" / run_id
    assert (run_dir / "findings.json").is_file()
    assert not (run_dir / "other.json").exists()
    # And the note the drawer shows was not doubled by the second attempt.
    assert jobs_service.get_job(settings, job_id).error.count("uploaded late") == 1


def test_an_archive_for_a_job_closed_long_ago_is_refused(tmp_path, monkeypatch):
    """"Late" has to stop meaning "whenever". The agent that missed the grace
    period gets one more of them to deliver what it packed; an archive for a
    scan closed an hour ago is not a partial result, it is a surprise — and
    accepting it would let a job's run directory be written by anything still
    holding its id."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    settings = _settings(tmp_path)
    settings.job_cancel_grace_seconds = 1
    _age_cancellation(settings, job_id, 300)
    assert jobs_service.reap_stale_cancellations(settings) == 1
    _age_finish(settings, job_id, 3600)

    late = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={"agent_id": agent_id, "exit_code": "143", "run_id": run_id, "cancelled": "true"},
        files={"archive": ("run.tar.gz", _archive("findings.json"), "application/gzip")},
    )

    assert late.status_code == 422, late.text
    assert "already cancelled" in late.json()["detail"]
    assert not (settings.output_dir / "runs" / run_id / "findings.json").exists()


def test_a_confirmed_cancellation_still_says_who_asked_for_it(tmp_path, monkeypatch):
    """docs/api-and-rbac.md promises the reason lives in `error`, and for a
    finished job that is the only place on the row where it lives: the agent's
    upload used to write its own string over "Cancellation requested by X" —
    or, sending none, write NULL — leaving "who stopped my scan at 3am" one hop
    away in the audit trail."""
    client = _client(tmp_path, monkeypatch)
    auth = auth_headers(client, "operator")
    agent_id, job_id, run_id = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{job_id}/cancel", headers=auth).status_code == 200

    done = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={
            "agent_id": agent_id,
            "exit_code": "143",
            "run_id": run_id,
            "cancelled": "true",
            "error": "scanner signalled",
        },
    )
    assert done.status_code == 200, done.text
    assert done.json()["error"] == "Cancellation requested by operator; scanner signalled"

    # ...and an agent that reports no string of its own does not erase it.
    other_agent, other_job, other_run = _running_agent_job(client, auth)
    assert client.post(f"/api/jobs/{other_job}/cancel", headers=auth).status_code == 200
    silent = client.post(
        f"/api/agent/jobs/{other_job}/results",
        headers=_agent_headers(),
        data={
            "agent_id": other_agent,
            "exit_code": "143",
            "run_id": other_run,
            "cancelled": "true",
        },
    )
    assert silent.status_code == 200, silent.text
    assert silent.json()["error"] == "Cancellation requested by operator"


def test_the_grace_period_cannot_be_set_below_what_an_agent_can_answer_in(monkeypatch):
    """The stop reaches the agent on a heartbeat and the reaper only looks once
    a tick, so a grace shorter than "already declared offline, plus one sweep"
    is one no cooperating agent can answer inside. The old floor of 5s allowed
    an administrator who wanted cancellations to feel faster to make every one
    of them `unconfirmed` — the slo.md alert on each click, and the agent's
    honest confirmation a minute later meeting a finished job."""
    from api.settings import load_settings

    monkeypatch.delenv("OCTO_AGENT_STALE_SECONDS", raising=False)
    monkeypatch.delenv("OCTO_JOB_REAPER_INTERVAL_SECONDS", raising=False)
    monkeypatch.setenv("OCTO_JOB_CANCEL_GRACE_SECONDS", "30")
    assert load_settings().job_cancel_grace_seconds == 180

    # Derived, not a constant: an installation that slows its agents down moves
    # the floor with them.
    monkeypatch.setenv("OCTO_AGENT_STALE_SECONDS", "300")
    monkeypatch.setenv("OCTO_JOB_REAPER_INTERVAL_SECONDS", "120")
    assert load_settings().job_cancel_grace_seconds == 420

    # Anything above the floor is the administrator's business.
    monkeypatch.setenv("OCTO_JOB_CANCEL_GRACE_SECONDS", "900")
    assert load_settings().job_cancel_grace_seconds == 900
