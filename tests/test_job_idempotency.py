"""Idempotent scan start and result upload (ROADMAP P1.5).

P1.3 made a second upload an error, which is right for a *different* result and
wrong for the one that actually happens in production: the request landed, the
response did not, and the client sends the same thing again.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.services import tenants as tenants_service
from api.services.jobs import get_job
from tests.conftest import configured_client, login, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
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
    agents_service.configure(base)
    agents_service.register_agent(agent_id="agent-1", tenant_id="default")
    return base


def _archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in (("findings.json", b"{}\n"), ("summary.json", b'{"alive_hosts": 1}\n')):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_the_same_key_starts_one_scan(settings):
    first = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin", idempotency_key="req-1"
    )
    second = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin", idempotency_key="req-1"
    )
    assert second.job_id == first.job_id

    _, total = jobs_service.list_jobs(settings)
    assert total == 1


def test_the_same_key_in_another_tenant_is_a_different_request(settings):
    """Keys are the client's names for its own requests; two tenants must be
    able to use "nightly" without colliding."""
    tenants_service.create_tenant(tenant_id="ten_a", name="Tenant A")
    mine = jobs_service.start_scan(
        settings, StartScanRequest(mode="balanced"), username="admin", idempotency_key="nightly"
    )
    theirs = jobs_service.start_scan(
        settings,
        StartScanRequest(mode="balanced", tenant_id="ten_a"),
        username="admin",
        idempotency_key="nightly",
    )
    assert theirs.job_id != mine.job_id


def test_a_replayed_upload_returns_the_stored_outcome(settings):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    run_id = get_job(settings, job.job_id).run_id

    first = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive(),
        idempotency_key="upload-1",
    )
    assert first.status == "succeeded"

    # The retry must not re-extract the run or raise; it reports what landed.
    replay = jobs_service.complete_job(
        settings,
        job.job_id,
        agent_id="agent-1",
        exit_code=0,
        run_id=run_id,
        archive_bytes=_archive(),
        idempotency_key="upload-1",
    )
    assert replay.status == "succeeded"
    assert replay.finished_at == first.finished_at


def test_a_different_upload_for_a_finished_job_conflicts(settings):
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.complete_job(
        settings, job.job_id, agent_id="agent-1", exit_code=0, idempotency_key="upload-1"
    )

    with pytest.raises(jobs_service.ResultsConflict):
        jobs_service.complete_job(
            settings, job.job_id, agent_id="agent-1", exit_code=1, idempotency_key="upload-2"
        )
    assert get_job(settings, job.job_id).status == "succeeded"


def test_a_keyless_retry_is_still_recognised(settings):
    """Older agents send no key. The natural key — same agent, same exit code,
    same job — is enough to tell a retry from a contradicting result."""
    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=0)

    replay = jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=0)
    assert replay.status == "succeeded"

    from api.services import job_states

    with pytest.raises(job_states.InvalidJobTransition):
        jobs_service.complete_job(settings, job.job_id, agent_id="agent-1", exit_code=1)


def test_an_upload_for_a_cancelled_job_is_still_refused(settings):
    """Cancellation is a decision, not an outcome to replay: the agent's result
    must not quietly resurrect a job the operator stopped."""
    from api.services import job_states

    job = jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="admin")
    jobs_service.claim_job(settings, "agent-1")
    jobs_service.cancel_job(settings, job.job_id, username="operator")

    with pytest.raises(job_states.InvalidJobTransition):
        jobs_service.complete_job(
            settings, job.job_id, agent_id="agent-1", exit_code=0, idempotency_key="upload-1"
        )
    assert get_job(settings, job.job_id).status == "cancelled"


def test_retried_scan_start_over_http_returns_the_first_job(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    auth = {"Authorization": f"Bearer {login(client, 'operator')}", "Idempotency-Key": "retry-me"}

    first = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    assert first.status_code == 202

    second = client.post("/api/jobs", headers=auth, json={"mode": "safe"})
    # 200, not 202: this call accepted nothing, it reported what already exists.
    assert second.status_code == 200
    assert second.json()["job_id"] == first.json()["job_id"]

    listed = client.get("/api/jobs", headers=auth)
    assert listed.json()["total"] == 1


def test_retried_results_upload_over_http_is_not_an_error(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    agent_headers = {"Authorization": "Bearer test-agent-token"}
    agent_id = client.post(
        "/api/agent/register", headers=agent_headers, json={"hostname": "worker"}
    ).json()["agent_id"]
    auth = {"Authorization": f"Bearer {login(client, 'operator')}"}

    job = client.post("/api/jobs", headers=auth, json={"mode": "safe"}).json()
    client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=agent_headers)

    def _upload(key: str, exit_code: str = "0"):
        return client.post(
            f"/api/agent/jobs/{job['job_id']}/results",
            headers=agent_headers,
            data={
                "agent_id": agent_id,
                "exit_code": exit_code,
                "run_id": job["run_id"],
                "idempotency_key": key,
            },
            files={"archive": ("run.tar.gz", _archive(), "application/gzip")},
        )

    assert _upload("upload-1").status_code == 200
    assert _upload("upload-1").status_code == 200
    # A genuinely different completion is a conflict, not a silent overwrite.
    assert _upload("upload-2", exit_code="1").status_code == 409
