"""Result ingestion runs off the event loop, and under a bound.

The defect these cover: ``POST /api/agent/jobs/{job_id}/results`` is an
``async def`` route that called the synchronous ``jobs.complete_job`` directly,
so SQL, a NATS publish, archive extraction, artifact writes and projection
updates all happened *on* the event loop the replica serves every other request
from — heartbeats and readiness probes included. Moving that to a thread is
only half the fix; without a bound it trades a blocked loop for an unbounded
number of threads, database connections and buffered archives.
"""

from __future__ import annotations

import asyncio
import io
import tarfile
import types

import pytest

from api.services import ingest_gate
from tests.conftest import configured_client, login, requires_postgres


def _gate_settings(*, limit: int = 2, waiting: int = 8, wait: float = 5.0):
    return types.SimpleNamespace(
        agent_results_max_concurrent_ingests=limit,
        agent_results_ingest_max_waiting=waiting,
        agent_results_ingest_wait_seconds=wait,
    )


def test_the_gate_admits_only_the_configured_number_at_once():
    settings = _gate_settings(limit=2)
    gate = ingest_gate.IngestGate()
    live = 0
    peak = 0

    async def ingest() -> None:
        nonlocal live, peak
        async with gate.slot(settings):
            live += 1
            peak = max(peak, live)
            await asyncio.sleep(0.02)
            live -= 1

    async def scenario() -> None:
        await asyncio.wait_for(asyncio.gather(*(ingest() for _ in range(6))), 10)

    asyncio.run(scenario())

    assert peak == 2, f"{peak} ingests ran at once against a limit of 2"
    assert live == 0


def test_an_upload_beyond_the_queue_ceiling_is_refused_rather_than_buffered():
    # The ceiling is the memory bound: every waiter is holding its archive.
    settings = _gate_settings(limit=1, waiting=1, wait=5.0)
    gate = ingest_gate.IngestGate()

    async def scenario() -> None:
        holding = asyncio.Event()
        release = asyncio.Event()

        async def holder() -> None:
            async with gate.slot(settings):
                holding.set()
                await release.wait()

        async def waiter() -> None:
            async with gate.slot(settings):
                pass

        held = asyncio.create_task(holder())
        await holding.wait()
        queued = asyncio.create_task(waiter())
        # Let the waiter reach the semaphore before the third upload arrives.
        while gate._waiting < 1:  # noqa: SLF001 - the queue depth is the subject
            await asyncio.sleep(0)

        with pytest.raises(ingest_gate.IngestOverloaded) as exc:
            async with gate.slot(settings):
                pass
        assert exc.value.reason == "queue_full"

        release.set()
        await asyncio.wait_for(asyncio.gather(held, queued), 5)

    asyncio.run(scenario())


def test_a_slot_that_never_frees_is_refused_instead_of_held_forever():
    settings = _gate_settings(limit=1, waiting=4, wait=0.05)
    gate = ingest_gate.IngestGate()

    async def scenario() -> None:
        holding = asyncio.Event()
        release = asyncio.Event()

        async def holder() -> None:
            async with gate.slot(settings):
                holding.set()
                await release.wait()

        held = asyncio.create_task(holder())
        await holding.wait()

        with pytest.raises(ingest_gate.IngestOverloaded) as exc:
            async with gate.slot(settings):
                pass
        assert exc.value.reason == "timeout"

        release.set()
        await asyncio.wait_for(held, 5)

    asyncio.run(scenario())


def test_a_failed_ingest_gives_its_slot_back():
    settings = _gate_settings(limit=1, waiting=1, wait=1.0)
    gate = ingest_gate.IngestGate()

    async def scenario() -> None:
        with pytest.raises(ValueError):
            async with gate.slot(settings):
                raise ValueError("extraction blew up")
        # Would raise IngestOverloaded if the slot had leaked.
        async with gate.slot(settings):
            pass

    asyncio.run(scenario())


SETTINGS = {"job_execution_mode": "agent"}


def _client(tmp_path, monkeypatch, **overrides):
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _tiny_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        payload = b'{"ok": true}\n'
        info = tarfile.TarInfo(name="findings.json")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
        summary = b'{"alive_hosts": 1}\n'
        sinfo = tarfile.TarInfo(name="summary.json")
        sinfo.size = len(summary)
        tf.addfile(sinfo, io.BytesIO(summary))
    return buf.getvalue()


def _claimed_job(client):
    reg = client.post(
        "/api/agent/register", headers=_agent_headers(), json={"hostname": "worker"}
    )
    agent_id = reg.json()["agent_id"]
    operator = {"Authorization": f"Bearer {login(client, 'operator')}"}
    job = client.post(
        "/api/jobs",
        headers=operator,
        json={
            "mode": "safe",
            "skip_nse": True,
            "ranges": "127.0.0.1\n",
            "domains": "\n",
            "ports": "80\n",
        },
    ).json()
    claimed = client.post(
        f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers()
    )
    assert claimed.status_code == 200
    return agent_id, job["job_id"], job["run_id"]


def _upload(client, job_id, agent_id, run_id):
    return client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=_agent_headers(),
        data={"agent_id": agent_id, "exit_code": "0", "run_id": run_id},
        files={"archive": ("run.tar.gz", _tiny_archive(), "application/gzip")},
    )


@requires_postgres
def test_ingestion_does_not_run_on_the_event_loop(tmp_path, monkeypatch):
    """The whole point: `complete_job` must not execute on the loop thread.

    Asserted by asking for a running loop from inside the ingest. On the event
    loop that call succeeds — which is exactly the state this fix removes — and
    from a worker thread it raises, so the check fails if the offload is ever
    reverted or a caller drops the `to_thread`.
    """
    from api.services import jobs as jobs_service

    client = _client(tmp_path, monkeypatch)
    agent_id, job_id, run_id = _claimed_job(client)

    real = jobs_service.complete_job
    observed: dict[str, object] = {}

    def spy(*args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            observed["on_event_loop"] = False
        else:
            observed["on_event_loop"] = True
        return real(*args, **kwargs)

    monkeypatch.setattr("api.routes.agents.jobs_service.complete_job", spy)

    done = _upload(client, job_id, agent_id, run_id)

    assert done.status_code == 200, done.text
    assert observed == {"on_event_loop": False}


@requires_postgres
def test_a_saturated_replica_answers_503_with_retry_after(tmp_path, monkeypatch):
    """A refused upload must be retryable, not a lost scan result.

    503 rather than 429 because the agent is not over any quota, and with
    Retry-After because `agent/worker.py` retries that status with backoff —
    carrying the same derived idempotency key, so the retry replays instead of
    ingesting the run a second time.
    """
    from contextlib import asynccontextmanager

    client = _client(tmp_path, monkeypatch)
    agent_id, job_id, run_id = _claimed_job(client)

    @asynccontextmanager
    async def saturated(_settings):
        raise ingest_gate.IngestOverloaded("queue_full", "4 ingesting and 8 waiting")
        yield  # pragma: no cover - unreachable, keeps this a generator

    monkeypatch.setattr("api.routes.agents.ingest_gate.slot", saturated)

    refused = _upload(client, job_id, agent_id, run_id)

    assert refused.status_code == 503
    assert refused.headers["Retry-After"] == "5"
    assert "saturated" in refused.json()["detail"]


@requires_postgres
def test_a_refused_upload_leaves_the_job_claimable_rather_than_terminal(tmp_path, monkeypatch):
    """Refusing at the door must not be mistaken for a completion."""
    from contextlib import asynccontextmanager

    client = _client(tmp_path, monkeypatch)
    agent_id, job_id, run_id = _claimed_job(client)

    real_slot = ingest_gate.slot
    saturated = {"on": True}

    @asynccontextmanager
    async def maybe_saturated(settings):
        if saturated["on"]:
            raise ingest_gate.IngestOverloaded(
                "timeout", "no ingest slot became free within 25s"
            )
        async with real_slot(settings):
            yield

    # Patched rather than undone later: monkeypatch.undo() would also restore
    # the settings this client authenticates against, which configured_client
    # installed through the same fixture.
    monkeypatch.setattr("api.routes.agents.ingest_gate.slot", maybe_saturated)
    assert _upload(client, job_id, agent_id, run_id).status_code == 503

    operator = {"Authorization": f"Bearer {login(client, 'operator')}"}
    state = client.get(f"/api/jobs/{job_id}", headers=operator).json()
    assert state["status"] not in {"succeeded", "failed", "cancelled"}

    # And the retry the agent makes once a slot frees up is an ordinary upload,
    # not a conflict with a reservation the refusal left behind.
    saturated["on"] = False
    retried = _upload(client, job_id, agent_id, run_id)
    assert retried.status_code == 200, retried.text
    assert retried.json()["status"] == "succeeded"
