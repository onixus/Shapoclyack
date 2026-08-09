"""Agent-side obligations of the server's lease contract (ROADMAP P1.4/P1.5).

No database and no HTTP: these pin the behaviour of ``agent/worker.py`` around
a fake client, because getting it wrong is expensive in a way unit-testing the
server cannot catch — a scan that keeps running while the control plane hands
the same targets to a second agent.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from agent import worker


class _FakeClient:
    def __init__(self) -> None:
        self.heartbeats: list[dict[str, Any]] = []
        self.uploads: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def heartbeat(self, agent_id: str, *, status: str = "idle", current_job_id=None, detail=None):
        with self.lock:
            self.heartbeats.append({"status": status, "current_job_id": current_job_id})
        return {}

    def upload_results(self, job_id: str, **kwargs: Any):
        self.uploads.append({"job_id": job_id, **kwargs})
        return {}


def test_heartbeats_continue_for_the_whole_scan(monkeypatch, tmp_path):
    """The server renews a job's lease from the heartbeat. One heartbeat at the
    start would let any scan longer than OCTO_JOB_LEASE_SECONDS be requeued and
    handed to a second agent while this one is still scanning."""
    client = _FakeClient()

    def _slow_scan(**_kwargs):
        time.sleep(0.35)
        return 0, None, None

    monkeypatch.setattr(worker, "_run_scan", _slow_scan)
    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 2},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=0.05,
    )

    busy = [hb for hb in client.heartbeats if hb["current_job_id"] == "job-1"]
    # The initial one plus several from the renewal thread.
    assert len(busy) > 2
    assert all(hb["status"] == "busy" for hb in busy)


def test_the_upload_carries_the_claims_fencing_token(monkeypatch, tmp_path):
    """Without the attempt from the claim response, a straggling upload from a
    lease that already expired cannot be told from the current one."""
    client = _FakeClient()
    monkeypatch.setattr(worker, "_run_scan", lambda **_kwargs: (0, None, None))

    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 3},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=60.0,
    )

    assert client.uploads[0]["attempt"] == 3


def test_the_heartbeat_thread_survives_a_control_plane_blip(monkeypatch, tmp_path):
    """A failed heartbeat must not abort a running scan — it is retried on the
    next tick."""
    client = _FakeClient()
    failures = {"count": 0}
    real_heartbeat = client.heartbeat

    def _flaky(*args: Any, **kwargs: Any):
        # Only the renewal thread's heartbeats fail; the synchronous one at
        # claim time is the agent's own start-up check and is allowed to raise.
        if threading.current_thread() is not threading.main_thread() and failures["count"] < 2:
            failures["count"] += 1
            raise RuntimeError("API unreachable")
        return real_heartbeat(*args, **kwargs)

    client.heartbeat = _flaky  # type: ignore[method-assign]
    monkeypatch.setattr(worker, "_run_scan", lambda **_kwargs: (time.sleep(0.25), 0, None)[1:] + (None,))

    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 1},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=0.05,
    )

    assert failures["count"] == 2
    assert client.uploads  # the scan still completed and reported
