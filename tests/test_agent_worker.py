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
            self.heartbeats.append({"status": status, "current_job_id": current_job_id, "detail": detail})
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


def test_detect_current_stage(tmp_path):
    assert worker._detect_current_stage(None, None) is None  # noqa: SLF001
    assert worker._detect_current_stage(tmp_path, "run-x") is None  # noqa: SLF001

    run_dir = tmp_path / "runs" / "run-x"
    run_dir.mkdir(parents=True)
    assert worker._detect_current_stage(tmp_path, "run-x") is None  # noqa: SLF001

    # Via checkpoint.json
    (run_dir / "checkpoint.json").write_text('{"completed_stages": ["discover", "ports"]}', encoding="utf-8")
    assert worker._detect_current_stage(tmp_path, "run-x") == "ports"  # noqa: SLF001

    # Via stage_timings.json (higher precedence)
    (run_dir / "stage_timings.json").write_text('{"stages": [{"name": "pulse_probe"}]}', encoding="utf-8")
    assert worker._detect_current_stage(tmp_path, "run-x") == "pulse_probe"  # noqa: SLF001


def test_heartbeat_includes_detail_telemetry(monkeypatch, tmp_path):
    client = _FakeClient()
    run_dir = tmp_path / "runs" / "run-telemetry"
    run_dir.mkdir(parents=True)
    (run_dir / "stage_timings.json").write_text('{"stages": [{"name": "nuclei"}]}', encoding="utf-8")

    def _quick_scan(**_kwargs):
        time.sleep(0.15)
        return 0, None, None

    monkeypatch.setattr(worker, "_run_scan", _quick_scan)
    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-t", "run_id": "run-telemetry"},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=0.05,
    )

    details = [hb["detail"] for hb in client.heartbeats if hb.get("detail")]
    assert any("stage=" in str(d) for d in details)
    assert any("elapsed=" in str(d) for d in details)


def test_agent_client_request_retries_on_transient_error(monkeypatch):
    import io
    import urllib.error
    from unittest.mock import MagicMock

    attempts = 0

    def fake_urlopen(req, timeout):
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise urllib.error.HTTPError(
                url=req.full_url,
                code=503,
                msg="Service Unavailable",
                hdrs={},
                fp=io.BytesIO(b"busy"),
            )
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b'{"status": "ok"}'
        resp.__enter__.return_value = resp
        return resp

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    data = client._request("GET", "/api/ping", max_retries=2)  # noqa: SLF001
    assert data == {"status": "ok"}
    assert attempts == 2


def test_agent_client_request_fails_fast_on_client_error(monkeypatch):
    import io
    import urllib.error
    import pytest

    attempts = 0

    def fake_urlopen(req, timeout):
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=401,
            msg="Unauthorized",
            hdrs={},
            fp=io.BytesIO(b"bad token"),
        )

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    with pytest.raises(RuntimeError, match="401"):
        client._request("GET", "/api/ping", max_retries=3)  # noqa: SLF001
    assert attempts == 1  # No retries on 401


def test_run_scan_handles_timeout(monkeypatch, tmp_path):
    import subprocess
    from unittest.mock import MagicMock
    from pathlib import Path

    mock_proc = MagicMock()
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["scanner"], timeout=1.0)
    mock_proc.pid = 12345
    mock_proc.returncode = 124

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: mock_proc)
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: None)

    code, err, archive = worker._run_scan(  # noqa: SLF001
        config=tmp_path / "config.yaml",
        job={"run_id": "test-timeout-run", "inputs": {}},
        workdir=tmp_path / "work",
        output_dir=tmp_path / "out",
        timeout=1.0,
    )
    assert code == 124
    assert "timed out" in (err or "")
    assert archive is None
