"""Agent-side obligations of the server's lease contract (ROADMAP P1.4/P1.5).

No database and no HTTP: these pin the behaviour of ``agent/worker.py`` around
a fake client, because getting it wrong is expensive in a way unit-testing the
server cannot catch — a scan that keeps running while the control plane hands
the same targets to a second agent.
"""

from __future__ import annotations

import json
import signal
import threading
import time
from types import SimpleNamespace
from typing import Any

from agent import worker


class _FakeClient:
    def __init__(self) -> None:
        self.heartbeats: list[dict[str, Any]] = []
        self.uploads: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        #: What the API answers every heartbeat with (#360). The instruction is
        #: repeated rather than delivered once, which is what makes a lost
        #: response cost a cancellation an interval instead of losing it.
        self.cancel_requested = False

    def heartbeat(self, agent_id: str, *, status: str = "idle", current_job_id=None, detail=None):
        with self.lock:
            self.heartbeats.append({"status": status, "current_job_id": current_job_id, "detail": detail})
        return {"cancel_requested": self.cancel_requested}

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

    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", fake_urlopen)  # noqa: SLF001
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

    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", fake_urlopen)  # noqa: SLF001
    with pytest.raises(RuntimeError, match="401"):
        client._request("GET", "/api/ping", max_retries=3)  # noqa: SLF001
    assert attempts == 1  # No retries on 401


def test_the_server_side_refusals_get_their_own_exception_types(monkeypatch):
    """401 and 426 are the two answers the run loop reacts to rather than
    logs: a rotated signing key (#312) and a fleet-wide version floor (#363).
    Both used to arrive as a bare RuntimeError indistinguishable from a 500."""
    import io
    import urllib.error

    import pytest

    codes = iter([401, 426])

    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=next(codes),
            msg="refused",
            hdrs={},
            fp=io.BytesIO(b"nope"),
        )

    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", fake_urlopen)  # noqa: SLF001

    with pytest.raises(worker.AgentTokenRejected):
        client._request("GET", "/api/ping", max_retries=0)  # noqa: SLF001
    with pytest.raises(worker.AgentUpgradeRequired):
        client._request("GET", "/api/ping", max_retries=0)  # noqa: SLF001


def test_a_disabled_agents_403_is_its_own_exception_and_a_plain_403_is_not(monkeypatch):
    """Only the two lifecycle refusals become AgentDisabled (#308).

    A 403 also covers a cross-tenant request and the agent-id binding, and
    those two are misconfiguration to fail loudly on — backing off for five
    minutes would hide a token pointed at the wrong fleet.
    """
    import io
    import urllib.error

    import pytest

    bodies = iter(
        [
            b'{"detail":"This agent is disabled by an operator; job claims ..."}',
            b'{"detail":"This agent is quarantined by an operator; job claims ..."}',
            b'{"detail":"Cross-tenant agent access denied"}',
        ]
    )

    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            url=req.full_url,
            code=403,
            msg="refused",
            hdrs={},
            fp=io.BytesIO(next(bodies)),
        )

    client = worker.AgentClient("http://127.0.0.1:8080", "token", timeout=1.0)
    monkeypatch.setattr(client._opener, "open", fake_urlopen)  # noqa: SLF001

    for _ in range(2):
        with pytest.raises(worker.AgentDisabled):
            client._request("POST", "/api/agent/jobs/claim", max_retries=0)  # noqa: SLF001
    with pytest.raises(RuntimeError) as excinfo:
        client._request("POST", "/api/agent/jobs/claim", max_retries=0)  # noqa: SLF001
    assert not isinstance(excinfo.value, worker.AgentDisabled)


def test_a_disabled_agent_backs_off_instead_of_polling_every_second(monkeypatch, caplog):
    """A disabled agent keeps heartbeating but stops hammering the claim.

    The state is changed by a person in the console, so at the normal poll
    interval the agent would spend however long that takes writing one refusal
    per second into its journal and onto the API.
    """
    import argparse
    import logging

    waits: list[float] = []
    beats = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal beats
            beats += 1
            if beats > 3:
                raise KeyboardInterrupt
            # Answered even while disabled, and this is where the agent finds
            # out why — before the claim below is refused.
            return {
                "agent_id": "a1",
                "lifecycle_status": "disabled",
                "lifecycle_message": "This agent is disabled by an operator; Reason: rack retired",
            }

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            raise worker.AgentDisabled(
                "POST /api/agent/jobs/claim -> 403: This agent is disabled by an operator;"
            )

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    # The backoff is an interruptible wait on the shutdown event, so SIGTERM
    # still stops the agent promptly; record it instead of waiting it out.
    original_wait = threading.Event.wait

    def fake_wait(self, timeout=None):
        if timeout is not None:
            waits.append(timeout)
            return False
        return original_wait(self, timeout)

    monkeypatch.setattr(threading.Event, "wait", fake_wait)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="static-token",
        timeout=1.0,
        provisioning_key="",
        jwt_refresh_seconds=1800,
        agent_id="a1",
        hostname="edge-1",
        label=None,
        nats_url="",
        poll_interval=0.01,
        config="scanner/config/default.yaml",
        output_dir="out",
        scan_timeout=1.0,
    )

    with caplog.at_level(logging.ERROR, logger=worker.LOG.name):
        assert worker.run_loop(args) == 0

    assert waits and all(w == worker.DISABLED_BACKOFF_SECONDS for w in waits)
    # The operator's reason reaches the agent's journal, and once — three
    # identical polls must not be three identical lines.
    reason_lines = [r for r in caplog.records if "rack retired" in r.getMessage()]
    assert len(reason_lines) == 1


def test_the_loop_re_exchanges_the_provisioning_key_after_a_401(monkeypatch):
    """Rotating the agent signing key invalidates every token in the fleet at
    once (#312). Waiting out --jwt-refresh-seconds would idle every agent for
    up to half an hour after a change that took effect server-side instantly,
    so a rejected token is re-exchanged on the next pass."""
    import argparse

    exchanges: list[str] = []
    beats = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def exchange_provisioning_key(
            self, provisioning_key: str, *, agent_id: str | None = None
        ) -> dict[str, Any]:
            exchanges.append(provisioning_key)
            return {
                "access_token": f"tok-{len(exchanges)}",
                "tenant_id": "t1",
                "agent_id": agent_id or "a1",
                "expires_in": 3600,
            }

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal beats
            beats += 1
            if beats == 1:
                raise worker.AgentTokenRejected("POST /api/agent/heartbeat -> 401: expired")
            # Ends the loop once the re-exchange above has been observed.
            raise KeyboardInterrupt

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="",
        timeout=1.0,
        provisioning_key="prov-key",
        jwt_refresh_seconds=1800,
        agent_id="a1",
        hostname="edge-1",
        label=None,
        nats_url="",
        poll_interval=0.01,
        config="scanner/config/default.yaml",
        output_dir="out",
        scan_timeout=1.0,
    )

    assert worker.run_loop(args) == 0
    # One before the loop, one forced by the 401 — not one every 1800 seconds.
    assert exchanges == ["prov-key", "prov-key"]


def _run_loop_args(**overrides: Any):
    """The Namespace ``run_loop`` reads, with the fields these tests vary.

    Same defaults the three tests above spell out inline; the identity tests
    that follow flip ``agent_id`` and ``provisioning_key`` against each other,
    and four near-identical Namespaces would hide which field is the subject.
    """
    import argparse

    base = {
        "api_url": "http://127.0.0.1:8080",
        "token": "",
        "timeout": 1.0,
        "provisioning_key": "prov-key",
        "jwt_refresh_seconds": 0,
        "agent_id": None,
        "hostname": "edge-1",
        "label": None,
        "nats_url": "",
        "poll_interval": 0.01,
        "config": "scanner/config/default.yaml",
        "output_dir": "out",
        "scan_timeout": 1.0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_a_426_on_every_poll_is_one_journal_line_not_one_per_second(monkeypatch, caplog):
    """426 is no longer the rarity it was when it meant "below the version
    floor". Since #362 it is also the standing answer to an agent that has not
    declared a capability the job's scan policy needs, so a mixed fleet gets it
    on every poll — and at the normal interval an undeduplicated ERROR is one
    line per second, per agent, until an operator upgrades the host. Logged on
    change, like the lifecycle refusal next to it.
    """
    import logging

    polls = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal polls
            polls += 1
            if polls > 4:
                raise KeyboardInterrupt
            return {"agent_id": "a1", "lifecycle_status": "active"}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            # The same refusal every time, which is what it looks like from an
            # agent that cannot be upgraded this minute.
            raise worker.AgentUpgradeRequired(
                "POST /api/agent/jobs/claim -> 426: this job requires capability "
                "scan_policy, which this agent has not declared"
            )

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    with caplog.at_level(logging.ERROR, logger=worker.LOG.name):
        args = _run_loop_args(agent_id="a1", token="static-token", provisioning_key="")
        assert worker.run_loop(args) == 0

    refusals = [r for r in caplog.records if "scan_policy" in r.getMessage()]
    assert len(refusals) == 1, [r.getMessage() for r in refusals]
    # Still loud once, and still carrying what the API said is missing.
    assert "Job claim refused" in refusals[0].getMessage()


def test_the_same_426_after_a_day_of_work_is_a_second_journal_line(monkeypatch, caplog):
    """Deduplicating the refusal must not mean reporting it once per process.

    ``last_upgrade_message`` and ``last_lifecycle_message`` are re-assigned on
    every heartbeat, so they forget a refusal the moment it stops being the
    answer. ``last_claim_refusal_message`` was only ever written in the
    ``except`` branch, so an agent that was refused, then ran normally for a
    day, then hit the identical refusal again — a policy written, removed and
    written back — logged the first one and nothing after it, while
    docs/operations.md promises a line per *change* of the message.
    """
    import logging

    polls = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal polls
            polls += 1
            if polls > 3:
                raise KeyboardInterrupt
            return {"agent_id": "a1", "lifecycle_status": "active"}

        def claim(self, agent_id: str, **kwargs: Any) -> dict[str, Any] | None:
            if polls == 2:
                # The day of ordinary work, compressed to one job.
                return {"job_id": "j1", "run_id": "r1", "command": ["true"]}
            raise worker.AgentUpgradeRequired(
                "POST /api/agent/jobs/claim -> 426: this job requires capability "
                "scan_policy, which this agent has not declared"
            )

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker, "_execute_job", lambda *a, **kw: None)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    with caplog.at_level(logging.ERROR, logger=worker.LOG.name):
        args = _run_loop_args(agent_id="a1", token="static-token", provisioning_key="")
        assert worker.run_loop(args) == 0

    refusals = [r for r in caplog.records if "scan_policy" in r.getMessage()]
    assert len(refusals) == 2, [r.getMessage() for r in refusals]


def _advance_the_clock_past_every_refresh(monkeypatch) -> None:
    """Make ``time.time()`` jump a refresh interval on each call.

    The JWT refresh is due at ``now + max(60, …)``, so against a real clock a
    two-pass loop never reaches the second exchange — which is the call these
    tests exist to inspect.
    """
    ticks = iter(range(10**9, 10**9 + 10_000, 1_000))
    monkeypatch.setattr(worker.time, "time", lambda: next(ticks))


def test_the_key_exchange_carries_the_agents_own_id(monkeypatch):
    """Every exchange, bootstrap and refresh alike, asks to be OCTO_AGENT_ID.

    This is the crash-loop the branch shipped with (#308): the installer always
    writes OCTO_AGENT_ID, the exchange did not send it, so the server minted a
    random id into the token — and the register that followed, carrying the
    host's real id, was refused as impersonation. Outside any handler, so the
    process died and systemd restarted it five seconds later, for every agent
    provisioned with a key.
    """
    exchanged_ids: list[str | None] = []
    registered_ids: list[str | None] = []
    beats = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def exchange_provisioning_key(
            self, provisioning_key: str, *, agent_id: str | None = None
        ) -> dict[str, Any]:
            exchanged_ids.append(agent_id)
            # The server echoes back whatever it minted the token for.
            return {
                "access_token": "tok",
                "tenant_id": "t1",
                "agent_id": agent_id or "agent_random",
                "expires_in": 3600,
            }

        def register(self, *, agent_id=None, **kwargs: Any) -> dict[str, Any]:
            registered_ids.append(agent_id)
            return {"agent_id": agent_id or "agent_random", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal beats
            beats += 1
            if beats > 1:
                raise KeyboardInterrupt
            return {"agent_id": agent_id}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    # 60 s is the refresh floor, and the clock steps past it every pass, so the
    # second loop iteration performs the *refresh* exchange this test is about.
    _advance_the_clock_past_every_refresh(monkeypatch)
    args = _run_loop_args(agent_id="edge-01", jwt_refresh_seconds=60)

    assert worker.run_loop(args) == 0
    assert exchanged_ids == ["edge-01", "edge-01"]
    assert registered_ids == ["edge-01"]


def test_an_agent_with_no_id_of_its_own_keeps_the_first_one_it_was_given(monkeypatch):
    """The docker and k8s snippets set no OCTO_AGENT_ID, and must not drift.

    The first exchange has nothing to ask for and the server picks an id; from
    then on the agent *is* that id and every refresh has to say so. Re-exchanging
    on a bare timer used to hand the process a token for a brand-new id while its
    heartbeat still named the old one — a permanent 403 swallowed by the loop's
    catch-all, one dead agent per JWT lifetime.
    """
    exchanged_ids: list[str | None] = []
    beat_ids: list[str] = []

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def exchange_provisioning_key(
            self, provisioning_key: str, *, agent_id: str | None = None
        ) -> dict[str, Any]:
            exchanged_ids.append(agent_id)
            minted = agent_id or f"agent_{len(exchanged_ids)}"
            return {
                "access_token": "tok",
                "tenant_id": "t1",
                "agent_id": minted,
                "expires_in": 3600,
            }

        def register(self, *, agent_id=None, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": agent_id, "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            beat_ids.append(agent_id)
            if len(beat_ids) > 1:
                raise KeyboardInterrupt
            return {"agent_id": agent_id}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    _advance_the_clock_past_every_refresh(monkeypatch)
    args = _run_loop_args(agent_id=None, jwt_refresh_seconds=60)

    assert worker.run_loop(args) == 0
    # Nothing to ask for the first time; the id it was given every time after.
    assert exchanged_ids == [None, "agent_1"]
    assert beat_ids == ["agent_1", "agent_1"]


def test_a_quarantined_agent_backs_off_at_registration_instead_of_dying(monkeypatch):
    """A quarantined host restarting must wait, not spin under Restart=always.

    Registration used to happen before the loop and outside every handler, so
    the 403 an operator's quarantine produces there killed the process — and
    systemd brought it back every five seconds, forever, with no heartbeat in
    between to show it in the fleet view.
    """
    waits: list[float] = []
    attempts = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def exchange_provisioning_key(
            self, provisioning_key: str, *, agent_id: str | None = None
        ) -> dict[str, Any]:
            return {
                "access_token": "tok",
                "tenant_id": "t1",
                "agent_id": agent_id,
                "expires_in": 3600,
            }

        def register(self, **kwargs: Any) -> dict[str, Any]:
            nonlocal attempts
            attempts += 1
            if attempts > 2:
                raise KeyboardInterrupt
            raise worker.AgentDisabled(
                "POST /api/agent/register -> 403: This agent is quarantined by an "
                "operator; Reason: credential leak"
            )

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": agent_id}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    original_wait = threading.Event.wait

    def fake_wait(self, timeout=None):
        if timeout is not None:
            waits.append(timeout)
            return False
        return original_wait(self, timeout)

    monkeypatch.setattr(threading.Event, "wait", fake_wait)

    # Returns, rather than propagating the 403 out of run_loop.
    assert worker.run_loop(_run_loop_args(agent_id="edge-01")) == 0
    assert waits == [worker.DISABLED_BACKOFF_SECONDS, worker.DISABLED_BACKOFF_SECONDS]


def test_the_loop_logs_the_upgrade_message_once(monkeypatch, caplog):
    """The heartbeat response is the only channel that reaches a gated agent,
    and it repeats the message on every poll — the journal must not."""
    import argparse
    import logging

    beats = 0
    message = "This installation requires agent 0.44-0907 or newer"

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal beats
            beats += 1
            if beats > 3:
                raise KeyboardInterrupt
            return {"agent_id": "a1", "upgrade_message": message}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="static-token",
        timeout=1.0,
        provisioning_key="",
        jwt_refresh_seconds=1800,
        agent_id="a1",
        hostname="edge-1",
        label=None,
        nats_url="",
        poll_interval=0.01,
        config="scanner/config/default.yaml",
        output_dir="out",
        scan_timeout=1.0,
    )

    with caplog.at_level(logging.ERROR, logger=worker.LOG.name):
        assert worker.run_loop(args) == 0
    assert [r for r in caplog.records if message in r.getMessage()].__len__() == 1


def test_run_scan_handles_timeout(monkeypatch, tmp_path):
    import subprocess
    from unittest.mock import MagicMock

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


def test_run_scan_puts_the_process_group_down_when_the_api_cancels(monkeypatch, tmp_path):
    """The stop the heartbeat thread signalled has to reach the scanner (#360).

    The process *group*, not the process: the scan is `scanner.main` shelling
    out to nmap and nuclei, and killing only the parent would leave whatever is
    actually touching the target running with nobody left to report it.
    """
    import subprocess
    from unittest.mock import MagicMock

    mock_proc = MagicMock()
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["scanner"], timeout=1.0)
    mock_proc.pid = 12345
    mock_proc.returncode = 143
    signalled: list[int] = []

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: mock_proc)
    monkeypatch.setattr("os.getpgid", lambda pid: pid)
    monkeypatch.setattr("os.killpg", lambda pgid, sig: signalled.append(sig))

    # What the run had written when the signal arrived. An operator who stops a
    # scan asked for it to end, not for its findings so far to be dropped.
    run_dir = tmp_path / "out" / "runs" / "run-cancelled"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.json").write_text("{}", encoding="utf-8")
    workdir = tmp_path / "work"
    workdir.mkdir()

    cancel_event = threading.Event()
    cancel_event.set()
    code, err, archive = worker._run_scan(  # noqa: SLF001
        config=tmp_path / "config.yaml",
        job={"run_id": "run-cancelled", "inputs": {}},
        workdir=workdir,
        output_dir=tmp_path / "out",
        # Far past anything this test waits for: the cancellation is what ends
        # the scan here, not the timeout.
        timeout=3600.0,
        cancel_event=cancel_event,
    )

    assert code == 143
    assert "cancelled" in (err or "")
    assert signalled and signalled[0] == signal.SIGTERM
    assert archive is not None and archive.is_file()


def test_the_heartbeat_answer_stops_the_scan_and_the_upload_says_so(monkeypatch, tmp_path):
    """End to end on the agent side: the API answers a heartbeat with
    `cancel_requested`, the scan wait is released, and the result upload carries
    `cancelled` so the job is not filed as a scan that failed."""
    client = _FakeClient()
    client.cancel_requested = True

    def _waiting_scan(**kwargs: Any):
        event = kwargs["cancel_event"]
        # However long the scan would have taken; the heartbeat is what ends it.
        assert event.wait(timeout=5.0), "the heartbeat never delivered the cancellation"
        return 143, "cancelled on the operator's request", None

    monkeypatch.setattr(worker, "_run_scan", _waiting_scan)
    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 1},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=0.05,
    )

    assert client.uploads[0]["cancelled"] is True
    assert client.uploads[0]["exit_code"] == 143


def test_a_scan_that_finished_anyway_is_not_reported_as_cancelled(monkeypatch, tmp_path):
    """The stop can land in the second between the scan completing and the wait
    noticing it. Reporting that run as cancelled to match the request would
    throw away a whole sweep's findings, and the API accepts
    `cancelling -> succeeded` for exactly this case."""
    client = _FakeClient()

    def _finished_first(**kwargs: Any):
        # The operator clicks while the scan is on its last stage; the renewal
        # thread delivers it, and the scan has already succeeded by then.
        client.cancel_requested = True
        assert kwargs["cancel_event"].wait(timeout=5.0)
        return 0, None, None

    monkeypatch.setattr(worker, "_run_scan", _finished_first)
    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 1},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=0.05,
    )

    assert client.uploads[0]["cancelled"] is False
    assert client.uploads[0]["exit_code"] == 0


def test_a_job_cancelled_before_the_scan_started_never_starts_it(monkeypatch, tmp_path):
    """The stop can arrive between the claim and the first heartbeat. Launching
    the scan anyway would put the targets through a sweep that is already
    cancelled, only to kill it a minute later."""
    client = _FakeClient()
    client.cancel_requested = True
    started = {"count": 0}

    def _never(**_kwargs: Any):
        started["count"] += 1
        return 0, None, None

    monkeypatch.setattr(worker, "_run_scan", _never)
    worker._execute_job(  # noqa: SLF001
        client,
        agent_id="agent-1",
        job={"job_id": "job-1", "run_id": "run-1", "attempt": 1},
        config=tmp_path / "config.yaml",
        output_dir=tmp_path,
        heartbeat_interval=60.0,
    )

    assert started["count"] == 0
    assert client.uploads[0]["cancelled"] is True


class _FakeMsg:
    """One JetStream message, recording which disposition the session chose."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.data = json.dumps(payload).encode("utf-8")
        self.acked = False
        self.nakked = False
        self.termed = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.nakked = True

    async def term(self) -> None:
        self.termed = True


class _FakeSub:
    def __init__(self, *msgs: _FakeMsg) -> None:
        self._msgs = list(msgs)

    async def fetch(self, batch: int, timeout: float | None = None):
        from nats.errors import TimeoutError as NatsTimeout

        if not self._msgs:
            raise NatsTimeout
        return [self._msgs.pop(0)]


def _connected_session(
    *subs: _FakeSub, tenant_id: str, agent_group: str | None = None
) -> worker.AgentNatsSession:
    """A session with its event loop running but no broker behind it."""
    session = worker.AgentNatsSession(
        "nats://unused:4222", tenant_id=tenant_id, agent_group=agent_group
    )
    session._thread.start()  # noqa: SLF001
    session._nc = SimpleNamespace(is_connected=True, is_closed=True)  # noqa: SLF001
    session._subs = list(subs)  # noqa: SLF001
    session._started = True  # noqa: SLF001
    return session


def test_the_session_binds_only_its_own_tenants_subject():
    """The durable is per tenant too: two tenants sharing one consumer is the
    same thing as sharing the subject, because a work-queue stream drops a
    message as soon as whoever pulled it acks."""
    session = worker.AgentNatsSession("nats://unused:4222", tenant_id="acme-eu")

    assert session._bindings == [  # noqa: SLF001
        ("jobs.scan.acme-eu", "octo-agents-acme-eu")
    ]


def test_a_grouped_agent_binds_its_group_subject_as_well_as_the_ungrouped_one():
    """The point of #361 on the NATS path: the targets of a restricted job must
    not reach an agent outside its group *at all*, and a subject shared by the
    whole tenant is exactly what put them there. The ungrouped subject stays,
    because ``claim_job`` still lets a grouped agent take unrestricted work."""
    session = worker.AgentNatsSession(
        "nats://unused:4222", tenant_id="acme-eu", agent_group="pci"
    )

    assert session._bindings == [  # noqa: SLF001
        ("jobs.scan.acme-eu", "octo-agents-acme-eu"),
        ("jobs.scan.acme-eu.pci", "octo-agents-acme-eu-pci"),
    ]
    assert session.agent_group == "pci"


def test_an_offer_for_this_tenant_is_claimed_and_acked():
    msg = _FakeMsg({"job_id": "job-1", "tenant_id": "acme-eu"})
    session = _connected_session(_FakeSub(msg), tenant_id="acme-eu")

    class _Client:
        def claim(self, agent_id: str, *, job_id: str | None = None):
            return {"job_id": job_id, "run_id": "run-1"}

    try:
        claimed = session.pull_and_claim(_Client(), "agent-1", timeout=1.0)
    finally:
        session.close()

    assert claimed is not None and claimed["job_id"] == "job-1"
    assert msg.acked and not msg.termed


def test_an_offer_for_another_tenant_is_terminated_not_nakked():
    """A NAK redelivers the message and spends one of its max_deliver attempts,
    so an agent that must not run the job would be deciding how many tries its
    rightful owner has left. Nothing is HTTP-claimed either."""
    msg = _FakeMsg({"job_id": "job-2", "tenant_id": "other-tenant"})
    session = _connected_session(_FakeSub(msg), tenant_id="acme-eu")

    class _Client:
        def __init__(self) -> None:
            self.claims = 0

        def claim(self, agent_id: str, *, job_id: str | None = None):
            self.claims += 1
            return {"job_id": job_id, "run_id": "run-2"}

    client = _Client()
    try:
        claimed = session.pull_and_claim(client, "agent-1", timeout=1.0)
    finally:
        session.close()

    assert claimed is None
    assert msg.termed
    assert not msg.nakked and not msg.acked
    assert client.claims == 0


def test_a_refusal_of_the_claim_reaches_the_run_loop_and_nakks_the_offer():
    """The NATS half of the fleet gets the same backoff as the HTTP half (#308).

    ``pull_and_claim`` used to catch everything as "will reconnect", so a
    disabled agent tore down a healthy session and logged a traceback on every
    poll instead of backing off — and because the loop does not sleep while a
    NATS session is up, that was one per iteration. The offer must go back to
    the stream, too: another agent in the tenant can take it.
    """
    import pytest

    msg = _FakeMsg({"job_id": "job-3", "tenant_id": "acme-eu"})
    session = _connected_session(_FakeSub(msg), tenant_id="acme-eu")

    class _Client:
        def claim(self, agent_id: str, *, job_id: str | None = None):
            raise worker.AgentDisabled(
                "POST /api/agent/jobs/claim -> 403: This agent is quarantined by an operator;"
            )

    try:
        with pytest.raises(worker.AgentDisabled):
            session.pull_and_claim(_Client(), "agent-1", timeout=1.0)
    finally:
        session.close()

    assert msg.nakked and not msg.acked and not msg.termed


def test_an_offer_addressed_to_another_group_is_terminated_not_nakked():
    """Second barrier behind the subject filter. NAK would be the harmful
    answer: five of them (``JOBS_MAX_DELIVER``) and the offer leaves the
    consumer for good, so the job's own group never sees it and the job sits in
    ``queued`` forever — the agent has no HTTP-claim fallback while a NATS
    session is up."""
    msg = _FakeMsg({"job_id": "job-4", "tenant_id": "acme-eu", "agent_group": "pci"})
    session = _connected_session(_FakeSub(msg), tenant_id="acme-eu", agent_group="office")

    class _Client:
        def __init__(self) -> None:
            self.claims = 0

        def claim(self, agent_id: str, *, job_id: str | None = None):
            self.claims += 1
            return {"job_id": job_id}

    client = _Client()
    try:
        claimed = session.pull_and_claim(client, "agent-1", timeout=1.0)
    finally:
        session.close()

    assert claimed is None
    assert msg.termed and not msg.nakked and not msg.acked
    assert client.claims == 0


def test_an_offer_already_taken_is_terminated_so_the_attempts_are_not_burned():
    """204 means the job is no longer queued. Redelivering cannot make it
    claimable again; the API republishes an offer when a lease expires and the
    job goes back to ``queued``."""
    msg = _FakeMsg({"job_id": "job-5", "tenant_id": "acme-eu"})
    session = _connected_session(_FakeSub(msg), tenant_id="acme-eu")

    class _Client:
        def claim(self, agent_id: str, *, job_id: str | None = None):
            return None

    try:
        claimed = session.pull_and_claim(_Client(), "agent-1", timeout=1.0)
    finally:
        session.close()

    assert claimed is None
    assert msg.termed and not msg.nakked


def test_a_grouped_agent_drains_the_ungrouped_subject_before_its_own():
    """Both queues are served from one poll, ungrouped first: a busy group must
    not starve the work nobody restricted."""
    ungrouped = _FakeMsg({"job_id": "job-plain", "tenant_id": "acme-eu"})
    grouped = _FakeMsg({"job_id": "job-pci", "tenant_id": "acme-eu", "agent_group": "pci"})
    session = _connected_session(
        _FakeSub(ungrouped), _FakeSub(grouped), tenant_id="acme-eu", agent_group="pci"
    )

    class _Client:
        def claim(self, agent_id: str, *, job_id: str | None = None):
            return {"job_id": job_id}

    try:
        first = session.pull_and_claim(_Client(), "agent-1", timeout=1.0)
        second = session.pull_and_claim(_Client(), "agent-1", timeout=1.0)
    finally:
        session.close()

    assert first is not None and first["job_id"] == "job-plain"
    assert second is not None and second["job_id"] == "job-pci"
    assert ungrouped.acked and grouped.acked


def test_the_nats_path_still_asks_the_api_when_no_offer_arrives(monkeypatch):
    """An offer is published once and its delivery attempts are finite.

    An agent that cannot run the job NAKs it — the one without the
    ``scan_policy`` capability does exactly that (#362) — and the durable
    consumer is shared by the whole (tenant, group), so a few of those and the
    offer is gone for everyone. The NATS path had no other way to find work,
    and the job stayed ``queued`` for ever next to an agent able to take it.
    """
    import argparse

    claims = 0
    pulls = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1", "hostname": "edge-1", "tenant_id": "t1"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": "a1"}

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            nonlocal claims
            claims += 1
            return None

    class _Session:
        agent_group = None

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def start(self) -> None:
            pass

        def close(self) -> None:
            pass

        def pull_and_claim(self, *args: Any, **kwargs: Any) -> None:
            # No offer, poll after poll: the queue is not empty, the message
            # that advertised it is. Bounded so that a loop which never asks
            # the API fails the assertion below rather than spinning.
            nonlocal pulls
            pulls += 1
            if pulls > 3:
                raise KeyboardInterrupt
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker, "AgentNatsSession", _Session)
    monkeypatch.setattr(worker, "check_nats_transport", lambda url: None)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8080",
        token="static-token",
        timeout=1.0,
        provisioning_key="",
        jwt_refresh_seconds=1800,
        agent_id="a1",
        hostname="edge-1",
        label=None,
        nats_url="nats://127.0.0.1:4222",
        poll_interval=0.01,
        config="scanner/config/default.yaml",
        output_dir="out",
        scan_timeout=1.0,
    )

    assert worker.run_loop(args) == 0
    assert claims == 1, "the NATS path never fell back to the API"
