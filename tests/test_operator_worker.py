"""Worker lifecycle: cancellation drains inference before releasing the claim."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from api.services.local_operator import worker


class FakeLeader:
    acquired = True
    released = False

    def __init__(self, *args, **kwargs):
        self.__class__.instances.append(self)

    instances = []

    def acquire(self):
        return self.acquired

    def release(self):
        self.released = True


@pytest.fixture()
def setup(monkeypatch):
    settings = SimpleNamespace(operator_enabled=True, operator_worker_enabled=True,
        operator_timeout_seconds=120, operator_worker_poll_seconds=.01,
        operator_worker_lease_seconds=180, postgres_url="unused")
    calls = []
    FakeLeader.instances = []
    monkeypatch.setattr(worker, "LeaderLock", FakeLeader)
    monkeypatch.setattr(worker.retention, "sweep", lambda *a, **k: 0)
    monkeypatch.setattr(worker.store, "recover_expired", lambda *a: 0)
    monkeypatch.setattr(worker.store, "claim_next", lambda *a, **k: {"task_id": "task"})
    monkeypatch.setattr(worker.store, "is_cancel_requested", lambda *a: False)
    monkeypatch.setattr(worker.store, "finish_task", lambda *a, **k: calls.append(k))
    return settings, calls


def test_once_finishes_success_and_releases_leader(setup, monkeypatch):
    settings, calls = setup

    async def execute(*args):
        return {"summary": "bounded"}

    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    asyncio.run(worker.run_worker(settings, once=True))
    assert calls == [{"result": {"summary": "bounded"}, "error": None}]
    assert FakeLeader.instances[0].released


@pytest.mark.parametrize("disabled", ["operator_enabled", "operator_worker_enabled"])
def test_disabled_worker_never_claims(setup, monkeypatch, disabled):
    settings, calls = setup
    setattr(settings, disabled, False)
    monkeypatch.setattr(worker.store, "claim_next", lambda *a, **k: pytest.fail("claimed while disabled"))
    asyncio.run(worker.run_worker(settings, once=True))
    assert calls == []


def test_follower_never_claims(setup, monkeypatch):
    settings, _ = setup
    monkeypatch.setattr(FakeLeader, "acquired", False)
    monkeypatch.setattr(worker.store, "claim_next", lambda *a, **k: pytest.fail("follower claimed"))
    asyncio.run(worker.run_worker(settings, once=True))


@pytest.mark.parametrize("reason", ["cancel", "shutdown", "leadership", "disable"])
def test_cancellation_awaits_provider_cleanup_before_finish(setup, monkeypatch, reason):
    settings, calls = setup
    events = []
    polls = 0
    stop = asyncio.Event()

    async def execute(*args):
        events.append("started")
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(.01)
            events.append("drained")

    def check(*args):
        nonlocal polls
        polls += 1
        if polls < 2:
            return False
        if reason == "shutdown":
            stop.set()
        elif reason == "leadership":
            FakeLeader.instances[0].acquired = False
        elif reason == "disable":
            settings.operator_worker_enabled = False
        return reason == "cancel"

    def finish(*args, **kwargs):
        assert events == ["started", "drained"]
        calls.append(kwargs)

    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    monkeypatch.setattr(worker.store, "is_cancel_requested", check)
    monkeypatch.setattr(worker.store, "finish_task", finish)
    asyncio.run(worker.run_worker(settings, once=True, stop=stop))
    assert calls[0]["error"] == ("operator_cancelled" if reason == "cancel" else "operator_interrupted")
    assert FakeLeader.instances[0].released


def test_provider_failure_does_not_record_or_log_raw_error(setup, monkeypatch, caplog):
    settings, calls = setup

    async def execute(*args):
        raise RuntimeError("secret provider response")

    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    asyncio.run(worker.run_worker(settings, once=True))
    assert calls == [{"result": None, "error": "operator_execution_failed"}]
    assert "secret provider response" not in caplog.text


def test_external_cancel_drains_and_marks_interrupted(setup, monkeypatch):
    settings, calls = setup
    drained = []

    async def execute(*args):
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(.01)
            drained.append(True)

    async def run():
        running = asyncio.create_task(worker.run_worker(settings, once=True))
        await asyncio.sleep(.02)
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running

    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    asyncio.run(run())
    assert drained == [True]
    assert calls == [{"result": None, "error": "operator_interrupted"}]
    assert FakeLeader.instances[0].released


@pytest.mark.parametrize("poll,lease", [(0,180),(float("nan"),180),(True,180),(2,149),(2,True)])
def test_invalid_runtime_bounds_fail_before_claim(setup, poll, lease):
    settings, calls = setup
    settings.operator_worker_poll_seconds = poll
    settings.operator_worker_lease_seconds = lease
    with pytest.raises(ValueError, match="invalid_operator_worker"):
        asyncio.run(worker.run_worker(settings, once=True))
    assert calls == []


def test_recovery_precedes_claim_and_never_runs_in_follower(setup, monkeypatch):
    settings, _ = setup
    events = []
    monkeypatch.setattr(worker.store, "recover_expired", lambda *a: events.append("recover"))
    monkeypatch.setattr(worker.store, "claim_next", lambda *a, **k: events.append("claim"))
    asyncio.run(worker.run_worker(settings, once=True))
    assert events == ["recover", "claim"]
    events.clear()
    monkeypatch.setattr(FakeLeader, "acquired", False)
    asyncio.run(worker.run_worker(settings, once=True))
    assert events == []


def test_total_execution_deadline_cancels_and_drains(setup, monkeypatch):
    settings, calls = setup
    settings.operator_timeout_seconds = .02
    monkeypatch.setattr(worker, "_EXECUTION_GRACE_SECONDS", 0)
    drained = []

    async def execute(*args):
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(.01)
            drained.append(True)

    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    asyncio.run(worker.run_worker(settings, once=True))
    assert drained == [True]
    assert calls == [{"result": None, "error": "operator_timeout"}]
    assert FakeLeader.instances[0].released


def test_retention_is_bounded_to_once_per_minute_and_runs_before_claim(setup, monkeypatch):
    settings, _ = setup
    events = []
    moments = iter([100.0, 101.0, 159.9, 160.0])
    stop = asyncio.Event()
    claims = 0
    monkeypatch.setattr(worker, "monotonic", lambda: next(moments))
    monkeypatch.setattr(worker.retention, "sweep",
                        lambda *a, **k: events.append(("sweep", k["limit"])))

    def claim(*args, **kwargs):
        nonlocal claims
        claims += 1
        events.append(("claim", claims))
        if claims == 4:
            stop.set()

    monkeypatch.setattr(worker.store, "claim_next", claim)
    asyncio.run(worker.run_worker(settings, stop=stop))
    assert events == [("sweep", 20), ("claim", 1), ("claim", 2), ("claim", 3),
                      ("sweep", 20), ("claim", 4)]


@pytest.mark.parametrize("mode", ["follower", "disabled"])
def test_retention_never_runs_without_enabled_leader(setup, monkeypatch, mode):
    settings, _ = setup
    if mode == "follower":
        monkeypatch.setattr(FakeLeader, "acquired", False)
    else:
        settings.operator_worker_enabled = False
    monkeypatch.setattr(worker.retention, "sweep", lambda *a, **k: pytest.fail("retention without leader"))
    asyncio.run(worker.run_worker(settings, once=True))


def test_retention_error_is_sanitized_and_does_not_block_claim(setup, monkeypatch, caplog):
    settings, calls = setup

    def fail(*args, **kwargs):
        raise RuntimeError("sensitive retention database error")

    async def execute(*args):
        return {"summary": "bounded"}

    monkeypatch.setattr(worker.retention, "sweep", fail)
    monkeypatch.setattr(worker.gateway, "execute_task", execute)
    asyncio.run(worker.run_worker(settings, once=True))
    assert calls == [{"result": {"summary": "bounded"}, "error": None}]
    assert "Operator history maintenance failed" in caplog.text
    assert "sensitive retention database error" not in caplog.text
