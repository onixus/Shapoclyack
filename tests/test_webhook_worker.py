"""Phase 10.3: the two background workers behind webhook delivery.

The NATS connection and the delivery loop are stubbed out here — what is worth
asserting is the wiring: which halves start under which flags, that a bad event
is terminated rather than redelivered forever, and that a database blip is
nak'd so JetStream brings the event back.
"""

from __future__ import annotations

import asyncio
import json
import logging
from types import SimpleNamespace

import pytest
from nats.js.api import DeliverPolicy
from nats.js.errors import NotFoundError

from api.services.integrations import webhook_worker
from api.settings import Settings


class _Msg:
    """Minimal stand-in for a JetStream message; records the terminal call."""

    def __init__(self, payload: bytes, subject: str = "events.asset.acme.new_cve") -> None:
        self.data = payload
        self.subject = subject
        self.acked = False
        self.naked = False
        self.termed = False

    async def ack(self) -> None:
        self.acked = True

    async def nak(self) -> None:
        self.naked = True

    async def term(self) -> None:
        self.termed = True


def _envelope() -> bytes:
    return json.dumps(
        {"kind": "new_cve", "tenant_id": "acme", "event_id": "ev-1", "data": {}}
    ).encode("utf-8")


@pytest.fixture(autouse=True)
def _no_leftover_workers():
    yield
    webhook_worker.stop_worker()


def test_valid_event_is_queued_and_acked(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(
        webhook_worker.webhooks, "enqueue_event", lambda envelope: seen.append(envelope) or ["whd_1"]
    )
    worker = webhook_worker.WebhookFanoutWorker(nats_url="nats://unused")
    msg = _Msg(_envelope())

    asyncio.run(worker._handle_msg(msg))

    assert seen[0]["event_id"] == "ev-1"
    assert (msg.acked, msg.naked, msg.termed) == (True, False, False)
    assert worker.stats == {"messages": 1, "queued": 1, "errors": 0}


@pytest.mark.parametrize("payload", [b"not json", b'"a string, not an envelope"'])
def test_unusable_message_is_terminated_not_retried(monkeypatch, payload):
    """Redelivering it will not make it parse — retrying is pure noise."""
    monkeypatch.setattr(
        webhook_worker.webhooks,
        "enqueue_event",
        lambda envelope: pytest.fail("enqueue_event called for an unusable message"),
    )
    worker = webhook_worker.WebhookFanoutWorker(nats_url="nats://unused")
    msg = _Msg(payload)

    asyncio.run(worker._handle_msg(msg))

    assert msg.termed is True
    assert msg.acked is False


def test_database_failure_naks_so_the_event_comes_back(monkeypatch):
    def _boom(envelope):
        raise RuntimeError("postgres unavailable")

    monkeypatch.setattr(webhook_worker.webhooks, "enqueue_event", _boom)
    worker = webhook_worker.WebhookFanoutWorker(nats_url="nats://unused")
    msg = _Msg(_envelope())

    asyncio.run(worker._handle_msg(msg))

    assert (msg.naked, msg.acked, msg.termed) == (True, False, False)
    assert worker.stats["errors"] == 1


class _Js:
    def __init__(self, *, exists: bool = False, policy=None) -> None:
        self.exists = exists
        self.policy = policy
        self.added: list = []

    async def consumer_info(self, stream, name):
        if not self.exists:
            raise NotFoundError()
        return SimpleNamespace(config=SimpleNamespace(deliver_policy=self.policy))

    async def add_consumer(self, stream, config):
        self.added.append((stream, config))
        self.exists = True


def test_ensure_fanout_creates_new_policy_when_missing():
    js = _Js()
    asyncio.run(webhook_worker.ensure_fanout_consumer(js))
    assert len(js.added) == 1
    stream, config = js.added[0]
    assert stream == webhook_worker.STREAM_EVENTS
    assert config.durable_name == webhook_worker.CONSUMER_WEBHOOK_FANOUT
    assert config.deliver_policy == DeliverPolicy.NEW


def test_ensure_fanout_leaves_an_existing_consumer_alone():
    js = _Js(exists=True, policy=DeliverPolicy.NEW)
    asyncio.run(webhook_worker.ensure_fanout_consumer(js))
    assert js.added == []


def test_ensure_fanout_warns_when_the_existing_policy_is_all(caplog):
    js = _Js(exists=True, policy=DeliverPolicy.ALL)
    with caplog.at_level(logging.WARNING):
        asyncio.run(webhook_worker.ensure_fanout_consumer(js))
    assert js.added == []
    assert "DeliverPolicy.NEW" in caplog.text


def test_dispatcher_tick_accumulates_outcomes_and_reports_the_queue(monkeypatch):
    monkeypatch.setattr(
        webhook_worker.webhooks,
        "dispatch_once",
        lambda: {"attempted": 3, "delivered": 2, "retrying": 1, "dead": 0},
    )
    monkeypatch.setattr(
        webhook_worker.webhooks,
        "queue_depth",
        lambda: {"pending": 4, "delivered": 2, "dead": 1},
    )
    pruned: list[int] = []
    monkeypatch.setattr(
        webhook_worker.webhooks, "prune_deliveries", lambda: pruned.append(1) or 0
    )

    dispatcher = webhook_worker.WebhookDispatcher(settings=Settings())
    dispatcher._tick()
    dispatcher._tick()

    assert dispatcher.stats["ticks"] == 2
    assert dispatcher.stats["delivered"] == 4
    assert dispatcher.stats["retrying"] == 2
    assert (
        webhook_worker.metrics.WEBHOOK_DELIVERY_QUEUE.labels(status="dead")._value.get() == 1
    )
    # Retention is hourly, not per tick: it is a DELETE running in every replica.
    assert len(pruned) == 1


def test_first_prune_does_not_depend_on_host_uptime(monkeypatch):
    """monotonic() counts from the host's boot, not from this process's start.

    Seeding "last pruned" with 0.0 therefore made the first sweep wait for the
    *machine's* uptime to pass the interval — deferred on a freshly booted node,
    immediate on a long-lived one. A newly booted CI runner is exactly the first
    case, which is how this was caught.
    """
    monkeypatch.setattr(
        webhook_worker.webhooks,
        "dispatch_once",
        lambda: {"attempted": 0, "delivered": 0, "retrying": 0, "dead": 0},
    )
    monkeypatch.setattr(webhook_worker.webhooks, "queue_depth", lambda: {})
    pruned: list[int] = []
    monkeypatch.setattr(
        webhook_worker.webhooks, "prune_deliveries", lambda: pruned.append(1) or 0
    )
    # A host up for five seconds — far below the one-hour retention interval.
    clock = iter([5.0, 6.0, 5.0 + webhook_worker._PRUNE_INTERVAL_SECONDS])
    monkeypatch.setattr(webhook_worker.time, "monotonic", lambda: next(clock))

    dispatcher = webhook_worker.WebhookDispatcher(settings=Settings())
    dispatcher._tick()
    assert len(pruned) == 1, "first tick must sweep whatever the host's uptime is"

    dispatcher._tick()
    assert len(pruned) == 1, "second tick is inside the interval"

    dispatcher._tick()
    assert len(pruned) == 2, "an interval later it sweeps again"


def test_dispatcher_tick_failure_is_counted_not_fatal(monkeypatch):
    dispatcher = webhook_worker.WebhookDispatcher(settings=Settings())

    def _boom():
        # Stop after this pass, so the loop is exercised exactly once.
        dispatcher._stop.set()
        raise RuntimeError("db down")

    monkeypatch.setattr(webhook_worker.webhooks, "dispatch_once", _boom)

    dispatcher._run()

    assert dispatcher.stats["errors"] == 1


def test_start_worker_respects_the_flags(monkeypatch):
    started: list[str] = []
    monkeypatch.setattr(
        webhook_worker.WebhookDispatcher, "start", lambda self: started.append("dispatch")
    )
    monkeypatch.setattr(
        webhook_worker.WebhookFanoutWorker, "start", lambda self: started.append("fanout")
    )

    webhook_worker.start_worker(Settings(webhooks_enabled=False, nats_url="nats://x"))
    assert started == []

    # Dispatch off: outbound HTTP does not run here, but the fan-out consumer
    # still turns events into delivery rows for whichever replica does (#153).
    webhook_worker.start_worker(
        Settings(webhooks_enabled=True, webhook_dispatch_enabled=False, nats_url="nats://x")
    )
    assert started == ["fanout"]
    assert webhook_worker.worker_stats() == {"fanout": webhook_worker._FANOUT.stats}
    webhook_worker.stop_worker()
    started.clear()

    # Fan-out off: an egress-only replica that opens connections to receivers
    # and never touches the broker.
    webhook_worker.start_worker(
        Settings(webhooks_enabled=True, webhook_fanout_enabled=False, nats_url="nats://x")
    )
    assert started == ["dispatch"]
    webhook_worker.stop_worker()
    started.clear()

    # Both off: API-only — subscriptions, DLQ and audit trail, no threads.
    webhook_worker.start_worker(
        Settings(
            webhooks_enabled=True,
            webhook_dispatch_enabled=False,
            webhook_fanout_enabled=False,
            nats_url="nats://x",
        )
    )
    assert started == []
    assert webhook_worker.worker_stats() is None

    # No broker: nothing to consume, but the DLQ is still replayable.
    webhook_worker.start_worker(Settings(webhooks_enabled=True, nats_url=""))
    assert started == ["dispatch"]
    assert webhook_worker.worker_stats() == {"dispatch": webhook_worker._DISPATCHER.stats}
    webhook_worker.stop_worker()
    assert webhook_worker.worker_stats() is None

    started.clear()
    webhook_worker.start_worker(Settings(webhooks_enabled=True, nats_url="nats://x"))
    assert sorted(started) == ["dispatch", "fanout"]


def test_start_worker_is_idempotent(monkeypatch):
    starts: list[str] = []
    monkeypatch.setattr(
        webhook_worker.WebhookDispatcher, "start", lambda self: starts.append("dispatch")
    )
    settings = Settings(webhooks_enabled=True, nats_url="")

    webhook_worker.start_worker(settings)
    webhook_worker.start_worker(settings)

    assert starts == ["dispatch"]
