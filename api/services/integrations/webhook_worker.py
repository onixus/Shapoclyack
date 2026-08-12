"""Background threads behind webhook delivery (ROADMAP P2 / Phase 10.3).

Two independent workers, started and stopped from the FastAPI lifespan:

``WebhookFanoutWorker``
    A JetStream durable pull consumer on ``events.asset.>`` that turns each
    event into rows in ``webhook_deliveries``. It only writes the queue — it
    never POSTs — so a slow receiver can never stall consumption of the event
    stream, and an event is acked once it is durably queued.

``WebhookDispatcher``
    A timer that drains the due end of that queue. Safe in every replica
    without leader election, like ``job_reaper``: due-ness is a property of the
    row and claims are taken with ``FOR UPDATE SKIP LOCKED``, so concurrent
    dispatchers divide the queue rather than duplicating it.

The split is also what makes the DLQ replayable with the broker down: a
requeued delivery is a row, and the dispatcher needs no NATS to send it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any

from api.services import metrics
from api.services.integrations import webhooks
from api.services.nats_bus import STREAM_EVENTS
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.webhooks")

CONSUMER_WEBHOOK_FANOUT = "octo-webhook-fanout"
SUBJECT_FILTER = "events.asset.>"

# How often the dispatcher prunes the audit trail. The sweep is one bounded
# DELETE, but it runs on every replica, so it does not belong on the 5s tick.
_PRUNE_INTERVAL_SECONDS = 3600.0


class WebhookFanoutWorker:
    """events.asset.* → webhook_deliveries rows."""

    def __init__(self, *, nats_url: str, fetch_timeout: float = 5.0) -> None:
        self._nats_url = nats_url
        self._fetch_timeout = fetch_timeout
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"messages": 0, "queued": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-webhook-fanout", daemon=True)
        self._thread.start()
        LOG.info("Webhook fan-out worker started (stream=%s)", STREAM_EVENTS)

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Webhook fan-out worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                asyncio.run(self._consume_loop())
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Webhook fan-out loop crashed; restarting")
                if self._stop.wait(2.0):
                    break

    async def _consume_loop(self) -> None:
        import nats
        from nats.errors import TimeoutError as NatsTimeout
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

        nc = await nats.connect(self._nats_url, name="octo-webhook-fanout", connect_timeout=5)
        try:
            js = nc.jetstream()
            try:
                sub = await js.pull_subscribe(
                    SUBJECT_FILTER, durable=CONSUMER_WEBHOOK_FANOUT, stream=STREAM_EVENTS
                )
            except Exception:  # noqa: BLE001 - consumer does not exist yet
                await js.add_consumer(
                    STREAM_EVENTS,
                    ConsumerConfig(
                        durable_name=CONSUMER_WEBHOOK_FANOUT,
                        ack_policy=AckPolicy.EXPLICIT,
                        filter_subject=SUBJECT_FILTER,
                        # NEW, not ALL: a webhook created today should not fire
                        # a month of retained history at its receiver the first
                        # time this consumer is created.
                        deliver_policy=DeliverPolicy.NEW,
                        max_deliver=5,
                    ),
                )
                sub = await js.pull_subscribe(
                    SUBJECT_FILTER, durable=CONSUMER_WEBHOOK_FANOUT, stream=STREAM_EVENTS
                )

            LOG.info(
                "Webhook fan-out subscribed stream=%s consumer=%s",
                STREAM_EVENTS,
                CONSUMER_WEBHOOK_FANOUT,
            )
            while not self._stop.is_set():
                try:
                    msgs = await sub.fetch(10, timeout=self._fetch_timeout)
                except NatsTimeout:
                    await self._report_lag(sub)
                    continue
                await self._report_lag(sub)
                for msg in msgs:
                    await self._handle_msg(msg)
        finally:
            await _drain(nc)

    async def _report_lag(self, sub: Any) -> None:
        try:
            info = await sub.consumer_info()
            metrics.NATS_CONSUMER_PENDING.labels(consumer=CONSUMER_WEBHOOK_FANOUT).set(
                info.num_pending
            )
        except Exception:  # noqa: BLE001
            pass

    async def _handle_msg(self, msg: Any) -> None:
        try:
            envelope = json.loads(msg.data.decode("utf-8"))
        except Exception:  # noqa: BLE001
            # Undecodable: redelivering it will not make it parse.
            self._stats["errors"] += 1
            LOG.warning("Dropping unparseable asset event on %s", getattr(msg, "subject", "?"))
            await _term(msg)
            return
        if not isinstance(envelope, dict):
            await _term(msg)
            return
        try:
            created = await asyncio.to_thread(webhooks.enqueue_event, envelope)
        except Exception:  # noqa: BLE001
            self._stats["errors"] += 1
            LOG.exception("Failed to queue webhook deliveries for event %s", envelope.get("event_id"))
            # nak, not term: the database being briefly unavailable is exactly
            # what redelivery is for.
            await _nak(msg)
            return
        self._stats["messages"] += 1
        self._stats["queued"] += len(created)
        await _ack(msg)


class WebhookDispatcher:
    """Drains due webhook deliveries on a timer."""

    def __init__(self, *, settings: Settings) -> None:
        self._settings = settings
        self._poll_interval = max(1.0, float(settings.webhook_dispatch_interval_seconds))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_prune = 0.0
        self._stats = {"ticks": 0, "attempted": 0, "delivered": 0, "retrying": 0, "dead": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-webhook-dispatch", daemon=True
        )
        self._thread.start()
        LOG.info(
            "Webhook dispatcher started (interval=%.0fs batch=%d max_attempts=%d)",
            self._poll_interval,
            self._settings.webhook_dispatch_batch_size,
            self._settings.webhook_max_attempts,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("Webhook dispatcher stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Webhook dispatch tick failed")
            self._stop.wait(self._poll_interval)

    def _tick(self) -> None:
        self._stats["ticks"] += 1
        outcome = webhooks.dispatch_once()
        for key in ("attempted", "delivered", "retrying", "dead"):
            self._stats[key] += outcome[key]
        for status, count in webhooks.queue_depth().items():
            metrics.WEBHOOK_DELIVERY_QUEUE.labels(status=status).set(count)
        now = time.monotonic()
        if now - self._last_prune >= _PRUNE_INTERVAL_SECONDS:
            self._last_prune = now
            webhooks.prune_deliveries()


async def _ack(msg: Any) -> None:
    try:
        await msg.ack()
    except Exception:  # noqa: BLE001
        pass


async def _nak(msg: Any) -> None:
    try:
        await msg.nak()
    except Exception:  # noqa: BLE001
        pass


async def _term(msg: Any) -> None:
    try:
        await msg.term()
    except Exception:  # noqa: BLE001
        pass


async def _drain(nc: Any) -> None:
    if nc is None:
        return
    try:
        if not nc.is_closed:
            await nc.drain()
    except Exception:  # noqa: BLE001
        pass
    try:
        if not nc.is_closed:
            await nc.close()
    except Exception:  # noqa: BLE001
        pass
    current = asyncio.current_task()
    pending = [task for task in asyncio.all_tasks() if task is not current and not task.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    await asyncio.sleep(0.05)


_FANOUT: WebhookFanoutWorker | None = None
_DISPATCHER: WebhookDispatcher | None = None


def start_worker(settings: Settings) -> None:
    """Start whichever halves this deployment can run.

    The dispatcher runs whenever webhooks and dispatch are both enabled; the
    fan-out consumer additionally needs a broker, since with no NATS there is
    no event stream to consume. A broker-less installation can still create
    subscriptions, send a test delivery, and replay the DLQ — deliveries are
    rows, and the dispatcher reads them from Postgres.
    """
    global _FANOUT, _DISPATCHER
    if not settings.webhooks_enabled or not settings.webhook_dispatch_enabled:
        return
    if _DISPATCHER is None:
        _DISPATCHER = WebhookDispatcher(settings=settings)
        _DISPATCHER.start()
    if _FANOUT is None and settings.nats_url.strip():
        _FANOUT = WebhookFanoutWorker(nats_url=settings.nats_url)
        _FANOUT.start()


def stop_worker() -> None:
    global _FANOUT, _DISPATCHER
    if _FANOUT is not None:
        _FANOUT.stop()
        _FANOUT = None
    if _DISPATCHER is not None:
        _DISPATCHER.stop()
        _DISPATCHER = None


def worker_stats() -> dict[str, dict[str, int]] | None:
    if _FANOUT is None and _DISPATCHER is None:
        return None
    stats: dict[str, dict[str, int]] = {}
    if _FANOUT is not None:
        stats["fanout"] = _FANOUT.stats
    if _DISPATCHER is not None:
        stats["dispatch"] = _DISPATCHER.stats
    return stats
