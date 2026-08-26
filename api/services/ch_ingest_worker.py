"""NATS → ClickHouse ingest consumer (Phase 3.2).

Pulls scan results from JetStream stream ``INGEST``, transforms archives,
bulk-inserts into ClickHouse. Runs in a background thread when
``OCTO_CLICKHOUSE_URL`` and ``OCTO_NATS_URL`` are both set.

The consumer filters on ``ingest.results.>`` rather than on the stream's whole
``ingest.>`` tree. Phase S8 put endpoint inventory on
``ingest.endpoint_inventory.{tenant}``, which the wide filter also delivered
here: every inventory event was fetched one at a time by the single-threaded
pull loop, transformed into nothing, acked, and counted as a successful
ClickHouse ingest — inflating the SLO 6 denominator with empties (#230). The
legacy ``ingest.raw_results`` copy of every result drops out with it, so a
result is no longer transformed and inserted twice.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from typing import Any

from api.services import ch_transform
from api.services import clickhouse_client as ch
from api.services import metrics as metrics_service
from api.services.nats_bus import STREAM_INGEST
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.ch-ingest")

# Renamed together with the narrowed filter: JetStream will not change the
# filter subject of an existing durable, so a deployment upgrading in place
# would keep consuming ``ingest.>`` under the old name. See docs/operations.md
# for removing the retired ``octo-ch-ingest`` consumer.
CONSUMER_CH_INGEST = "octo-ch-ingest-results"
SUBJECT_FILTER = "ingest.results.>"
SUBJECT_PREFIX = "ingest.results."


def is_ingest_results_subject(subject: str) -> bool:
    """True for the scan-result subjects this worker exists to consume."""
    return (subject or "").startswith(SUBJECT_PREFIX)


class ClickHouseIngestWorker:
    def __init__(
        self,
        *,
        nats_url: str,
        clickhouse_url: str,
        fetch_timeout: float = 5.0,
        settings: Settings | None = None,
    ) -> None:
        self._nats_url = nats_url
        self._clickhouse_url = clickhouse_url
        self._fetch_timeout = fetch_timeout
        self._settings = settings
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"messages": 0, "vuln_rows": 0, "port_rows": 0, "errors": 0}

    @property
    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="octo-ch-ingest",
            daemon=True,
        )
        self._thread.start()
        LOG.info("ClickHouse ingest worker started")

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        LOG.info("ClickHouse ingest worker stopped stats=%s", self._stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                asyncio.run(self._consume_loop())
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("ClickHouse ingest loop crashed; restarting")
                if self._stop.wait(2.0):
                    break

    async def _consume_loop(self) -> None:
        import nats
        from nats.errors import TimeoutError as NatsTimeout
        from nats.js.api import AckPolicy, ConsumerConfig, DeliverPolicy

        nc = await nats.connect(self._nats_url, name="octo-ch-ingest", connect_timeout=5)
        try:
            js = nc.jetstream()
            try:
                sub = await js.pull_subscribe(
                    SUBJECT_FILTER,
                    durable=CONSUMER_CH_INGEST,
                    stream=STREAM_INGEST,
                )
            except Exception:
                await js.add_consumer(
                    STREAM_INGEST,
                    ConsumerConfig(
                        durable_name=CONSUMER_CH_INGEST,
                        ack_policy=AckPolicy.EXPLICIT,
                        filter_subject=SUBJECT_FILTER,
                        deliver_policy=DeliverPolicy.ALL,
                        max_deliver=5,
                    ),
                )
                sub = await js.pull_subscribe(
                    SUBJECT_FILTER,
                    durable=CONSUMER_CH_INGEST,
                    stream=STREAM_INGEST,
                )

            client = ch.get_client(self._clickhouse_url)
            LOG.info("CH ingest subscribed stream=%s consumer=%s", STREAM_INGEST, CONSUMER_CH_INGEST)

            while not self._stop.is_set():
                try:
                    msgs = await sub.fetch(1, timeout=self._fetch_timeout)
                except NatsTimeout:
                    await self._report_consumer_lag(sub)
                    continue
                await self._report_consumer_lag(sub)
                for msg in msgs:
                    await self._handle_msg(client, msg)
        finally:
            if nc is not None:
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
                pending = [t for t in asyncio.all_tasks() if t is not current and not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                await asyncio.sleep(0.05)

    async def _report_consumer_lag(self, sub: Any) -> None:
        try:
            info = await sub.consumer_info()
            metrics_service.NATS_CONSUMER_PENDING.labels(consumer=CONSUMER_CH_INGEST).set(
                info.num_pending
            )
        except Exception:  # noqa: BLE001
            pass

    async def _handle_msg(self, client: Any, msg: Any) -> None:
        start = time.perf_counter()
        try:
            # Second line of defence behind the consumer filter: a durable left
            # over from before #230 still delivers ingest.endpoint_inventory.*
            # here, and those must not be counted as ingested results.
            subject = getattr(msg, "subject", "") or ""
            if not is_ingest_results_subject(subject):
                LOG.debug("CH ingest skipping foreign subject %s", subject)
                await msg.ack()
                return
            payload = json.loads(msg.data.decode("utf-8"))
            if not isinstance(payload, dict):
                await msg.term()
                return
            vuln_rows, port_rows = await asyncio.to_thread(
                ch_transform.transform_ingest_payload,
                payload,
                settings=self._settings,
            )
            inserted_v = await asyncio.to_thread(
                ch.insert_rows,
                client,
                ch.VULN_TABLE,
                ch.VULN_COLUMNS,
                vuln_rows,
            )
            inserted_p = await asyncio.to_thread(
                ch.insert_rows,
                client,
                ch.PORTS_TABLE,
                ch.PORT_COLUMNS,
                port_rows,
            )
            self._stats["messages"] += 1
            self._stats["vuln_rows"] += inserted_v
            self._stats["port_rows"] += inserted_p
            metrics_service.CH_INGEST_MESSAGES_TOTAL.labels(result="ok").inc()
            await msg.ack()
            LOG.info(
                "Ingested job=%s run=%s vulns=%s ports=%s",
                payload.get("job_id"),
                payload.get("run_id"),
                inserted_v,
                inserted_p,
            )
        except Exception:  # noqa: BLE001
            self._stats["errors"] += 1
            metrics_service.CH_INGEST_MESSAGES_TOTAL.labels(result="error").inc()
            LOG.exception("Failed to process ingest message")
            try:
                await msg.nak()
            except Exception:  # noqa: BLE001
                pass
        finally:
            metrics_service.CH_INGEST_BATCH_DURATION_SECONDS.observe(time.perf_counter() - start)


_WORKER: ClickHouseIngestWorker | None = None


def start_worker(
    *, nats_url: str, clickhouse_url: str, settings: Settings | None = None
) -> ClickHouseIngestWorker | None:
    global _WORKER
    if not nats_url.strip() or not clickhouse_url.strip():
        return None
    if _WORKER is not None:
        return _WORKER
    worker = ClickHouseIngestWorker(
        nats_url=nats_url, clickhouse_url=clickhouse_url, settings=settings
    )
    worker.start()
    _WORKER = worker
    return worker


def stop_worker() -> None:
    global _WORKER
    if _WORKER is not None:
        _WORKER.stop()
        _WORKER = None


def worker_stats() -> dict[str, int] | None:
    if _WORKER is None:
        return None
    return _WORKER.stats
