"""NATS → ClickHouse ingest consumer (Phase 3.2).

Pulls from JetStream stream ``INGEST`` (subjects ``ingest.>``), transforms
archives, bulk-inserts into ClickHouse. Runs in a background thread when
``OCTO_CLICKHOUSE_URL`` and ``OCTO_NATS_URL`` are both set.
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from api.services import ch_transform
from api.services import clickhouse_client as ch
from api.services.nats_bus import STREAM_INGEST
from api.settings import Settings

LOG = logging.getLogger("octo-man.ch-ingest")

CONSUMER_CH_INGEST = "octo-ch-ingest"
SUBJECT_FILTER = "ingest.>"


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
                    continue
                for msg in msgs:
                    await self._handle_msg(client, msg)
        finally:
            await nc.drain()

    async def _handle_msg(self, client: Any, msg: Any) -> None:
        try:
            payload = json.loads(msg.data.decode("utf-8"))
            if not isinstance(payload, dict):
                await msg.term()
                return
            # Prefer tenant subject messages; still accept legacy ingest.raw_results.
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
            LOG.exception("Failed to process ingest message")
            try:
                await msg.nak()
            except Exception:  # noqa: BLE001
                pass


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
