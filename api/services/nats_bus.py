"""NATS JetStream bus for job dispatch and raw-result ingest (Phase 1).

Subjects (streams created on connect when missing):
  - jobs.scan          → stream JOBS
  - ingest.raw_results → stream INGEST

Set OCTO_NATS_URL to enable. Empty URL keeps legacy HTTP-only agent flow.
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from typing import Any

LOG = logging.getLogger("octo-man.nats")

SUBJECT_JOBS_SCAN = "jobs.scan"
SUBJECT_INGEST_RAW = "ingest.raw_results"

STREAM_JOBS = "JOBS"
STREAM_INGEST = "INGEST"

# Durable pull consumer for remote agents (queue group = fair dispatch).
CONSUMER_AGENTS = "octo-agents"


@dataclass(frozen=True)
class NatsConfig:
    url: str
    connect_timeout: float = 5.0


class NatsBus:
    """Background asyncio loop + JetStream helpers usable from sync FastAPI code."""

    def __init__(self, config: NatsConfig) -> None:
        self._config = config
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, name="octo-nats", daemon=True)
        self._nc: Any = None
        self._js: Any = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._started = False

    @property
    def enabled(self) -> bool:
        return bool(self._config.url.strip())

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def start(self) -> None:
        if not self.enabled or self._started:
            return
        self._thread.start()
        fut = asyncio.run_coroutine_threadsafe(self._connect(), self._loop)
        try:
            fut.result(timeout=self._config.connect_timeout + 10)
            self._started = True
            self._ready.set()
            atexit.register(self.close)
            LOG.info("NATS JetStream connected (%s)", self._config.url)
        except Exception as exc:  # noqa: BLE001
            self._error = exc
            LOG.exception("NATS connect failed; bus disabled for this process")
            self.close()

    async def _connect(self) -> None:
        import nats
        from nats.js.api import (
            AckPolicy,
            ConsumerConfig,
            RetentionPolicy,
            StorageType,
            StreamConfig,
        )

        self._nc = await nats.connect(
            self._config.url,
            connect_timeout=self._config.connect_timeout,
            max_reconnect_attempts=5,
            name="octo-man-api",
        )
        self._js = self._nc.jetstream()
        await self._ensure_stream(
            StreamConfig(
                name=STREAM_JOBS,
                subjects=["jobs.>"],
                retention=RetentionPolicy.WORK_QUEUE,
                storage=StorageType.FILE,
                max_msgs=100_000,
                duplicate_window=120_000_000_000,  # 120s in nanoseconds
            )
        )
        await self._ensure_stream(
            StreamConfig(
                name=STREAM_INGEST,
                subjects=["ingest.>"],
                retention=RetentionPolicy.LIMITS,
                storage=StorageType.FILE,
                max_msgs=500_000,
                duplicate_window=600_000_000_000,  # 600s
            )
        )
        # Prefetch pull consumer for agents (created by API so agents can bind).
        try:
            await self._js.add_consumer(
                STREAM_JOBS,
                ConsumerConfig(
                    durable_name=CONSUMER_AGENTS,
                    ack_policy=AckPolicy.EXPLICIT,
                    filter_subject=SUBJECT_JOBS_SCAN,
                    max_deliver=5,
                ),
            )
        except Exception:  # noqa: BLE001
            # Already exists — fine.
            pass

    async def _ensure_stream(self, config: Any) -> None:
        assert self._js is not None
        try:
            await self._js.add_stream(config=config)
        except Exception:  # noqa: BLE001
            try:
                await self._js.update_stream(config=config)
            except Exception:  # noqa: BLE001
                LOG.debug("stream %s already present", config.name)

    def _call(self, coro: Any, *, timeout: float = 15.0) -> Any:
        if not self._started or self._js is None:
            raise RuntimeError("NATS bus is not connected")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    def close(self) -> None:
        if self._nc is not None and self._loop.is_running():
            try:
                fut = asyncio.run_coroutine_threadsafe(self._nc.drain(), self._loop)
                fut.result(timeout=5)
            except Exception:  # noqa: BLE001
                pass
            self._nc = None
            self._js = None
        if self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._started = False

    def publish_json(
        self,
        subject: str,
        payload: dict[str, Any],
        *,
        msg_id: str | None = None,
    ) -> bool:
        """Publish JSON; returns False if bus offline. msg_id enables JetStream dedupe."""

        async def _pub() -> None:
            assert self._js is not None
            headers = {"Nats-Msg-Id": msg_id} if msg_id else None
            await self._js.publish(
                subject,
                json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=headers,
            )

        try:
            self._call(_pub())
            return True
        except Exception:  # noqa: BLE001
            LOG.exception("NATS publish failed subject=%s msg_id=%s", subject, msg_id)
            return False

    def publish_job_offer(self, payload: dict[str, Any]) -> bool:
        job_id = str(payload.get("job_id") or "")
        msg_id = f"job-{job_id}" if job_id else None
        return self.publish_json(SUBJECT_JOBS_SCAN, payload, msg_id=msg_id)

    def publish_ingest(self, payload: dict[str, Any], *, msg_id: str) -> bool:
        return self.publish_json(SUBJECT_INGEST_RAW, payload, msg_id=msg_id)


_BUS: NatsBus | None = None
_BUS_LOCK = threading.Lock()


def ingest_msg_id(*, job_id: str, run_id: str, archive_sha256: str) -> str:
    """Stable idempotency key for ingest.raw_results (JetStream Nats-Msg-Id)."""
    raw = f"{job_id}:{run_id}:{archive_sha256}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


def archive_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_bus(url: str) -> NatsBus | None:
    """Return a started bus for ``url``, or None when URL empty / connect failed."""
    global _BUS
    url = (url or "").strip()
    if not url:
        return None
    with _BUS_LOCK:
        if _BUS is not None and _BUS._config.url == url and _BUS._started:  # noqa: SLF001
            return _BUS
        if _BUS is not None:
            _BUS.close()
        bus = NatsBus(NatsConfig(url=url))
        bus.start()
        _BUS = bus if bus._started else None  # noqa: SLF001
        return _BUS


def reset_bus_for_tests() -> None:
    global _BUS
    with _BUS_LOCK:
        if _BUS is not None:
            _BUS.close()
        _BUS = None
