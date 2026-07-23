"""NATS JetStream bus for job dispatch and raw-result ingest (Phase 1).

Subjects (streams created on connect when missing):
  - jobs.scan          → stream JOBS
  - ingest.raw_results → stream INGEST

Set OCTO_NATS_URL to enable. Empty URL keeps legacy HTTP-only agent flow.

Retention / HA overrides (all optional, applied on every connect via
JetStream ``update_stream``, so changing them takes effect on redeploy):
  - OCTO_NATS_JOBS_MAX_AGE_SECONDS   (default 86400 / 24h)
  - OCTO_NATS_INGEST_MAX_AGE_SECONDS (default 604800 / 7d)
  - OCTO_NATS_INGEST_MAX_BYTES       (default 10GiB)
  - OCTO_NATS_STREAM_REPLICAS        (default 1; set 3 on a 3-node cluster)
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

LOG = logging.getLogger("octo-man.nats")

SUBJECT_JOBS_SCAN = "jobs.scan"
SUBJECT_INGEST_RAW = "ingest.raw_results"  # legacy alias
# Per-tenant gateway subject (TASK 4): ingest.results.{tenant_id}

STREAM_JOBS = "JOBS"
STREAM_INGEST = "INGEST"

# Durable pull consumer for remote agents (queue group = fair dispatch).
CONSUMER_AGENTS = "octo-agents"

# Retention bounds so a stalled consumer / unreachable ClickHouse worker can't
# grow JetStream storage without limit. Overridable per environment.
_DEFAULT_JOBS_MAX_AGE_SECONDS = 24 * 3600
_DEFAULT_INGEST_MAX_AGE_SECONDS = 7 * 24 * 3600
_DEFAULT_INGEST_MAX_BYTES = 10 * 1024 * 1024 * 1024  # 10GB
# JetStream replication factor (R). 1 = single node (default/dev). Set to 3 on
# a 3+ node NATS cluster (e.g. prod overlay) for stream-level HA.
_DEFAULT_STREAM_REPLICAS = 1


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOG.warning("Invalid int for %s=%r; using default %s", name, raw, default)
        return default


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

        stream_replicas = _int_env("OCTO_NATS_STREAM_REPLICAS", _DEFAULT_STREAM_REPLICAS)
        jobs_max_age = _int_env("OCTO_NATS_JOBS_MAX_AGE_SECONDS", _DEFAULT_JOBS_MAX_AGE_SECONDS)
        ingest_max_age = _int_env(
            "OCTO_NATS_INGEST_MAX_AGE_SECONDS", _DEFAULT_INGEST_MAX_AGE_SECONDS
        )
        ingest_max_bytes = _int_env(
            "OCTO_NATS_INGEST_MAX_BYTES", _DEFAULT_INGEST_MAX_BYTES
        )

        await self._ensure_stream(
            StreamConfig(
                name=STREAM_JOBS,
                subjects=["jobs.>"],
                retention=RetentionPolicy.WORK_QUEUE,
                storage=StorageType.FILE,
                max_msgs=100_000,
                # Unclaimed/unacked job offers older than this are dropped —
                # bounds storage if agents stay offline indefinitely.
                max_age=float(jobs_max_age),
                num_replicas=stream_replicas,
            )
        )
        await self._ensure_stream(
            StreamConfig(
                name=STREAM_INGEST,
                subjects=["ingest.>"],
                retention=RetentionPolicy.LIMITS,
                storage=StorageType.FILE,
                max_msgs=500_000,
                # Bounds storage if the ClickHouse ingest worker falls behind
                # or is disabled; oldest raw results are discarded past this.
                max_age=float(ingest_max_age),
                max_bytes=ingest_max_bytes,
                num_replicas=stream_replicas,
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
        last_exc: BaseException | None = None
        for attempt in range(1, 6):
            try:
                await self._js.add_stream(config=config)
                return
            except Exception as add_exc:  # noqa: BLE001
                last_exc = add_exc
                # Already present (or raced with another API replica). Push our
                # retention/replica config onto it so limit changes (e.g. a new
                # OCTO_NATS_*_MAX_AGE_SECONDS) take effect on redeploy, not only
                # on first stream creation.
                try:
                    await self._js.update_stream(config=config)
                    return
                except Exception:  # noqa: BLE001
                    pass
                try:
                    await self._js.stream_info(config.name)
                    return
                except Exception as info_exc:  # noqa: BLE001
                    last_exc = info_exc
                    await asyncio.sleep(0.2 * attempt)
        LOG.warning("stream %s not ready after retries: %s", config.name, last_exc)

    def _call(self, coro: Any, *, timeout: float = 15.0) -> Any:
        if not self._started or self._js is None:
            raise RuntimeError("NATS bus is not connected")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    def close(self) -> None:
        if self._nc is not None and self._loop.is_running():
            async def _shutdown() -> None:
                if self._nc is not None:
                    try:
                        if not self._nc.is_closed:
                            await self._nc.drain()
                    except Exception:  # noqa: BLE001
                        pass
                    try:
                        if not self._nc.is_closed:
                            await self._nc.close()
                    except Exception:  # noqa: BLE001
                        pass
                loop = asyncio.get_running_loop()
                current_task = asyncio.current_task(loop)
                pending = [t for t in asyncio.all_tasks(loop) if t is not current_task and not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                await asyncio.sleep(0.05)
                loop.stop()

            try:
                fut = asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
                fut.result(timeout=5)
            except Exception:  # noqa: BLE001
                if self._loop.is_running():
                    self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread.is_alive():
                self._thread.join(timeout=3)
            self._nc = None
            self._js = None
        elif self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
            if self._thread.is_alive():
                self._thread.join(timeout=3)
        self._started = False

    def publish_json(
        self,
        subject: str,
        payload: dict[str, Any],
        *,
        msg_id: str | None = None,
        headers: dict[str, str] | None = None,
        retries: int = 3,
    ) -> bool:
        """Publish JSON with simple retries; returns False if bus offline."""

        async def _pub() -> None:
            assert self._js is not None
            hdrs: dict[str, str] = {}
            if msg_id:
                hdrs["Nats-Msg-Id"] = msg_id
            if headers:
                hdrs.update(headers)
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            last_exc: BaseException | None = None
            for attempt in range(1, max(1, retries) + 1):
                try:
                    await self._js.publish(subject, body, headers=hdrs or None)
                    return
                except Exception as exc:  # noqa: BLE001
                    last_exc = exc
                    LOG.warning(
                        "NATS publish attempt %s/%s failed subject=%s: %s",
                        attempt,
                        retries,
                        subject,
                        exc,
                    )
                    await asyncio.sleep(0.2 * attempt)
            assert last_exc is not None
            raise last_exc

        try:
            self._call(_pub())
            return True
        except Exception:  # noqa: BLE001
            LOG.exception("NATS publish failed subject=%s msg_id=%s", subject, msg_id)
            return False

    def publish_job_offer(self, payload: dict[str, Any]) -> bool:
        job_id = str(payload.get("job_id") or "")
        msg_id = f"job-{job_id}" if job_id else None
        tenant_id = str(payload.get("tenant_id") or "")
        extra = {"tenant_id": tenant_id} if tenant_id else None
        return self.publish_json(SUBJECT_JOBS_SCAN, payload, msg_id=msg_id, headers=extra)

    def publish_ingest(self, payload: dict[str, Any], *, msg_id: str) -> bool:
        """Publish to ``ingest.results.{tenant_id}`` (and legacy ``ingest.raw_results``)."""
        tenant_id = str(payload.get("tenant_id") or "default")
        subject = ingest_results_subject(tenant_id)
        extra = {"tenant_id": tenant_id}
        ok = self.publish_json(subject, payload, msg_id=msg_id, headers=extra)
        # Keep legacy subject for older consumers / tests.
        self.publish_json(
            SUBJECT_INGEST_RAW,
            payload,
            msg_id=f"{msg_id}-legacy" if msg_id else None,
            headers=extra,
        )
        return ok


_BUS: NatsBus | None = None
_BUS_LOCK = threading.Lock()


def ingest_results_subject(tenant_id: str) -> str:
    """NATS subject ``ingest.results.{tenant_id}`` with safe token."""
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (tenant_id or "default"))
    return f"ingest.results.{safe or 'default'}"


def ingest_msg_id(*, job_id: str, run_id: str, archive_sha256: str) -> str:
    """Stable idempotency key for ingest publish (JetStream Nats-Msg-Id)."""
    raw = f"{job_id}:{run_id}:{archive_sha256}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


def archive_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def startup_bus(url: str) -> NatsBus | None:
    """Initialize global NATS connection (call from FastAPI lifespan/startup)."""
    return get_bus(url)


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


def shutdown_bus() -> None:
    reset_bus_for_tests()


def reset_bus_for_tests() -> None:
    global _BUS
    with _BUS_LOCK:
        if _BUS is not None:
            _BUS.close()
        _BUS = None
