"""NATS JetStream bus for job dispatch and raw-result ingest (Phase 1).

Subjects (streams created on connect when missing):
  - jobs.scan                        → stream JOBS
  - ingest.raw_results               → stream INGEST
  - events.asset.{tenant}.{kind}     → stream EVENTS (Phase 10.2)

Set OCTO_NATS_URL to enable. Empty URL keeps legacy HTTP-only agent flow.

Retention / HA overrides (all optional, applied on every connect via
JetStream ``update_stream``, so changing them takes effect on redeploy):
  - OCTO_NATS_JOBS_MAX_AGE_SECONDS      (default 86400 / 24h)
  - OCTO_NATS_INGEST_MAX_AGE_SECONDS    (default 604800 / 7d)
  - OCTO_NATS_INGEST_MAX_BYTES          (default 10GiB)
  - OCTO_NATS_EVENTS_MAX_AGE_SECONDS    (default 2592000 / 30d)
  - OCTO_NATS_EVENTS_MAX_BYTES          (default 1GiB)
  - OCTO_NATS_EVENTS_DEDUPE_SECONDS     (default 86400 / 24h)
  - OCTO_NATS_STREAM_REPLICAS           (default 1; set 3 on a 3-node cluster)
"""

from __future__ import annotations

import asyncio
import atexit
import hashlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass
from typing import Any

LOG = logging.getLogger("shapoclyack.nats")

SUBJECT_JOBS_SCAN = "jobs.scan"
SUBJECT_INGEST_RAW = "ingest.raw_results"  # legacy alias
# Per-tenant gateway subject (TASK 4): ingest.results.{tenant_id}
# Per-tenant asset events (Phase 10.2): events.asset.{tenant_id}.{kind}

STREAM_JOBS = "JOBS"
STREAM_INGEST = "INGEST"
STREAM_EVENTS = "EVENTS"

# Durable pull consumer for remote agents (queue group = fair dispatch).
CONSUMER_AGENTS = "octo-agents"

# Retention bounds so a stalled consumer / unreachable ClickHouse worker can't
# grow JetStream storage without limit. Overridable per environment.
_DEFAULT_JOBS_MAX_AGE_SECONDS = 24 * 3600
_DEFAULT_INGEST_MAX_AGE_SECONDS = 7 * 24 * 3600
_DEFAULT_INGEST_MAX_BYTES = 10 * 1024 * 1024 * 1024  # 10GB
# Asset events are small JSON envelopes and are kept far longer than raw
# results: a webhook consumer that was down for a weekend should still be able
# to replay what changed, and 30d also gives an operator a queryable change
# history without a second store.
_DEFAULT_EVENTS_MAX_AGE_SECONDS = 30 * 24 * 3600
_DEFAULT_EVENTS_MAX_BYTES = 1024 * 1024 * 1024  # 1GB
# JetStream's own duplicate window defaults to 2 minutes, which is shorter than
# the gap between an upload and its retry after a network timeout — the exact
# case the Phase 10.1 event ids exist to collapse. 24h covers a replayed
# results upload without keeping the dedupe table alive for the stream's life.
_DEFAULT_EVENTS_DEDUPE_SECONDS = 24 * 3600
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


# Attempts and backoff for creating a JetStream stream at connect time. The
# ceiling matters more than the count: a cold JetStream is unavailable for
# seconds, and a replica that gives up early comes back with no stream.
_STREAM_ATTEMPTS = 8
_STREAM_MAX_DELAY_SECONDS = 3.0
# What those attempts add up to in sleeps (0.2, 0.4, 0.8, 1.6, then the cap).
# start() waits on _connect as a whole, so its timeout has to cover this or a
# flat TimeoutError replaces the message that says which stream failed and why.
_STREAM_BUDGET_SECONDS = 12.0


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
            fut.result(timeout=self._config.connect_timeout + _STREAM_BUDGET_SECONDS + 5)
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
            name="shapoclyack-api",
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
        # Asset-level events (Phase 10.2). LIMITS retention, not WORK_QUEUE:
        # unlike a job offer, one event legitimately has several independent
        # consumers (a webhook fan-out, a ticket bridge, an operator's replay),
        # and WORK_QUEUE would let whichever one connected first consume it
        # away from the others.
        await self._ensure_stream(
            StreamConfig(
                name=STREAM_EVENTS,
                subjects=["events.>"],
                retention=RetentionPolicy.LIMITS,
                storage=StorageType.FILE,
                max_msgs=1_000_000,
                max_age=float(
                    _int_env("OCTO_NATS_EVENTS_MAX_AGE_SECONDS", _DEFAULT_EVENTS_MAX_AGE_SECONDS)
                ),
                max_bytes=_int_env("OCTO_NATS_EVENTS_MAX_BYTES", _DEFAULT_EVENTS_MAX_BYTES),
                duplicate_window=float(
                    _int_env("OCTO_NATS_EVENTS_DEDUPE_SECONDS", _DEFAULT_EVENTS_DEDUPE_SECONDS)
                ),
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
        """Create or reconcile one stream, or refuse to report a working bus.

        Raising is the point. ``start()`` already treats a failed ``_connect``
        as "NATS is unavailable, disable the bus for this process and say so";
        returning quietly here defeated that, because the bus then came up
        ``_started`` with no stream behind it and every later publish failed
        one message at a time with ``NoStreamResponseError``. A replica that
        starts while JetStream is still initialising must look unavailable,
        not healthy.

        The budget is sized for that case rather than for a warm server: a
        JetStream that is enabled but has not finished opening a cold
        ``store_dir`` answers "no responders" for seconds, not milliseconds,
        and the previous five tries spanned two of them.
        """
        assert self._js is not None
        delay = 0.2
        add_exc: BaseException | None = None
        last_exc: BaseException | None = None
        for attempt in range(1, _STREAM_ATTEMPTS + 1):
            try:
                await self._js.add_stream(config=config)
                return
            except Exception as exc:  # noqa: BLE001
                # Kept separately from last_exc: this is the one that says why
                # creation failed ("no responders" when JetStream is not up
                # yet), and the stream_info error below used to overwrite it
                # with a flat "stream not found" that explains nothing.
                add_exc = exc
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
                    if attempt == _STREAM_ATTEMPTS:
                        break
                    await asyncio.sleep(delay)
                    delay = min(delay * 2, _STREAM_MAX_DELAY_SECONDS)
        raise RuntimeError(
            f"JetStream stream {config.name} could not be created or read after "
            f"{_STREAM_ATTEMPTS} attempts: add_stream failed with {add_exc!r}; "
            f"stream_info failed with {last_exc!r}"
        )

    def _call(self, coro: Any, *, timeout: float = 15.0) -> Any:
        if not self._started or self._js is None:
            raise RuntimeError("NATS bus is not connected")
        fut = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return fut.result(timeout=timeout)

    def close(self) -> None:
        loop = self._loop

        if self._nc is not None and loop.is_running():
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
                current = asyncio.current_task()
                pending = [t for t in asyncio.all_tasks() if t is not current and not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

            try:
                fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
                fut.result(timeout=5)
            except Exception:  # noqa: BLE001
                LOG.debug("Failed to shut down NATS event loop cleanly", exc_info=True)
            finally:
                if loop.is_running():
                    loop.call_soon_threadsafe(loop.stop)
        elif loop.is_running():
            loop.call_soon_threadsafe(loop.stop)

        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=5)

        if not self._thread.is_alive() and not loop.is_running() and not loop.is_closed():
            loop.close()

        self._nc = None
        self._js = None
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

    def publish_asset_event(self, envelope: dict[str, Any], *, retries: int = 1) -> bool:
        """Publish one asset event to ``events.asset.{tenant_id}.{kind}``."""
        tenant_id = str(envelope.get("tenant_id") or "default")
        kind = str(envelope.get("kind") or "unknown")
        return self.publish_json(
            asset_event_subject(tenant_id, kind),
            envelope,
            msg_id=str(envelope.get("event_id") or "") or None,
            headers={"tenant_id": tenant_id, "event_kind": kind},
            retries=retries,
        )

    def publish_endpoint_inventory(self, envelope: dict[str, Any], *, retries: int = 1) -> bool:
        """Publish accepted endpoint inventory summary to ``ingest.endpoint_inventory.{tenant_id}`` (Phase S8)."""
        tenant_id = str(envelope.get("tenant_id") or "default")
        snapshot_id = str(envelope.get("snapshot_id") or "")
        digest = str(envelope.get("payload_digest") or "")
        msg_id = endpoint_inventory_msg_id(
            tenant_id=tenant_id, snapshot_id=snapshot_id, payload_digest=digest
        )
        return self.publish_json(
            endpoint_inventory_subject(tenant_id),
            envelope,
            msg_id=msg_id,
            headers={
                "tenant_id": tenant_id,
                "event_type": "endpoint_inventory_accepted",
            },
            retries=retries,
        )


_BUS: NatsBus | None = None
_BUS_LOCK = threading.Lock()


# A token that needs no encoding: ASCII alphanumerics plus - and _, which carry
# no meaning to NATS. Everything else (notably ``.``, ``*`` and ``>``) is a
# separator or wildcard and would reshape the subject tree rather than name a
# leaf in it.
_SUBJECT_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
# Reserved prefix for the encoded form of a token that is not representable
# directly. `tenants.create_tenant` rejects ids starting with it, so an encoded
# token can never collide with a literal one.
_ENCODED_TOKEN_PREFIX = "h_"


def is_subject_token(value: str) -> bool:
    """Whether ``value`` can be a NATS subject token verbatim."""
    return bool(_SUBJECT_TOKEN_RE.match(value or ""))


def _subject_token(value: str, fallback: str) -> str:
    """Encode one subject token injectively.

    Replacing every disallowed character with ``_`` (the previous behaviour)
    was *not* injective: tenants ``acme.eu`` and ``acme_eu`` both collapsed to
    ``acme_eu``, so a consumer or a NATS ACL scoped to one tenant's subject
    would have received the other tenant's messages. Tenant ids are now
    validated at creation, but ids predating that validation still exist, so
    anything unrepresentable is hashed into the reserved ``h_`` namespace
    instead of being mangled into a neighbour's subject.

    A conforming id is used verbatim, so every subject in an existing
    deployment keeps the exact name it has today.
    """
    value = value or ""
    if is_subject_token(value) and not value.startswith(_ENCODED_TOKEN_PREFIX):
        return value
    if not value:
        return fallback
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]
    LOG.warning(
        "Tenant id %r is not a valid NATS subject token; publishing under %s%s instead",
        value,
        _ENCODED_TOKEN_PREFIX,
        digest,
    )
    return f"{_ENCODED_TOKEN_PREFIX}{digest}"


def ingest_results_subject(tenant_id: str) -> str:
    """NATS subject ``ingest.results.{tenant_id}`` with safe token."""
    return f"ingest.results.{_subject_token(tenant_id, 'default')}"


def asset_event_subject(tenant_id: str, kind: str) -> str:
    """NATS subject ``events.asset.{tenant_id}.{kind}`` with safe tokens."""
    return f"events.asset.{_subject_token(tenant_id, 'default')}.{_subject_token(kind, 'unknown')}"


def endpoint_inventory_subject(tenant_id: str) -> str:
    """NATS subject ``ingest.endpoint_inventory.{tenant_id}`` with safe token (Phase S8)."""
    return f"ingest.endpoint_inventory.{_subject_token(tenant_id, 'default')}"


def endpoint_inventory_msg_id(*, tenant_id: str, snapshot_id: str, payload_digest: str) -> str:
    """Stable idempotency key for endpoint inventory publish (JetStream Nats-Msg-Id)."""
    raw = f"{tenant_id}:{snapshot_id}:{payload_digest}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:48]


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
