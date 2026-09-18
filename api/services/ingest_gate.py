"""Bounds how many result uploads this replica ingests at the same time.

``jobs.complete_job`` is synchronous and long: SQL, a NATS publish, archive
extraction, artifact writes — network I/O when the store is S3 — and projection
updates. Called directly from the ``async def`` upload route it ran *on the
event loop*, so one slow ingest delayed every other request the replica was
serving, heartbeats and readiness probes included. It runs on a worker thread
now, and this gate is what keeps "off the event loop" from turning into "as
many threads, database connections and archive extractions at once as the
sensor fleet cares to start".

Two numbers, because they bound different things:

* ``limit`` — ingests running at once. This is the thread, connection and CPU
  bound.
* ``max_waiting`` — uploads allowed to queue for a slot. This is the *memory*
  bound: a waiter is holding its whole archive in RAM, so a backlog without a
  ceiling is not a queue, it is a slow out-of-memory. Worst case in flight is
  ``(limit + max_waiting) * agent_results_max_body_bytes``; the default
  four-plus-eight against the 128 MiB body cap is the arithmetic an operator
  should redo before raising either number.

A refused upload is a 503 with ``Retry-After``. The sensor already retries that
status with backoff (``agent/worker.py``, ``_request``), and because the retry
carries the same derived idempotency key, it is answered as a replay rather
than ingested twice.

The wait is bounded too: an upload that never gets a slot is told so while its
agent is still listening, instead of holding a connection until one side gives
up.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, AsyncIterator

from api.services import metrics as metrics_service

if TYPE_CHECKING:  # pragma: no cover - typing only
    from api.settings import Settings

LOG = logging.getLogger(__name__)


class IngestOverloaded(RuntimeError):
    """No ingest slot for this upload. ``reason`` is the metric label."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class IngestGate:
    """Process-wide admission control for result ingestion."""

    def __init__(self) -> None:
        self._semaphore: asyncio.Semaphore | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._limit = 0
        self._waiting = 0

    def _get(self, limit: int) -> asyncio.Semaphore:
        # Rebuilt when the loop changes, not only when the limit does: a
        # semaphore parks its waiters on the loop that awaited it, and the test
        # suite builds a fresh app — and so a fresh loop — per case.
        loop = asyncio.get_running_loop()
        if self._semaphore is None or self._loop is not loop or self._limit != limit:
            self._semaphore = asyncio.Semaphore(limit)
            self._loop = loop
            self._limit = limit
            self._waiting = 0
        return self._semaphore

    @asynccontextmanager
    async def slot(self, settings: Settings) -> AsyncIterator[None]:
        """Hold one ingest slot, or raise :class:`IngestOverloaded`."""
        limit = max(1, int(settings.agent_results_max_concurrent_ingests))
        max_waiting = max(0, int(settings.agent_results_ingest_max_waiting))
        wait_seconds = max(0.0, float(settings.agent_results_ingest_wait_seconds))
        sem = self._get(limit)

        # Checked before queueing rather than after: the point of the ceiling is
        # to refuse the upload *before* this replica agrees to hold its archive.
        if sem.locked() and self._waiting >= max_waiting:
            metrics_service.AGENT_INGEST_REJECTED_TOTAL.labels(reason="queue_full").inc()
            raise IngestOverloaded(
                "queue_full",
                f"{limit} result uploads are being ingested and {self._waiting} are waiting",
            )

        self._waiting += 1
        metrics_service.AGENT_INGEST_WAITING.set(self._waiting)
        try:
            await asyncio.wait_for(sem.acquire(), timeout=wait_seconds or None)
        except (TimeoutError, asyncio.TimeoutError) as exc:
            metrics_service.AGENT_INGEST_REJECTED_TOTAL.labels(reason="timeout").inc()
            raise IngestOverloaded(
                "timeout",
                f"no ingest slot became free within {wait_seconds:g}s",
            ) from exc
        finally:
            self._waiting -= 1
            metrics_service.AGENT_INGEST_WAITING.set(self._waiting)

        metrics_service.AGENT_INGEST_IN_FLIGHT.inc()
        try:
            yield
        finally:
            metrics_service.AGENT_INGEST_IN_FLIGHT.dec()
            sem.release()


GATE = IngestGate()


def slot(settings: Settings) -> "AsyncIterator[None]":
    """Module-level entry point, so callers do not reach for the singleton."""
    return GATE.slot(settings)
