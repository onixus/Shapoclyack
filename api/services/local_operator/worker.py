"""Standalone, singleton pilot worker: ``python -m ...worker [--once]``.

The API never starts this worker. A claimed task is attempted once; expired
claims are interrupted by the store and are never automatically replayed.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import math
import signal
import uuid
from contextlib import suppress
from time import monotonic

from api.db import tenant_scope
from api.services.leader_lock import OPERATOR_LOCK_ID, LeaderLock
from api.services import audit
from api.services.local_operator import gateway, retention, store
from api.settings import Settings, load_settings

LOG = logging.getLogger("shapoclyack.operator-worker")
_EXECUTION_GRACE_SECONDS = 15.0


def _parameters(settings: Settings) -> tuple[float, int]:
    poll = getattr(settings, "operator_worker_poll_seconds", 2.0)
    lease = getattr(settings, "operator_worker_lease_seconds", 180)
    timeout = settings.operator_timeout_seconds
    if (isinstance(poll, bool) or not isinstance(poll, (int, float))
            or not math.isfinite(poll) or not 0 < poll <= 60):
        raise ValueError("invalid_operator_worker_poll")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 120):
        raise ValueError("invalid_operator_worker_timeout")
    if type(lease) is not int or lease < timeout + 30 or lease > 3600:
        raise ValueError("invalid_operator_worker_lease")
    return float(poll), lease


async def _cancel_and_wait(execution: asyncio.Task) -> None:
    """Do not release a slot while its provider coroutine is still running."""
    execution.cancel()
    with suppress(asyncio.CancelledError, Exception):
        await execution


async def process_task(settings: Settings, task: dict, owner: str,
                       leader: LeaderLock, stop: asyncio.Event) -> None:
    """Execute one fenced claim, monitoring cancellation and leadership."""
    execution = asyncio.create_task(gateway.execute_task(settings, task))
    poll, _ = _parameters(settings)
    deadline = asyncio.get_running_loop().time() + settings.operator_timeout_seconds + _EXECUTION_GRACE_SECONDS
    result = None
    error = None
    try:
        while not execution.done():
            if stop.is_set():
                error = "operator_interrupted"
                break
            if store.is_cancel_requested(settings, task["task_id"], owner):
                error = "operator_cancelled"
                break
            if not settings.operator_enabled or not settings.operator_worker_enabled or not leader.acquire():
                error = "operator_interrupted"
                break
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                error = "operator_timeout"
                break
            await asyncio.wait({execution}, timeout=min(poll, 2.0, remaining))
        if error is None:
            result = execution.result()
    except asyncio.CancelledError:
        error = "operator_interrupted"
        raise
    except gateway.GatewayError as exc:
        error = exc.code
    except Exception:
        # Neither exception messages nor tracebacks may expose input/evidence,
        # provider output, credentials or raw upstream errors.
        error = "operator_execution_failed"
        LOG.warning("Operator task execution failed")
    finally:
        if error is not None or not execution.done():
            await _cancel_and_wait(execution)
        # The store validates owner, lease, and cancellation atomically. Even
        # a completed provider response cannot override a concurrent cancel.
        store.finish_task(settings, task["task_id"], owner, result=result, error=error)


async def run_worker(settings: Settings, *, once: bool = False,
                     stop: asyncio.Event | None = None,
                     owner: str | None = None) -> None:
    poll, lease = _parameters(settings)
    stop = stop if stop is not None else asyncio.Event()
    owner = owner or str(uuid.uuid4())
    leader = LeaderLock(settings.postgres_url, object_id=OPERATOR_LOCK_ID, name="operator-worker")
    next_retention = 0.0
    try:
        while not stop.is_set():
            if settings.operator_enabled and settings.operator_worker_enabled and leader.acquire():
                # Recovery closes expired claims as interrupted; it never
                # requeues a task. The lease exceeds the full execution budget.
                store.recover_expired(settings)
                moment = monotonic()
                if moment >= next_retention:
                    next_retention = moment + 60.0
                    try:
                        retention.sweep(settings, limit=20)
                    except Exception:
                        LOG.warning("Operator history maintenance failed")
                task = store.claim_next(settings, owner, lease_seconds=lease)
                if task is not None:
                    await process_task(settings, task, owner, leader, stop)
            if once:
                return
            try:
                await asyncio.wait_for(stop.wait(), timeout=poll)
            except TimeoutError:
                pass
    finally:
        leader.release()


async def _main(once: bool) -> None:
    settings = load_settings()
    tenant_scope.configure(settings)
    audit.configure(settings)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    registered = []
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
            registered.append(signum)
        except NotImplementedError:  # pragma: no cover - non-Unix event loop
            pass
    try:
        await run_worker(settings, once=once, stop=stop)
    finally:
        for signum in registered:
            loop.remove_signal_handler(signum)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the standalone AI operator pilot worker")
    parser.add_argument("--once", action="store_true", help="Attempt at most one queued task and exit")
    args = parser.parse_args()
    asyncio.run(_main(args.once))


if __name__ == "__main__":
    main()
