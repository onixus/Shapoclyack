"""Stage2 enrichment queue fan-out after Stage1 inventory (FTT-PULSE-2026-054).

When a Stage1 job opts in with ``stage2_enrichment=true`` and its run publishes
successfully, the control plane turns observed open hosts into claimable
Stage2 jobs (``intent=enrichment``). Sensors claim them through the ordinary
``FOR UPDATE SKIP LOCKED`` path — the same durable queue used for shards
(ADR 0010) and the product shape of ADR 0008 (heavy work off the inventory
critical path).

Pure helpers here are unit-tested without Postgres. The enqueue entry point
is best-effort: a failure never changes the Stage1 terminal outcome.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any, Callable

from api.db import models
from api.db.engine import get_session
from api.schemas import JobInfo, StartScanRequest
from api.services import publication_marks
from api.services import job_store
from api.settings import Settings
from scanner.pipeline.protocol import parse_endpoint

_log = logging.getLogger(__name__)

#: Hard ceiling on Stage2 sibling jobs for one Stage1 run (matches shard cap).
MAX_STAGE2_SHARDS = 64
#: Refuse to fan out more unique hosts than this from one Stage1 run.
MAX_STAGE2_HOSTS = 10_000
#: Default partition width when the operator did not set ``shard_count`` on
#: Stage1. One Stage2 job per wave keeps claim semantics simple; operators
#: who already shard Stage1 still get one Stage2 group sized by host count
#: via :func:`stage2_shard_count`.
DEFAULT_STAGE2_SHARDS = 1

STAGE1_INTENTS = frozenset({"inventory", "inventory_services"})

PUBLICATION_STEP = publication_marks.STAGE2


def hosts_from_open_ports_text(text: str) -> tuple[str, ...]:
    """Unique host strings from ``open_ports.txt`` lines, stable order.

    Lines that are not ``host:port[/proto]`` are skipped. IPv6 stays bracketed
    only if the endpoint parser returned the inner host — we re-emit the host
    token as Pulse/naabu expect it in ranges input (no brackets for v4; bare
    v6 forms that appeared in the artifact).
    """
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parsed = parse_endpoint(line)
        if parsed is None:
            continue
        host = parsed.host.strip()
        if not host or host in seen:
            continue
        seen.add(host)
        out.append(host)
    return tuple(out)


def hosts_from_open_ports_file(path: Path) -> tuple[str, ...]:
    """Read ``open_ports.txt`` if present; missing/empty → empty tuple."""
    if not path.is_file():
        return ()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        _log.warning("Could not read open_ports at %s", path, exc_info=True)
        return ()
    return hosts_from_open_ports_text(text)


def partition_hosts(
    hosts: tuple[str, ...] | list[str],
    *,
    shard_count: int,
) -> tuple[tuple[str, ...], ...]:
    """Round-robin host partitions; empty buckets omitted (stable indices)."""
    if shard_count < 1 or shard_count > MAX_STAGE2_SHARDS:
        raise ValueError(
            f"stage2 shard_count must be between 1 and {MAX_STAGE2_SHARDS}"
        )
    ordered = tuple(hosts)
    if not ordered:
        return ()
    buckets: list[list[str]] = [[] for _ in range(shard_count)]
    for index, host in enumerate(ordered):
        buckets[index % shard_count].append(host)
    return tuple(
        tuple(bucket)
        for bucket in buckets
        if bucket
    )


def stage2_shard_count(host_count: int, *, requested: int | None = None) -> int:
    """How many Stage2 jobs to open for ``host_count`` unique hosts.

    ``requested`` comes from Stage1 ``shard_count`` when the operator already
    sized the estate horizontally; otherwise one job unless the host set is
    empty. Always capped by :data:`MAX_STAGE2_SHARDS` and by host count.
    """
    if host_count <= 0:
        return 0
    if requested is not None:
        n = max(1, min(int(requested), MAX_STAGE2_SHARDS, host_count))
        return n
    return min(DEFAULT_STAGE2_SHARDS, host_count)


def should_enqueue_stage2(scan_options: dict[str, Any] | None) -> bool:
    """Whether a published job may fan out Stage2 enrichment jobs."""
    options = scan_options or {}
    if not options.get("stage2_enrichment"):
        return False
    # Already a Stage2 child — never recurse.
    if options.get("stage2_of"):
        return False
    intent = options.get("intent")
    if intent is not None and intent not in STAGE1_INTENTS:
        # Opt-in on a non-Stage1 intent is refused rather than silently
        # spawning assessment from a job that already ran full enrichment.
        return False
    return True


def require_agent_execution_for_stage2(execution: str) -> None:
    """Refuse local fan-out: uncancellable threads + API-pod load."""
    if execution != "agent":
        raise ValueError(
            "stage2_enrichment requires job_execution_mode=agent; "
            "local mode cannot safely fan out Stage2 enrichment jobs"
        )


def build_stage2_meta(
    *,
    group_id: str,
    index: int,
    count: int,
    parent_job_id: str,
    parent_run_id: str | None,
) -> dict[str, Any]:
    """Server-only scan_options keys for one Stage2 sibling."""
    meta: dict[str, Any] = {
        "stage2_group_id": group_id,
        "stage2_index": index,
        "stage2_count": count,
        "stage2_of": parent_job_id,
    }
    if parent_run_id:
        meta["stage2_of_run_id"] = parent_run_id
    return meta


def build_stage2_request(
    parent_options: dict[str, Any],
    *,
    hosts: tuple[str, ...],
    tenant_id: str,
) -> StartScanRequest:
    """StartScanRequest for one Stage2 partition (no Stage2 recursion flag)."""
    ranges = "\n".join(hosts)
    mode = parent_options.get("requested_mode") or parent_options.get("mode") or "balanced"
    if mode not in ("safe", "balanced", "fast", "test"):
        mode = "balanced"
    return StartScanRequest(
        mode=mode,  # type: ignore[arg-type]
        intent="enrichment",
        delta=False,
        skip_nse=False,
        notify=bool(parent_options.get("notify")),
        export_defectdojo=bool(parent_options.get("export_defectdojo")),
        tenant_id=tenant_id,
        ranges=ranges,
        domains=None,
        ports=None,
        ports_udp=None,
        surface=parent_options.get("surface"),
        agent_group=parent_options.get("agent_group"),
        stage2_enrichment=False,
        priority=0,
    )


def enqueue_stage2_after_stage1(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    publication_id: str | None,
    run_dir: Path | None,
    start_scan: Callable[..., JobInfo],
) -> tuple[str, ...]:
    """Fan out Stage2 jobs from a published Stage1 run. Best-effort.

    Returns the Stage2 job ids created (possibly empty). Marks the publication
    step before creating jobs so a killed replica that retries does not open a
    second group. Callers must already know the run succeeded.
    """
    with get_session(settings.postgres_url) as session:
        parent = session.get(models.Job, job_id)
        if parent is None:
            return ()
        options = dict(parent.scan_options or {})
        execution = parent.execution or "local"
        requested_by = parent.requested_by or "system"
        parent_priority = int(parent.priority or 0)
        parent_snapshot = {
            "options": options,
            "execution": execution,
            "requested_by": requested_by,
            "priority": parent_priority,
        }

    if not should_enqueue_stage2(parent_snapshot["options"]):
        return ()
    try:
        require_agent_execution_for_stage2(parent_snapshot["execution"])
    except ValueError as exc:
        _log.info("Stage2 skipped for job %s: %s", job_id, exc)
        return ()

    if run_dir is None:
        _log.info("Stage2 skipped for job %s: run directory unavailable", job_id)
        return ()

    hosts = hosts_from_open_ports_file(run_dir / "open_ports.txt")
    if not hosts:
        _log.info("Stage2 skipped for job %s: no open hosts in run %s", job_id, run_id)
        # Mark so a republish does not keep re-reading an empty artifact.
        with get_session(settings.postgres_url) as session:
            publication_marks.first_pass(session, publication_id, PUBLICATION_STEP)
        return ()
    if len(hosts) > MAX_STAGE2_HOSTS:
        _log.warning(
            "Stage2 for job %s truncated from %s to %s hosts",
            job_id,
            len(hosts),
            MAX_STAGE2_HOSTS,
        )
        hosts = hosts[:MAX_STAGE2_HOSTS]

    # Operator-requested width, not ``shard_of``. Submission stores the
    # requested N in ``shard_count`` and the number of non-empty partitions
    # in ``shard_of``; reading the latter undersizes Stage2 when a bucket
    # was empty.
    parent_shard_count = parent_snapshot["options"].get("shard_count")
    try:
        n = stage2_shard_count(
            len(hosts),
            requested=(
                int(parent_shard_count) if parent_shard_count is not None else None
            ),
        )
    except (TypeError, ValueError):
        n = stage2_shard_count(len(hosts))
    if n <= 0:
        return ()

    partitions = partition_hosts(hosts, shard_count=n)
    if not partitions:
        return ()

    # Claim the publication step under the row lock before creating jobs so a
    # reconciler retry cannot open a second Stage2 group.
    with get_session(settings.postgres_url) as session:
        if not publication_marks.first_pass(session, publication_id, PUBLICATION_STEP):
            return ()

    group_id = uuid.uuid4().hex[:12]
    created: list[str] = []
    sibling_ids: list[str] = []
    try:
        for part in partitions:
            # Index is the position among *kept* partitions (no empty gaps at
            # this layer — partition_hosts already dropped empties, and with
            # shard_count ≤ host_count every bucket is non-empty).
            index = len(created)
            request = build_stage2_request(
                parent_snapshot["options"],
                hosts=part,
                tenant_id=tenant_id,
            )
            # Preserve operator priority on Stage2 so a raised Stage1 stays
            # ahead of background inventory in the same tenant queue.
            request = request.model_copy(update={"priority": parent_snapshot["priority"]})
            meta = build_stage2_meta(
                group_id=group_id,
                index=index,
                count=len(partitions),
                parent_job_id=job_id,
                parent_run_id=run_id,
            )
            info = start_scan(
                settings,
                request,
                username=parent_snapshot["requested_by"],
                quota_exempt=True,
                widen_with_promoted=False,
                _stage2_meta=meta,
                _defer_dispatch=True,
            )
            created.append(info.job_id)
            sibling_ids.append(info.job_id)
    except Exception:
        _log.exception(
            "Stage2 fan-out failed for job %s after creating %s siblings",
            job_id,
            len(created),
        )
        # The publication mark committed before this loop. Drop it so a
        # republish can retry instead of treating the lost group as done.
        _release_stage2_mark(settings, publication_id)
        # Best-effort cancel what landed so a partial group is not claimed.
        from api.services import job_control

        for child_id in created:
            try:
                job_control.cancel_job(
                    settings, child_id, username=parent_snapshot["requested_by"]
                )
            except Exception:
                _log.warning(
                    "Could not cancel Stage2 job %s after fan-out failure",
                    child_id,
                    exc_info=True,
                )
        raise

    # Annotate sibling ids and offer on NATS only after the whole group exists.
    for child_id in sibling_ids:
        _annotate_stage2_siblings(settings, child_id, sibling_ids)
    from api.services import job_dispatch

    for child_id in sibling_ids:
        try:
            job_dispatch.publish_offer(settings, child_id)
        except Exception:
            _log.warning(
                "Could not publish Stage2 offer for %s", child_id, exc_info=True
            )

    job_store.refresh_job_gauges(settings)
    _log.info(
        "Stage2 enqueued %s jobs (group %s) from Stage1 job %s run %s",
        len(sibling_ids),
        group_id,
        job_id,
        run_id,
    )
    return tuple(sibling_ids)


def _release_stage2_mark(settings: Settings, publication_id: str | None) -> None:
    """Undo a Stage2 claim so a failed fan-out is not permanent."""
    try:
        with get_session(settings.postgres_url) as session:
            publication_marks.release(session, publication_id, PUBLICATION_STEP)
    except Exception:
        _log.warning(
            "Could not release Stage2 publication mark %s",
            publication_id,
            exc_info=True,
        )


def _annotate_stage2_siblings(
    settings: Settings, job_id: str, sibling_ids: list[str]
) -> None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Job, job_id)
        if row is None:
            return
        options = dict(row.scan_options or {})
        options["stage2_job_ids"] = list(sibling_ids)
        row.scan_options = options


def enqueue_stage2_best_effort(
    settings: Settings,
    job_id: str,
    *,
    run_id: str,
    tenant_id: str,
    publication_id: str | None = None,
) -> None:
    """POST_PUBLICATION hook: never raises into the publisher."""
    try:
        from api.services import jobs as jobs_service
        from api.services.run_completion import _written_run_dir

        run_dir = _written_run_dir(settings, run_id, tenant_id)
        enqueue_stage2_after_stage1(
            settings,
            job_id,
            run_id=run_id,
            tenant_id=tenant_id,
            publication_id=publication_id,
            run_dir=run_dir,
            start_scan=jobs_service.start_scan,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort by contract
        _log.exception(
            "Stage2 enrichment fan-out failed for job %s run %s", job_id, run_id
        )
        try:
            from api.services.run_completion import _append_job_error

            _append_job_error(
                settings,
                job_id,
                f"; stage2 enrichment enqueue failed: {type(exc).__name__}: {exc}",
            )
        except Exception:  # pragma: no cover
            _log.warning(
                "Could not note Stage2 failure on job %s", job_id, exc_info=True
            )
