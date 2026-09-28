"""The artifact half of a tenant purge (#325): run archives, job inputs, reports.

Through the artifact store (#336), so the same step empties a volume and a
bucket. What belongs to the tenant, and how it is found:

* **tenant-scoped runs** — everything under ``runs/_tenants/{segment}/`` (#427),
  screenshots included: they live inside the run. One run per batch, each
  behind a hold check, then the segment itself, which takes the ingest staging
  trees a crashed upload left beside the runs;
* **flat runs of earlier releases** — ``runs/{run_id}``, whose owner is only
  what its ``tenant.json`` says. Every flat run is read; one whose marker names
  this tenant is deleted, one with no marker is the default tenant's and left,
  and one whose marker *cannot* be read fails the step rather than be guessed
  at: guessing "not ours" would leave a customer's scan behind, and guessing
  "ours" could delete somebody else's;
* **job inputs** — ``job_inputs/{job_id}/`` for every job row the tenant has,
  read before the Postgres step deletes those rows (hence the step order);
* **reports** — ``reports/{tenant_id}/`` (#292), plus any ``storage_path`` a
  report row names outside it.

Pod-local copies go too, as far as this replica can see them: the working
copies of a remote backend (``cache/runs/_tenants/{segment}``) and the job
inputs the local runner materialised. Another replica's cache is not reachable
from here; it holds nothing a request can reach once the tenant is gone, and
its size-bounded eviction removes it.

The step ends by listing what it deleted and failing if anything is left.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

from sqlalchemy import select

from api.db import models
from api.services import artifact_store
from api.services.artifact_store import keys, workspace
from api.services.tenant_purge.context import PurgeContext

LOG = logging.getLogger("shapoclyack.tenant-purge")

# The shape reports.store._report_key accepts for the tenant component: an id
# it would have refused never had a report written under it.
_REPORT_TENANT_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")

#: The flat-run scan reads one ``tenant.json`` per run of every tenant, which
#: on a bucket is a request each. It renews the lease — through a checkpoint —
#: at least this often, so a long scan is not taken for a dead one and started
#: over by another replica, which would then never finish it either.
_FLAT_SCAN_CHECKPOINT_RUNS = 100
_FLAT_SCAN_CHECKPOINT_SECONDS = 30.0

#: What a flat run with no marker belongs to (``runs.read_run_tenant``'s rule).
_UNMARKED_OWNER = "default"


def _report_prefix(tenant_id: str) -> str | None:
    if not _REPORT_TENANT_RE.fullmatch(tenant_id) or tenant_id in {".", ".."}:
        return None
    return artifact_store.normalize_prefix(f"{keys.REPORTS}/{tenant_id}")


def _job_ids(ctx: PurgeContext) -> list[str]:
    with ctx.guard() as session:
        return list(
            session.execute(
                select(models.Job.job_id)
                .where(models.Job.tenant_id == ctx.tenant_id)
                .order_by(models.Job.job_id)
            ).scalars()
        )


def _report_paths(ctx: PurgeContext) -> list[str]:
    with ctx.guard() as session:
        return [
            path
            for path in session.execute(
                select(models.GeneratedReport.storage_path).where(
                    models.GeneratedReport.tenant_id == ctx.tenant_id,
                    models.GeneratedReport.storage_path.is_not(None),
                )
            ).scalars()
            if path
        ]


def _record(ctx: PurgeContext, counts: dict[str, int]) -> None:
    with ctx.guard() as session:
        ctx.add_counts(session, counts)


def _tenant_runs(ctx: PurgeContext, store: artifact_store.ArtifactStore) -> None:
    segment = keys.tenant_segment(ctx.tenant_id)
    root = keys.tenant_runs_prefix(segment)
    for name in list(store.list_children(root)):
        ctx.checkpoint()
        removed = store.delete_prefix(f"{root}/{name}")
        _record(
            ctx,
            {"run_objects": removed, "runs": 0 if name.startswith(".") else 1},
        )
        workspace.forget_run_marker(keys.RunRef(name, segment))
    # Whatever the listing did not show as a child — a marker at the root of
    # the segment, a staging tree mid-rename — goes with the segment itself.
    ctx.checkpoint()
    leftovers = store.delete_prefix(root)
    if leftovers:
        _record(ctx, {"run_objects": leftovers})
    if artifact_store.is_remote(ctx.settings):
        shutil.rmtree(
            workspace.cache_root(ctx.settings) / keys.TENANT_RUNS / segment, ignore_errors=True
        )


def _flat_owner(store: artifact_store.ArtifactStore, ref: keys.RunRef) -> str | None:
    """The tenant a flat run's ``tenant.json`` names; None when it cannot be parsed.

    Stricter than a listing: an unparsable marker is None here, never "the
    default tenant's". And narrower than ``retention_policy.run_owner``: a
    store that fails to answer (throttling, a timeout) raises, so the step
    fails and is retried instead of reporting a run that is fine as unreadable.
    """
    marker = keys.run_artifact(ref, "tenant.json")
    try:
        raw = store.get_bytes(marker)
    except artifact_store.ArtifactNotFound:
        return _UNMARKED_OWNER
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    owner = str(payload.get("tenant_id") or "").strip() if isinstance(payload, dict) else ""
    return owner or _UNMARKED_OWNER


def _flat_runs(ctx: PurgeContext, store: artifact_store.ArtifactStore) -> list[str]:
    """Delete the flat runs marked as this tenant's; return the unreadable ones."""
    unreadable: list[str] = []
    read = 0
    last_checkpoint = time.monotonic()
    for name in list(store.list_children(keys.RUNS)):
        if name.startswith(".") or name == keys.TENANT_RUNS:
            continue
        try:
            ref = keys.run_ref(name)
        except ValueError:
            continue
        read += 1
        if (
            read % _FLAT_SCAN_CHECKPOINT_RUNS == 0
            or time.monotonic() - last_checkpoint >= _FLAT_SCAN_CHECKPOINT_SECONDS
        ):
            ctx.checkpoint()
            last_checkpoint = time.monotonic()
        owner = _flat_owner(store, ref)
        if owner is None:
            unreadable.append(name)
            continue
        if owner != ctx.tenant_id:
            continue
        ctx.checkpoint()
        last_checkpoint = time.monotonic()
        removed = workspace.delete_run(ctx.settings, ref)
        workspace.forget_run_marker(ref)
        _record(ctx, {"legacy_runs": 1, "legacy_run_objects": removed})
    return unreadable


def _job_inputs(ctx: PurgeContext, store: artifact_store.ArtifactStore) -> None:
    local_root = Path(ctx.settings.state_dir) / keys.JOB_INPUTS
    for job_id in _job_ids(ctx):
        try:
            prefix = keys.job_inputs_prefix(job_id)
        except ValueError:
            continue
        ctx.checkpoint()
        removed = store.delete_prefix(prefix)
        # The local runner's copy (job_inputs.ensure_local). The id is a
        # platform-generated one, but it becomes a path: keep it inside.
        local = (local_root / job_id).resolve()
        if local.parent == local_root.resolve():
            shutil.rmtree(local, ignore_errors=True)
        if removed:
            _record(ctx, {"job_input_objects": removed})


def _reports(ctx: PurgeContext, store: artifact_store.ArtifactStore) -> None:
    prefix = _report_prefix(ctx.tenant_id)
    stray = []
    for path in _report_paths(ctx):
        try:
            key = keys.report_key_from_storage_path(path)
        except ValueError:
            continue
        # Only keys that are there: a store's batch delete counts what it was
        # asked to remove, and the tombstone should say what was.
        if (prefix is None or not key.startswith(f"{prefix}/")) and store.exists(key):
            stray.append(key)
    if stray:
        ctx.checkpoint()
        _record(ctx, {"report_objects": store.delete_keys(stray)})
    if prefix is not None:
        ctx.checkpoint()
        removed = store.delete_prefix(prefix)
        if removed:
            _record(ctx, {"report_objects": removed})


def run(ctx: PurgeContext) -> dict[str, Any]:
    store = artifact_store.get_store(ctx.settings)
    _tenant_runs(ctx, store)
    unreadable = _flat_runs(ctx, store)
    _job_inputs(ctx, store)
    _reports(ctx, store)

    # The proof: nothing is left under the prefixes that are the tenant's alone.
    segment_left = list(store.list_prefix(keys.tenant_runs_prefix(keys.tenant_segment(ctx.tenant_id))))
    prefix = _report_prefix(ctx.tenant_id)
    reports_left = list(store.list_prefix(prefix)) if prefix is not None else []
    if segment_left or reports_left:
        raise RuntimeError(
            f"{len(segment_left)} run object(s) and {len(reports_left)} report object(s) "
            "remain after the purge"
        )
    if unreadable:
        shown = ", ".join(sorted(unreadable)[:5])
        raise RuntimeError(
            f"{len(unreadable)} flat run(s) have a tenant.json that cannot be read, so "
            f"whether they are this tenant's is unknown: {shown}. Repair or remove "
            "them and retry"
        )
    return {
        "runs": 0,
        "run_objects": 0,
        "legacy_runs": 0,
        "legacy_run_objects": 0,
        "job_input_objects": 0,
        "report_objects": 0,
    }
