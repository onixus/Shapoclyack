"""The artifact half of a tenant purge (#325): run archives, job inputs, reports.

Through the artifact store (#336), so the same step empties a volume and a
bucket. What belongs to the tenant, and how it is found:

* **tenant-scoped runs** — everything under ``runs/_tenants/{segment}/`` (#427),
  screenshots included: they live inside the run. One run per batch, each
  behind a hold check, then the segment itself, which takes the ingest staging
  trees a crashed upload left beside the runs;
* **flat runs of earlier releases** — ``runs/{run_id}``, whose owner is only
  what its ``tenant.json`` says. Every flat run is read; one whose marker names
  this tenant is deleted. A missing or unreadable marker fails the step rather
  than being guessed: guessing "not ours" would leave a customer's scan behind,
  and guessing "ours" could delete somebody else's (#311);
* **job inputs** — ``job_inputs/{job_id}/`` for every job row the tenant has,
  read before the Postgres step deletes those rows (hence the step order);
* **reports** — ``reports/{tenant_id}/`` (#292), plus any ``storage_path`` a
  report row names outside it;
* **migration backups** — copies under ``migration-backups/legacy-artifacts/``.
  A key under ``/_tenants/{segment}/`` belongs to that segment. A flat backup
  belongs to whoever its copied ``tenant.json`` names. Anything still named
  as this tenant after the delete fails the step, and so does a backup marker
  that cannot be read: guessing would either keep the tenant's scan or delete
  someone else's.

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
from api.services.legacy_artifact_migration import BACKUP_ROOT
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
    """The explicitly marked owner; None when it is absent or unreadable (#311).

    A store failure raises so the purge is retried. Missing or malformed owner
    metadata blocks the flat-run step rather than letting a purge of ``default``
    delete an artifact whose real owner is unknown.
    """
    marker = keys.run_artifact(ref, "tenant.json")
    try:
        raw = store.get_bytes(marker)
    except artifact_store.ArtifactNotFound:
        return None
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    owner = payload.get("tenant_id") if isinstance(payload, dict) else None
    return owner.strip() if isinstance(owner, str) and owner.strip() else None


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


def _marker_owner_bytes(raw: bytes) -> str | None:
    """The tenant a copied ``tenant.json`` names, or None when it cannot be read."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    owner = payload.get("tenant_id") if isinstance(payload, dict) else None
    if not isinstance(owner, str) or not owner.strip():
        return None
    return owner.strip()


def delete_migration_backups(
    store: artifact_store.ArtifactStore, tenant_id: str
) -> tuple[int, list[str]]:
    """Delete this tenant's legacy-migration copies. Return (removed, unreadable run names).

    Unreadable markers are not deleted: the caller refuses to finish while they
    remain, for the same reason an unreadable flat ``tenant.json`` blocks a purge.
    """
    segment = keys.tenant_segment(tenant_id)
    scoped = f"/_tenants/{segment}/"
    removed = 0
    unreadable: list[str] = []
    seen: set[str] = set()
    owned_keys: list[str] = []
    for entry in store.list_prefix(BACKUP_ROOT):
        key = entry.key
        if scoped in key:
            owned_keys.append(key)
            continue
        if "/_tenants/" in key or not key.endswith("/tenant.json"):
            continue
        prefix = key[: -len("/tenant.json")]
        if prefix in seen:
            continue
        seen.add(prefix)
        try:
            raw = store.get_bytes(key)
        except artifact_store.ArtifactNotFound:
            continue
        owner = _marker_owner_bytes(raw)
        if owner is None:
            unreadable.append(prefix.rsplit("/", 1)[-1])
            continue
        if owner != tenant_id:
            continue
        removed += store.delete_prefix(prefix)
    if owned_keys:
        removed += store.delete_keys(owned_keys)
    return removed, unreadable


def remaining_migration_backups(store: artifact_store.ArtifactStore, tenant_id: str) -> list[str]:
    """Backup keys that still name ``tenant_id`` after :func:`delete_migration_backups`."""
    segment = keys.tenant_segment(tenant_id)
    scoped = f"/_tenants/{segment}/"
    left: list[str] = []
    for entry in store.list_prefix(BACKUP_ROOT):
        key = entry.key
        if scoped in key:
            left.append(key)
            continue
        if "/_tenants/" in key or not key.endswith("/tenant.json"):
            continue
        try:
            raw = store.get_bytes(key)
        except artifact_store.ArtifactNotFound:
            continue
        if _marker_owner_bytes(raw) == tenant_id:
            left.append(key)
    return left


def run(ctx: PurgeContext) -> dict[str, Any]:
    store = artifact_store.get_store(ctx.settings)
    _tenant_runs(ctx, store)
    unreadable = _flat_runs(ctx, store)
    _job_inputs(ctx, store)
    _reports(ctx, store)
    ctx.checkpoint()
    backup_removed, backup_unreadable = delete_migration_backups(store, ctx.tenant_id)
    if backup_removed:
        _record(ctx, {"backup_objects": backup_removed})

    # The proof: nothing is left under the prefixes that are the tenant's alone.
    segment_left = list(store.list_prefix(keys.tenant_runs_prefix(keys.tenant_segment(ctx.tenant_id))))
    prefix = _report_prefix(ctx.tenant_id)
    reports_left = list(store.list_prefix(prefix)) if prefix is not None else []
    backups_left = remaining_migration_backups(store, ctx.tenant_id)
    if segment_left or reports_left or backups_left:
        raise RuntimeError(
            f"{len(segment_left)} run object(s), {len(reports_left)} report object(s) and "
            f"{len(backups_left)} migration backup object(s) remain after the purge"
        )
    if unreadable:
        shown = ", ".join(sorted(unreadable)[:5])
        raise RuntimeError(
            f"{len(unreadable)} flat run(s) have a tenant.json that cannot be read, so "
            f"whether they are this tenant's is unknown: {shown}. Repair or remove "
            "them and retry"
        )
    if backup_unreadable:
        shown = ", ".join(sorted(backup_unreadable)[:5])
        raise RuntimeError(
            f"{len(backup_unreadable)} migration backup(s) have a tenant.json that cannot "
            f"be read, so whether they are this tenant's is unknown: {shown}. Repair or "
            "remove them and retry"
        )
    return {
        "runs": 0,
        "run_objects": 0,
        "legacy_runs": 0,
        "legacy_run_objects": 0,
        "job_input_objects": 0,
        "report_objects": 0,
    }
