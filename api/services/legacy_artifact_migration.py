"""Auditable migration of flat run artifacts into their tenant prefixes (#311)."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services.artifact_store import keys, workspace
from api.settings import Settings, load_settings

MANIFEST_VERSION = 1
BACKUP_ROOT = "migration-backups/legacy-artifacts"
PROBLEM_STATUSES = {"refused", "conflict", "unsupported"}


class MigrationError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tenant_ids(settings: Settings) -> set[str]:
    with get_session(settings.postgres_url) as session:
        return set(session.execute(select(models.Tenant.tenant_id)).scalars())


def _source_marker(store: artifact_store.ArtifactStore, ref: keys.RunRef) -> bytes | None:
    try:
        return store.get_bytes(keys.run_artifact(ref, workspace.RUN_MARKER))
    except artifact_store.ArtifactNotFound:
        return None


def _marker_owner(raw: bytes | None) -> str:
    if raw is None:
        return ""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return ""
    if not isinstance(payload, dict):
        return ""
    value = payload.get("tenant_id")
    return value.strip() if isinstance(value, str) else ""


def _assigned_marker(raw: bytes | None, tenant_id: str) -> bytes:
    try:
        payload = json.loads((raw or b"{}").decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    return (json.dumps({**payload, "tenant_id": tenant_id}, indent=2) + "\n").encode("utf-8")


def _entry(
    store: artifact_store.ArtifactStore,
    *,
    source: str,
    destination: str,
    backup: str,
    assigned_owner: bool,
    tenant_id: str,
) -> dict[str, Any]:
    try:
        raw = store.get_bytes(source)
        source_missing = False
    except artifact_store.ArtifactNotFound:
        if not (assigned_owner and source.endswith("/tenant.json")):
            raise
        raw = b""
        source_missing = True
    desired = _assigned_marker(raw, tenant_id) if assigned_owner and source.endswith("/tenant.json") else raw
    destination_existed = store.exists(destination)
    destination_sha256 = ""
    status = "pending"
    if destination_existed:
        destination_sha256 = _sha256(store.get_bytes(destination))
        if destination_sha256 != _sha256(desired):
            status = "conflict"
    return {
        "source": source,
        "destination": destination,
        "backup": backup,
        "size": len(raw),
        "source_sha256": _sha256(raw),
        "source_missing": source_missing,
        "sha256": _sha256(desired),
        "destination_existed": destination_existed,
        "destination_sha256": destination_sha256,
        "status": status,
    }


def build_plan(
    settings: Settings,
    *,
    assignments: dict[str, str] | None = None,
    migration_id: str | None = None,
) -> dict[str, Any]:
    """Inspect every flat run without changing the store."""
    assignments = assignments or {}
    unknown_assignments = set(assignments) - {ref.run_id for ref in workspace.run_refs(settings)}
    if unknown_assignments:
        raise MigrationError(f"assignment names no flat run: {sorted(unknown_assignments)[0]}")
    migration_id = migration_id or uuid.uuid4().hex
    manifest: dict[str, Any] = {
        "version": MANIFEST_VERSION,
        "migration_id": migration_id,
        "created_at": _now(),
        "backend": settings.artifact_backend,
        "runs": [],
    }
    tenants = _tenant_ids(settings)
    store = artifact_store.get_store(settings)
    for ref in workspace.run_refs(settings):
        if ref.tenant is not None or ref.run_id == workspace.FLAT_RUN_ID:
            continue
        raw_marker = _source_marker(store, ref)
        marked_owner = _marker_owner(raw_marker)
        assigned_owner = assignments.get(ref.run_id, "")
        if marked_owner and assigned_owner and marked_owner != assigned_owner:
            raise MigrationError(f"run {ref.run_id} is already marked as {marked_owner}")
        owner = marked_owner or assigned_owner
        run: dict[str, Any] = {
            "run_id": ref.run_id,
            "tenant_id": owner,
            "assigned_owner": bool(assigned_owner and not marked_owner),
            "status": "pending",
            "objects": [],
        }
        manifest["runs"].append(run)
        if not owner:
            run.update(status="refused", error="owner metadata is missing or damaged")
            continue
        if owner not in tenants:
            run.update(status="refused", error=f"tenant {owner!r} does not exist")
            continue
        try:
            destination_ref = keys.run_ref(ref.run_id, owner)
        except ValueError:
            run.update(status="unsupported", error="legacy run id cannot be a tenant-scoped run id")
            continue
        for artifact in store.list_prefix(keys.run_prefix(ref)):
            relative = artifact.key.removeprefix(f"{keys.run_prefix(ref)}/")
            entry = _entry(
                store,
                source=artifact.key,
                destination=keys.run_artifact(destination_ref, relative),
                backup=f"{BACKUP_ROOT}/{migration_id}/{artifact.key}",
                assigned_owner=run["assigned_owner"],
                tenant_id=owner,
            )
            run["objects"].append(entry)
            if entry["status"] == "conflict":
                run["status"] = "conflict"
                run["error"] = f"destination differs: {entry['destination']}"
        if run["assigned_owner"] and raw_marker is None:
            source = keys.run_artifact(ref, workspace.RUN_MARKER)
            entry = _entry(
                store,
                source=source,
                destination=keys.run_artifact(destination_ref, workspace.RUN_MARKER),
                backup=f"{BACKUP_ROOT}/{migration_id}/{source}",
                assigned_owner=True,
                tenant_id=owner,
            )
            run["objects"].append(entry)
            if entry["status"] == "conflict":
                run["status"] = "conflict"
                run["error"] = f"destination differs: {entry['destination']}"
        if not run["objects"]:
            run["status"] = "skipped"
    return manifest


def save_manifest(manifest: dict[str, Any], path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_manifest(path: Path) -> dict[str, Any]:
    manifest = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("version") != MANIFEST_VERSION:
        raise MigrationError("unsupported migration manifest")
    if not isinstance(manifest.get("runs"), list):
        raise MigrationError("migration manifest has no runs")
    return manifest


def _verify(manifest: dict[str, Any]) -> None:
    problems = [run for run in manifest["runs"] if run.get("status") in PROBLEM_STATUSES]
    if problems:
        raise MigrationError(
            "migration is not safe to apply: "
            + "; ".join(f"{run['run_id']}: {run.get('error', run['status'])}" for run in problems)
        )


def _put_verified(store: artifact_store.ArtifactStore, key: str, data: bytes) -> None:
    store.put_bytes(key, data)
    if _sha256(store.get_bytes(key)) != _sha256(data):
        raise MigrationError(f"verification failed after writing {key}")


def apply_migration(
    settings: Settings, manifest: dict[str, Any], *, manifest_path: Path | None = None
) -> dict[str, Any]:
    """Copy, verify and only then remove each source object. Safe to resume."""
    _verify(manifest)
    store = artifact_store.get_store(settings)
    for run in manifest["runs"]:
        if run["status"] in {"migrated", "rolled_back", "skipped"}:
            continue
        run["status"] = "partial"
        for entry in run["objects"]:
            if entry["status"] == "migrated":
                continue
            source_raw = None
            try:
                source_raw = store.get_bytes(entry["source"])
            except artifact_store.ArtifactNotFound:
                pass
            if source_raw is None:
                if entry.get("source_missing"):
                    source_raw = b""
                elif store.exists(entry["destination"]) and _sha256(
                    store.get_bytes(entry["destination"])
                ) == entry["sha256"]:
                    entry["status"] = "migrated"
                    continue
                else:
                    raise MigrationError(f"source disappeared before migration: {entry['source']}")
            if _sha256(source_raw) != entry["source_sha256"]:
                raise MigrationError(f"source changed after dry-run: {entry['source']}")
            desired = (
                _assigned_marker(source_raw, run["tenant_id"])
                if run["assigned_owner"] and entry["source"].endswith("/tenant.json")
                else source_raw
            )
            if _sha256(desired) != entry["sha256"]:
                raise MigrationError(f"assigned marker changed after dry-run: {entry['source']}")
            if store.exists(entry["backup"]):
                if _sha256(store.get_bytes(entry["backup"])) != entry["source_sha256"]:
                    raise MigrationError(f"backup does not match its source: {entry['backup']}")
            else:
                _put_verified(store, entry["backup"], source_raw)
            if store.exists(entry["destination"]):
                if _sha256(store.get_bytes(entry["destination"])) != entry["sha256"]:
                    raise MigrationError(f"destination changed after dry-run: {entry['destination']}")
            else:
                _put_verified(store, entry["destination"], desired)
            store.delete(entry["source"])
            entry["status"] = "migrated"
            entry["migrated_at"] = _now()
            if manifest_path is not None:
                save_manifest(manifest, manifest_path)
        run["status"] = "migrated"
        if manifest_path is not None:
            save_manifest(manifest, manifest_path)
    return manifest


def rollback_migration(
    settings: Settings, manifest: dict[str, Any], *, manifest_path: Path | None = None
) -> dict[str, Any]:
    """Restore source bytes from the backup and remove only destinations we created."""
    store = artifact_store.get_store(settings)
    for run in manifest["runs"]:
        for entry in run.get("objects", []):
            if entry.get("status") != "migrated":
                continue
            backup = store.get_bytes(entry["backup"])
            if _sha256(backup) != entry["source_sha256"]:
                raise MigrationError(f"backup failed verification: {entry['backup']}")
            if store.exists(entry["source"]):
                if _sha256(store.get_bytes(entry["source"])) != entry["source_sha256"]:
                    raise MigrationError(f"rollback would overwrite a changed source: {entry['source']}")
            elif not entry.get("source_missing"):
                _put_verified(store, entry["source"], backup)
            if not entry["destination_existed"] and store.exists(entry["destination"]):
                if _sha256(store.get_bytes(entry["destination"])) != entry["sha256"]:
                    raise MigrationError(
                        f"rollback would remove a changed destination: {entry['destination']}"
                    )
                store.delete(entry["destination"])
            entry["status"] = "rolled_back"
            entry["rolled_back_at"] = _now()
            if manifest_path is not None:
                save_manifest(manifest, manifest_path)
        if run.get("status") == "migrated":
            run["status"] = "rolled_back"
    if manifest_path is not None:
        save_manifest(manifest, manifest_path)
    return manifest


def summary(manifest: dict[str, Any]) -> dict[str, Any]:
    runs: dict[str, int] = {}
    objects: dict[str, int] = {}
    for run in manifest["runs"]:
        runs[run["status"]] = runs.get(run["status"], 0) + 1
        for entry in run.get("objects", []):
            objects[entry["status"]] = objects.get(entry["status"], 0) + 1
    return {"migration_id": manifest["migration_id"], "runs": runs, "objects": objects}


def _assignments(values: list[str]) -> dict[str, str]:
    result = {}
    for value in values:
        run_id, separator, tenant_id = value.partition("=")
        if not separator or not run_id.strip() or not tenant_id.strip():
            raise MigrationError("--assign must be RUN_ID=TENANT_ID")
        result[run_id.strip()] = tenant_id.strip()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true")
    action.add_argument("--rollback", action="store_true")
    parser.add_argument("--manifest", type=Path, default=Path("legacy-artifact-migration.json"))
    parser.add_argument("--assign", action="append", default=[], metavar="RUN_ID=TENANT_ID")
    args = parser.parse_args(argv)
    settings = load_settings()
    try:
        if args.rollback:
            manifest = load_manifest(args.manifest)
            rollback_migration(settings, manifest, manifest_path=args.manifest)
        elif args.apply:
            manifest = (
                load_manifest(args.manifest)
                if args.manifest.exists()
                else build_plan(settings, assignments=_assignments(args.assign))
            )
            save_manifest(manifest, args.manifest)
            apply_migration(settings, manifest, manifest_path=args.manifest)
        else:
            migration_id = None
            if args.manifest.exists():
                migration_id = load_manifest(args.manifest)["migration_id"]
            manifest = build_plan(
                settings, assignments=_assignments(args.assign), migration_id=migration_id
            )
            save_manifest(manifest, args.manifest)
    except (MigrationError, OSError, ValueError, artifact_store.ArtifactStoreError) as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(summary(manifest), sort_keys=True))
    return 2 if any(run["status"] in PROBLEM_STATUSES for run in manifest["runs"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
