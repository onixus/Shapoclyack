"""Safe extraction of agent-uploaded run archives + NATS ingest gateway (Phase 1)."""

from __future__ import annotations

import base64
import io
import json
import logging
import tarfile
from pathlib import Path
from typing import Any

from api.services import nats_bus

LOG = logging.getLogger("octo-man.ingest")


class IngestError(ValueError):
    """Raised when an uploaded archive cannot be accepted."""


def _safe_members(tf: tarfile.TarFile, dest: Path) -> list[tarfile.TarInfo]:
    dest_resolved = dest.resolve()
    members: list[tarfile.TarInfo] = []
    for member in tf.getmembers():
        name = member.name.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            raise IngestError(f"unsafe path in archive: {member.name}")
        if member.issym() or member.islnk():
            raise IngestError(f"links are not allowed: {member.name}")
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest_resolved)):
            raise IngestError(f"path escapes destination: {member.name}")
        members.append(member)
    return members


def validate_archive(archive_bytes: bytes) -> None:
    """Validate tar.gz structure without extracting (gateway pre-check)."""
    if not archive_bytes:
        raise IngestError("empty archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
            members = _safe_members(tf, Path("/tmp/octo-ingest-validate"))
            if not members:
                raise IngestError("archive has no members")
    except IngestError:
        raise
    except tarfile.TarError as exc:
        raise IngestError(f"invalid archive: {exc}") from exc


def extract_run_archive(archive_bytes: bytes, dest_dir: Path) -> Path:
    """Extract tar.gz into dest_dir (created to receive run artifacts)."""
    validate_archive(archive_bytes)
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        members = _safe_members(tf, dest_dir)
        # filter="data" blocks links/device nodes on Python 3.12+; ignore on older.
        try:
            tf.extractall(dest_dir, members=members, filter="data")
        except TypeError:
            tf.extractall(dest_dir, members=members)
    return dest_dir


def update_latest_run_pointer(state_dir: Path, run_id: str) -> None:
    """Update state/latest_run.json so the API/UI pick up the new run."""
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "latest_run.json").write_text(
        json.dumps({"run_id": run_id}, indent=2) + "\n",
        encoding="utf-8",
    )


def publish_raw_results(
    *,
    nats_url: str,
    job_id: str,
    run_id: str,
    agent_id: str,
    exit_code: int,
    archive_bytes: bytes,
    error: str | None = None,
    tenant_id: str = "default",
    include_archive_b64: bool = True,
    max_inline_bytes: int = 4_000_000,
) -> dict[str, Any]:
    """Validate and publish to ``ingest.raw_results`` with JetStream Msg-Id dedupe.

    Returns metadata about the publish attempt. Filesystem extract remains the
    caller's responsibility until Phase 3 ClickHouse consumer lands.
    """
    validate_archive(archive_bytes)
    digest = nats_bus.archive_sha256(archive_bytes)
    msg_id = nats_bus.ingest_msg_id(job_id=job_id, run_id=run_id, archive_sha256=digest)
    payload: dict[str, Any] = {
        "job_id": job_id,
        "run_id": run_id,
        "agent_id": agent_id,
        "exit_code": exit_code,
        "error": error,
        "tenant_id": tenant_id,
        "archive_sha256": digest,
        "archive_bytes": len(archive_bytes),
    }
    if include_archive_b64 and len(archive_bytes) <= max_inline_bytes:
        payload["archive_b64"] = base64.b64encode(archive_bytes).decode("ascii")
    else:
        payload["archive_inline"] = False

    bus = nats_bus.get_bus(nats_url)
    published = False
    if bus is not None:
        published = bus.publish_ingest(payload, msg_id=msg_id)
        if published:
            LOG.info(
                "Published ingest.raw_results job=%s run=%s tenant=%s msg_id=%s",
                job_id,
                run_id,
                tenant_id,
                msg_id,
            )
    return {"msg_id": msg_id, "archive_sha256": digest, "published": published, "tenant_id": tenant_id}
