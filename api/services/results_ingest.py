"""Safe extraction of agent-uploaded run archives into output/runs/<run_id>/."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path


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


def extract_run_archive(archive_bytes: bytes, dest_dir: Path) -> Path:
    """Extract tar.gz into dest_dir (created to receive run artifacts)."""
    if not archive_bytes:
        raise IngestError("empty archive")
    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        members = _safe_members(tf, dest_dir)
        if not members:
            raise IngestError("archive has no members")
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
