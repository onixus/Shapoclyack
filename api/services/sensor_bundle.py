"""The signed sensor bundle this installation hands out (#363).

The publish pipeline builds ``shapoclyack-sensor-<version>.tar.gz`` from the
``agent`` package, writes ``sensor-bundle.json`` describing it (version,
archive name, sha256, size) and signs that manifest with the release key
(``scripts/build-sensor-bundle.sh``). An operator puts the three files in
``OCTO_AGENT_BUNDLE_DIR``; ``GET /api/agent/bundle`` returns the manifest and
signature, and ``GET /api/agent/bundle/download`` the archive.

**This module does not verify the signature, on purpose.** The boundary is the
sensor: ``agent/update.py`` checks the manifest against the release key pinned
in its own package and refuses anything else, so a check here would add nothing
an attacker who controls this server could not remove. What is checked here is
consistency -- the archive the manifest names exists, has that size and that
sha256 -- because a bundle directory half-copied by an operator is a mistake
better answered ``503`` with a reason than refused by every sensor in turn.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path

MANIFEST_NAME = "sensor-bundle.json"
SIGNATURE_NAME = "sensor-bundle.json.sig"
#: The same caps the sensor applies; a larger file is not one it would take.
MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024
_ARCHIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.tar\.gz$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

#: (path, size, mtime_ns) -> sha256, so a fleet polling the metadata does not
#: hash the archive once per request. A replaced file changes the key.
_digest_cache: dict[tuple[str, int, int], str] = {}
_digest_lock = threading.Lock()


@dataclass(frozen=True)
class SensorBundle:
    version: str
    archive: str
    archive_path: Path
    sha256: str
    size: int
    manifest: bytes
    signature: str


def reset_for_tests() -> None:
    with _digest_lock:
        _digest_cache.clear()


def _read_capped(path: Path, cap: int) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise ValueError(f"{path.name} is larger than {cap} bytes")
    return data


def _sha256(path: Path) -> str:
    stat = path.stat()
    key = (str(path), stat.st_size, stat.st_mtime_ns)
    with _digest_lock:
        cached = _digest_cache.get(key)
    if cached:
        return cached
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    with _digest_lock:
        _digest_cache[key] = value
    return value


def _unreadable(exc: OSError) -> str:
    name = Path(exc.filename).name if exc.filename else "a bundle file"
    return f"{name} cannot be read by this server ({exc.strerror or exc})"


def current_bundle(bundle_dir: str) -> SensorBundle:
    """The bundle in ``bundle_dir`` (``OCTO_AGENT_BUNDLE_DIR``).

    Raises ``LookupError`` when none is published and ``ValueError`` when the
    directory holds one that does not add up or that this process cannot read.
    """
    if not bundle_dir:
        raise LookupError(
            "No sensor bundle is published on this server (OCTO_AGENT_BUNDLE_DIR is not set)"
        )
    root = Path(bundle_dir)
    try:
        manifest = _read_capped(root / MANIFEST_NAME, MAX_MANIFEST_BYTES)
        signature = _read_capped(root / SIGNATURE_NAME, MAX_SIGNATURE_BYTES)
    except FileNotFoundError as exc:
        raise LookupError(
            f"No sensor bundle is published on this server ({exc.filename} is missing)"
        ) from exc
    except OSError as exc:
        # Present but unreadable to the API's account (copied as root with
        # umask 077; cosign writes the .sig 0600) or a directory: the bundle
        # is there and broken, which is the 503, not a 500 without a reason.
        raise ValueError(_unreadable(exc)) from exc
    try:
        data = json.loads(manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{MANIFEST_NAME} is not JSON") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{MANIFEST_NAME} is not a JSON object")
    version = data.get("version")
    archive = data.get("archive")
    digest = data.get("sha256")
    size = data.get("size")
    if not isinstance(version, str) or not version:
        raise ValueError(f"{MANIFEST_NAME} names no version")
    # The name is joined to the directory, so it has to be a bare file name.
    if not isinstance(archive, str) or not _ARCHIVE_RE.match(archive):
        raise ValueError(f"{MANIFEST_NAME} names no usable archive")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise ValueError(f"{MANIFEST_NAME} names no sha256")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ValueError(f"{MANIFEST_NAME} names no size")
    archive_path = root / archive
    if not archive_path.is_file():
        raise ValueError(f"{archive}, named by {MANIFEST_NAME}, is not in the bundle directory")
    try:
        if archive_path.stat().st_size != size:
            raise ValueError(f"{archive} is not the {size} bytes {MANIFEST_NAME} says")
        if _sha256(archive_path) != digest:
            raise ValueError(f"{archive} does not match the sha256 in {MANIFEST_NAME}")
    except OSError as exc:
        raise ValueError(_unreadable(exc)) from exc
    text = signature.decode("ascii", errors="replace").strip()
    if not text:
        raise ValueError(f"{SIGNATURE_NAME} is empty")
    return SensorBundle(
        version=version,
        archive=archive,
        archive_path=archive_path,
        sha256=digest,
        size=size,
        manifest=manifest,
        signature=text,
    )
