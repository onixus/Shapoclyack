#!/usr/bin/env python3
"""Offline enrichment bundles: built on a connected host, installed on an air-gapped one (#339).

An air-gapped installation cannot run ``scripts/fetch-enrichment.sh``: every
feed it reads is on the internet. What it can do is take a file across the gap.
This module makes that file and is the only thing that unpacks it.

**Build** (connected side, ``make enrichment-bundle``): the enrichment data
directory a refresh just filled is packed into one tarball — every dataset the
manifest in ``scripts/enrichment_manifest.py`` knows about, plus
``bundle-manifest.json`` as the *first* member, recording per file its sha256,
size, dataset, source URL, the data date the feed stamped on it (``updated``),
when it was fetched, and the schema version. The archive is deterministic: the
same directory produces the same bytes (sorted members, fixed owner and mode,
the data's own timestamp rather than the wall clock, a gzip header with no name
or time), so two people building from one refresh can compare checksums.

**Install** (air-gapped side): the archive is untrusted input until proven
otherwise, and the extractor is written that way rather than on top of
``tarfile.extractall``:

* Only plain ustar/v7 **regular-file** headers are accepted — no symlinks, hard
  links, devices, FIFOs, directories, sparse files, and no pax or GNU long-name
  headers (the builder never writes them; a pax header is also the one place
  ``tarfile`` would buffer an attacker-chosen length in memory).
* The manifest must come first, and every later member must be one of the files
  it lists, at a path from a fixed whitelist of dataset paths — never absolute,
  never with ``..``, never twice. A file the manifest does not list is refused,
  not skipped.
* Sizes are checked against the manifest before a byte of content is read, the
  content is streamed to disk while hashed, and a sha256 mismatch refuses the
  whole bundle. The decompressed stream is metered against a budget computed
  from the manifest's own sizes, a total cap and a compression-ratio cap, so a
  zip bomb stops at the first byte past what it declared. A truncated archive, a
  bad gzip CRC or data after the end-of-archive marker is refused.
* Every file lands in a staging directory next to the data first. Each JSON
  dataset must parse and carry an ``entries`` map, each .mmdb must be a MaxMind
  DB, and a dataset that is *usable* on the volume today is never replaced by
  one that is not — the #246 floor, applied at the gap. A bundle older than the
  installed one is refused unless ``--allow-older`` (a replayed old bundle is how
  last month's KEV would come back).
* Only then is it committed: the previous files are hard-linked aside, a journal
  is written, and each file is swapped in with an atomic rename, so a reader sees
  the old file or the new one and never neither. Any failure rolls the lot back;
  a crash mid-commit is rolled back by the next run, which finds the journal.
  The dataset manifest (``enrichment-manifest.json``, ``origin: bundle``) and the
  installed-bundle record (``enrichment-bundle.json``, read by ``GET
  /api/system``) are part of the same transaction.

Every install appends a line to ``enrichment-bundle-history.jsonl`` and prints a
JSON summary to stdout, which is what the loader Job's log keeps.

Usage::

    python3 scripts/enrichment_bundle.py build --dir build/enrichment -o dist/enrichment-bundle.tar.gz
    python3 scripts/enrichment_bundle.py verify dist/enrichment-bundle.tar.gz
    python3 scripts/enrichment_bundle.py install dist/enrichment-bundle.tar.gz --dir /app/scanner/data
    python3 scripts/enrichment_bundle.py status --dir /app/scanner/data
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import fcntl
import getpass
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import stat
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any, Iterator

# Siblings, whichever way this file was loaded (script, or by path from tests).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import enrichment_manifest  # noqa: E402 - needs the path above

SCHEMA = "shapoclyack.enrichment-bundle"
SCHEMA_VERSION = 1
MANIFEST_MEMBER = "bundle-manifest.json"
INSTALLED_RECORD = "enrichment-bundle.json"
HISTORY = "enrichment-bundle-history.jsonl"
JOURNAL = ".enrichment-bundle-journal.json"
LOCK = ".enrichment-bundle.lock"
STAGING_PREFIX = ".enrichment-bundle-staging-"
BACKUP_PREFIX = ".enrichment-bundle-backup-"

#: Twice the 2Gi enrichment-data volume a bundle is unpacked onto: a bundle
#: that cannot fit there cannot be installed anyway.
DEFAULT_MAX_BYTES = 4 * 1024**3
#: The committed seed datasets compress 10.6x (22.1 MB of JSON into a 2.1 MB
#: bundle, measured when this was written); a .mmdb compresses far less. A
#: ratio of 100 is not enrichment data.
DEFAULT_MAX_RATIO = 100
#: Below this much data the ratio is not meaningful (a tiny, very regular file
#: compresses absurdly well) and is not enforced.
RATIO_FLOOR_BYTES = 1024 * 1024
MANIFEST_MAX_BYTES = 4 * 1024 * 1024

BLOCK = 512
RECORD = 20 * BLOCK
CHUNK = 1024 * 1024

EXIT_OK = 0
EXIT_REJECTED = 1
EXIT_ERROR = 2

_SHA256 = re.compile(r"[0-9a-f]{64}")


class BundleError(Exception):
    """The bundle is refused. Nothing on the volume has changed."""


class InstallError(Exception):
    """The install could not run (lock held, target unusable)."""


def dataset_paths() -> dict[str, str]:
    """Relative path → dataset name, for every file a bundle may carry.

    The whitelist *is* the manifest module's dataset table: a bundle can write
    exactly the files a refresh writes and nothing else, whatever its manifest
    says.
    """
    paths = {rel: name for name, (rel, _, _) in enrichment_manifest._JSON_DATASETS.items()}
    paths.update({rel: name for name, rel in enrichment_manifest._BINARY_DATASETS.items()})
    return paths


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="seconds")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _canonical(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def _built_at(generated_at: object, files: list[Path], explicit: str | None) -> str:
    """The bundle's timestamp, from the data rather than the clock.

    ``SOURCE_DATE_EPOCH`` (the reproducible-builds convention) or ``--built-at``
    when given; otherwise the moment the refresh that filled the directory
    finished, which is what "built" means for data. Either way two builds of
    one directory agree.
    """
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if explicit:
        parsed = _parse_time(explicit)
        if parsed is None:
            raise BundleError(f"--built-at {explicit!r} is not an ISO-8601 timestamp")
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    if epoch.isdigit():
        return _utc(int(epoch))
    generated = _parse_time(generated_at)
    if generated is not None:
        return generated.astimezone(timezone.utc).isoformat(timespec="seconds")
    return _utc(max(int(path.stat().st_mtime) for path in files))


def describe(data_dir: Path, *, built_at: str | None = None) -> dict:
    """The bundle manifest for ``data_dir``, without writing anything."""
    manifest_path = data_dir / enrichment_manifest.MANIFEST_NAME
    try:
        dataset_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        generated_at = dataset_manifest.get("generated_at") if isinstance(dataset_manifest, dict) else None
    except (OSError, json.JSONDecodeError):
        # No refresh ever described this directory: describe it now, with no
        # claim about where anything came from — and no timestamp from this
        # description, which would be the clock and break determinism.
        dataset_manifest = enrichment_manifest.build_manifest(data_dir, refreshed=set(), failed=set())
        generated_at = None
    records = dataset_manifest.get("datasets") if isinstance(dataset_manifest, dict) else None
    records = records if isinstance(records, dict) else {}

    paths = dataset_paths()
    files: list[dict[str, Any]] = []
    present: list[Path] = []
    for rel in sorted(paths):
        src = data_dir / rel
        try:
            info = os.lstat(src)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(f"{src} is not a regular file; refusing to bundle it")
        name = paths[rel]
        record = records.get(name) if isinstance(records.get(name), dict) else {}
        digest, size = _sha256_file(src)
        urls = record.get("origin_urls")
        files.append(
            {
                "path": rel,
                "dataset": name,
                "sha256": digest,
                "size": size,
                "source": record.get("source"),
                "source_urls": [str(u) for u in urls] if isinstance(urls, list) else [],
                "updated": record.get("updated"),
                "fetched_at": _utc(int(info.st_mtime)),
                "origin": record.get("origin"),
                "entries": record.get("entries"),
                "usable": record.get("usable"),
            }
        )
        present.append(src)
    if not files:
        raise BundleError(f"no enrichment dataset under {data_dir}; nothing to bundle")
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "built_at": _built_at(generated_at, present, built_at),
        "files": files,
    }


class _HashingReader:
    """Hash what ``tarfile`` copies into the archive, to catch a file that
    changed between being described and being packed."""

    def __init__(self, handle: IO[bytes]) -> None:
        self._handle = handle
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self.digest.update(data)
        return data


def _tarinfo(name: str, size: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mtime = mtime
    info.mode = 0o644
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.type = tarfile.REGTYPE
    return info


def build_bundle(data_dir: Path, out: Path, *, compress: bool = True, built_at: str | None = None) -> dict:
    """Pack ``data_dir`` into ``out``. Returns the bundle manifest."""
    manifest = describe(data_dir, built_at=built_at)
    manifest_bytes = _canonical(manifest)
    mtime = int(_parse_time(manifest["built_at"]).timestamp())  # type: ignore[union-attr]
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    try:
        with tmp.open("wb") as raw:
            # filename="" and mtime=0: nothing in the gzip header varies by host
            # or by moment, which is what keeps two builds byte-identical.
            sink: Any = (
                gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6)
                if compress
                else raw
            )
            with sink, tarfile.open(fileobj=sink, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                archive.addfile(_tarinfo(MANIFEST_MEMBER, len(manifest_bytes), mtime), _BytesReader(manifest_bytes))
                for entry in manifest["files"]:
                    src = data_dir / entry["path"]
                    with src.open("rb") as handle:
                        reader = _HashingReader(handle)
                        archive.addfile(_tarinfo(entry["path"], entry["size"], mtime), reader)
                    if reader.digest.hexdigest() != entry["sha256"]:
                        raise BundleError(f"{src} changed while the bundle was being built; run it again")
        tmp.replace(out)
    finally:
        tmp.unlink(missing_ok=True)
    return manifest


class _BytesReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, size: int = -1) -> bytes:
        end = len(self._data) if size < 0 else self._pos + size
        chunk = self._data[self._pos : end]
        self._pos += len(chunk)
        return chunk


# --------------------------------------------------------------------------
# Verify: the untrusted half
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Limits:
    max_bytes: int = DEFAULT_MAX_BYTES
    max_ratio: int = DEFAULT_MAX_RATIO


class _Meter:
    """The decompressed stream, metered against a budget that only shrinks.

    Before the manifest is read the budget is one manifest's worth; after, it
    is exactly what the manifest declared plus tar framing. Every read is
    bounded by what is left, so nothing — not a lying header, not a bomb — can
    make this allocate more than the budget.
    """

    def __init__(self, stream: IO[bytes], budget: int) -> None:
        self._stream = stream
        self.budget = budget
        self.consumed = 0

    def read(self, size: int) -> bytes:
        # One byte past the budget is enough to know it was exceeded, and is
        # all that is ever asked of the decompressor beyond it.
        data = self._stream.read(min(size, self.budget - self.consumed + 1))
        self.consumed += len(data)
        if self.consumed > self.budget:
            raise BundleError(
                "the archive expands past what its manifest declares "
                f"({self.budget} bytes); refusing (zip bomb, or not a bundle this tool built)"
            )
        return data

    def read_exact(self, size: int, what: str) -> bytes:
        parts: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self.read(min(remaining, CHUNK))
            if not chunk:
                raise BundleError(f"the archive is truncated (in {what})")
            parts.append(chunk)
            remaining -= len(chunk)
        return b"".join(parts)


def _padding(size: int) -> int:
    return (BLOCK - size % BLOCK) % BLOCK


def _check_name(raw: str) -> str:
    """A member name that can only ever mean a path under the data directory."""
    if not raw or "\x00" in raw or "\\" in raw:
        raise BundleError(f"member name {raw!r} is not a plain relative path")
    if raw.startswith("/"):
        raise BundleError(f"member {raw!r} is an absolute path")
    if any(part in ("", ".", "..") for part in raw.split("/")):
        raise BundleError(f"member {raw!r} has an empty, '.' or '..' path component")
    return raw


_TYPE_NAMES = {
    tarfile.SYMTYPE: "a symbolic link",
    tarfile.LNKTYPE: "a hard link",
    tarfile.CHRTYPE: "a character device",
    tarfile.BLKTYPE: "a block device",
    tarfile.FIFOTYPE: "a FIFO",
    tarfile.DIRTYPE: "a directory",
    tarfile.CONTTYPE: "a contiguous file",
    tarfile.GNUTYPE_SPARSE: "a sparse file",
    tarfile.XHDTYPE: "a pax extended header",
    tarfile.XGLTYPE: "a pax global header",
    tarfile.GNUTYPE_LONGNAME: "a GNU long-name header",
    tarfile.GNUTYPE_LONGLINK: "a GNU long-link header",
}


def _header(block: bytes) -> tarfile.TarInfo:
    try:
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
    except (tarfile.HeaderError, UnicodeDecodeError) as exc:
        raise BundleError(f"corrupt tar header: {exc}") from exc
    if info.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or info.name.endswith("/"):
        kind = _TYPE_NAMES.get(info.type, f"tar type {info.type!r}")
        raise BundleError(f"member {info.name!r} is {kind}; a bundle holds regular files only")
    return info


def _parse_manifest(raw: bytes, *, limits: Limits, compressed_size: int) -> dict:
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError(f"{MANIFEST_MEMBER} is not JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise BundleError(f"{MANIFEST_MEMBER} is not a {SCHEMA} manifest")
    version = manifest.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise BundleError("schema_version is missing")
    if version > SCHEMA_VERSION:
        raise BundleError(
            f"schema_version {version} is newer than this release reads ({SCHEMA_VERSION}); "
            "upgrade before loading this bundle"
        )
    if version < 1:
        raise BundleError(f"schema_version {version} is not valid")
    if _parse_time(manifest.get("built_at")) is None:
        raise BundleError("built_at is missing or not an ISO-8601 timestamp")
    files = manifest.get("files")
    whitelist = dataset_paths()
    if not isinstance(files, list) or not files:
        raise BundleError("the manifest lists no files")
    seen: set[str] = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise BundleError("a manifest file entry is not an object")
        path = _check_name(str(entry.get("path") or ""))
        if path not in whitelist:
            raise BundleError(f"{path!r} is not an enrichment dataset path; refusing")
        if entry.get("dataset") != whitelist[path]:
            raise BundleError(f"{path!r} is listed as dataset {entry.get('dataset')!r}, not {whitelist[path]!r}")
        if path in seen:
            raise BundleError(f"{path!r} is listed twice")
        seen.add(path)
        size = entry.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BundleError(f"{path!r} has no valid size")
        if not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]):
            raise BundleError(f"{path!r} has no valid sha256")
        total += size
    if total > limits.max_bytes:
        raise BundleError(f"the bundle declares {total} bytes, over the {limits.max_bytes} byte limit")
    if total > RATIO_FLOOR_BYTES and total > limits.max_ratio * max(compressed_size, 1):
        raise BundleError(
            f"the bundle declares {total} bytes from {compressed_size} on disk, a ratio over "
            f"{limits.max_ratio}; refusing"
        )
    return manifest


@dataclass
class Verified:
    manifest: dict
    bundle_id: str
    staged: dict[str, Path]


def _open_stream(bundle: Path) -> tuple[IO[bytes], IO[bytes]]:
    raw = bundle.open("rb")
    magic = raw.read(2)
    raw.seek(0)
    if magic == b"\x1f\x8b":
        return raw, gzip.GzipFile(fileobj=raw, mode="rb")
    return raw, raw


def read_bundle(bundle: Path, staging: Path, *, limits: Limits = Limits()) -> Verified:
    """Verify ``bundle`` member by member, writing each file under ``staging``."""
    info = bundle.stat()
    if not stat.S_ISREG(info.st_mode):
        # A FIFO would block the loader until its deadline; a device would
        # stream forever. The inbox holds files.
        raise BundleError(f"{bundle} is not a regular file")
    compressed_size = info.st_size
    raw, stream = _open_stream(bundle)
    staged: dict[str, Path] = {}
    try:
        meter = _Meter(stream, BLOCK + MANIFEST_MAX_BYTES + BLOCK)
        first = meter.read_exact(BLOCK, "the first header")
        info = _header(first)
        if _check_name(info.name) != MANIFEST_MEMBER:
            raise BundleError(f"the first member must be {MANIFEST_MEMBER}, not {info.name!r}")
        if info.size > MANIFEST_MAX_BYTES:
            raise BundleError(f"{MANIFEST_MEMBER} is {info.size} bytes; refusing")
        manifest_bytes = meter.read_exact(info.size, MANIFEST_MEMBER)
        meter.read_exact(_padding(info.size), MANIFEST_MEMBER)
        manifest = _parse_manifest(manifest_bytes, limits=limits, compressed_size=compressed_size)
        expected = {entry["path"]: entry for entry in manifest["files"]}

        # From here the budget is exact: every listed file with its header and
        # padding, the two end-of-archive blocks, and at most one record of
        # trailing zeros. A byte more is not something this tool wrote.
        # (The ratio was already checked against the declared sizes, so this
        # budget is within it too.)
        framing = sum(BLOCK + e["size"] + _padding(e["size"]) for e in expected.values())
        meter.budget = meter.consumed + framing + 2 * BLOCK + RECORD

        while True:
            block = meter.read_exact(BLOCK, "a header")
            if block == bytes(BLOCK):
                break
            info = _header(block)
            name = _check_name(info.name)
            entry = expected.get(name)
            if entry is None:
                if name in staged:
                    raise BundleError(f"{name!r} appears twice in the archive")
                raise BundleError(f"{name!r} is in the archive but not in the manifest; refusing")
            if info.size != entry["size"]:
                raise BundleError(f"{name!r} is {info.size} bytes in the archive, {entry['size']} in the manifest")
            staged[name] = _stage(meter, staging, name, entry)
            del expected[name]
            meter.read_exact(_padding(info.size), name)

        # The second end-of-archive block, then only zero padding to the end of
        # the stream. Reading to EOF is also what makes gzip check its CRC.
        tail = meter.read_exact(BLOCK, "the end-of-archive marker")
        if tail != bytes(BLOCK):
            raise BundleError("data after the end-of-archive marker; refusing")
        while True:
            chunk = meter.read(CHUNK)
            if not chunk:
                break
            if chunk.count(0) != len(chunk):
                raise BundleError("data after the end-of-archive marker; refusing")
        if expected:
            raise BundleError(f"the archive is missing {', '.join(sorted(expected))} (truncated?)")
    except (EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise BundleError(f"the archive is corrupt or truncated: {exc}") from exc
    finally:
        if stream is not raw:
            stream.close()
        raw.close()
    return Verified(manifest=manifest, bundle_id=hashlib.sha256(manifest_bytes).hexdigest(), staged=staged)


def _stage(meter: _Meter, staging: Path, name: str, entry: dict) -> Path:
    dest = staging / name
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(dest, flags, 0o644)
    digest = hashlib.sha256()
    with os.fdopen(fd, "wb") as out:
        remaining = entry["size"]
        while remaining:
            chunk = meter.read(min(remaining, CHUNK))
            if not chunk:
                raise BundleError(f"the archive is truncated (in {name!r})")
            digest.update(chunk)
            out.write(chunk)
            remaining -= len(chunk)
        out.flush()
        os.fsync(out.fileno())
    if digest.hexdigest() != entry["sha256"]:
        raise BundleError(f"{name!r} does not match its sha256 in the manifest; refusing")
    return dest


def _looks_like_mmdb(path: Path) -> bool:
    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - 128 * 1024))
        return b"\xab\xcd\xefMaxMind.com" in handle.read()


def check_content(verified: Verified, target: Path | None) -> None:
    """Each staged file is the kind of data its path says, and no worse than
    what it would replace."""
    floors = {rel: floor for _, (rel, floor, _) in enrichment_manifest._JSON_DATASETS.items()}
    for rel, staged in verified.staged.items():
        if rel not in floors:
            if not _looks_like_mmdb(staged):
                raise BundleError(f"{rel!r} is not a MaxMind DB; refusing")
            continue
        record = enrichment_manifest.inspect_json_dataset(staged, floors[rel])
        if record["entries"] is None:
            # Not JSON, or JSON without an ``entries`` map: not a dataset at
            # all, whatever its checksum says.
            raise BundleError(f"{rel!r} is not an enrichment dataset ({record['error']}); refusing")
        if record["usable"] or target is None:
            continue
        current = enrichment_manifest.inspect_json_dataset(target / rel, floors[rel])
        if current["usable"]:
            raise BundleError(
                f"{rel!r} in the bundle is not usable ({record['error']}) and would replace a "
                f"dataset that is ({current['entries']} entries); refusing"
            )


# --------------------------------------------------------------------------
# Install: the transaction
# --------------------------------------------------------------------------


def _real_dir(path: Path) -> None:
    """``path`` exists as a directory and is not a symlink (created if absent)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        path.mkdir(mode=0o755)
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BundleError(f"{path} is not a plain directory; refusing to write through it")


def _fsync_dir(path: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_json(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(_canonical(payload))
    tmp.replace(path)


def installed_record(target: Path) -> dict | None:
    try:
        payload = json.loads((target / INSTALLED_RECORD).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


@contextlib.contextmanager
def _locked(target: Path) -> Iterator[None]:
    fd = os.open(target / LOCK, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EACCES):
                raise InstallError(f"another bundle install is running on {target}") from exc
            raise
        yield
    finally:
        os.close(fd)


def recover(target: Path) -> bool:
    """Roll back an install that died mid-commit. True if there was one."""
    journal_path = target / JOURNAL
    rolled_back = False
    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        journal = None
    except (OSError, json.JSONDecodeError):
        journal = {}
    if journal is not None:
        name = str(journal.get("backup") or "")
        # The journal names its backup directory; it may only ever be one of
        # ours, beside the data — never a path that would make the rollback
        # copy something from elsewhere into the data directory.
        valid = name.startswith(BACKUP_PREFIX) and "/" not in name and name not in (".", "..")
        backup = target / name if valid else target / f"{BACKUP_PREFIX}missing"
        for item in journal.get("files") or []:
            rel = str(item.get("path") or "")
            if rel not in _transaction_paths():
                continue
            live = target / rel
            saved = backup / rel
            if item.get("had_previous") and saved.is_file():
                os.replace(saved, live)
            elif not item.get("had_previous"):
                live.unlink(missing_ok=True)
        journal_path.unlink(missing_ok=True)
        _fsync_dir(target)
        rolled_back = True
    # Whatever a crashed run left behind and no journal refers to any more.
    for leftover in target.glob(f"{STAGING_PREFIX}*"):
        shutil.rmtree(leftover, ignore_errors=True)
    for leftover in target.glob(f"{BACKUP_PREFIX}*"):
        shutil.rmtree(leftover, ignore_errors=True)
    return rolled_back


def _transaction_paths() -> set[str]:
    return set(dataset_paths()) | {INSTALLED_RECORD, enrichment_manifest.MANIFEST_NAME}


def _commit(target: Path, staging: Path, backup: Path, paths: list[str], bundle_id: str) -> None:
    # Everything that can refuse, refuses before the journal exists: after it,
    # the only way out is forward or a full rollback.
    for rel in paths:
        _real_dir((target / rel).parent)
    journal: dict[str, Any] = {"bundle_id": bundle_id, "backup": backup.name, "files": []}
    for rel in paths:
        live = target / rel
        had_previous = False
        try:
            info = os.lstat(live)
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISREG(info.st_mode):
                raise BundleError(f"{live} is not a regular file; refusing to replace it")
            saved = backup / rel
            saved.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(live, saved, follow_symlinks=False)
            except OSError:
                # Storage without hard links (some SMB/CSI drivers): a copy is
                # slower and just as good for a rollback.
                shutil.copy2(live, saved)
            had_previous = True
        journal["files"].append({"path": rel, "had_previous": had_previous})
    _write_json(target / JOURNAL, journal)
    _fsync_dir(target)
    try:
        for rel in paths:
            os.replace(staging / rel, target / rel)
    except BaseException:
        recover(target)
        raise
    (target / JOURNAL).unlink()
    _fsync_dir(target)


def install(
    bundle: Path,
    target: Path,
    *,
    limits: Limits = Limits(),
    allow_older: bool = False,
    now: datetime | None = None,
) -> dict:
    """Verify ``bundle`` and install it into ``target``. Returns a summary.

    ``summary["installed"]`` is False when this exact bundle is already the
    installed one — a no-op, so the loader can run on a schedule.
    """
    # The directory the operator named is taken as given (a mount point, or a
    # symlink they chose); it is everything *under* it that must not be a link.
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=True, mode=0o755)
    with _locked(target):
        if recover(target):
            print(f"note: rolled back an install that did not finish under {target}", file=sys.stderr)
        staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=target))
        backup = Path(tempfile.mkdtemp(prefix=BACKUP_PREFIX, dir=target))
        try:
            verified = read_bundle(bundle, staging, limits=limits)
            manifest = verified.manifest
            summary = {
                "event": "enrichment.bundle.install",
                "bundle": bundle.name,
                "bundle_id": verified.bundle_id,
                "built_at": manifest["built_at"],
                "target": str(target),
                "files": sorted(verified.staged),
                "installed": False,
            }
            current = installed_record(target) or {}
            if current.get("bundle_id") == verified.bundle_id:
                summary["reason"] = "already installed"
                return summary
            current_built = _parse_time(current.get("built_at"))
            new_built = _parse_time(manifest["built_at"])
            if current_built and new_built and new_built < current_built and not allow_older:
                raise BundleError(
                    f"the bundle was built {manifest['built_at']}, before the installed one "
                    f"({current['built_at']}); refusing without --allow-older"
                )
            check_content(verified, target)

            installed_at = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
            files = [entry for entry in manifest["files"] if entry["path"] in verified.staged]
            record = {
                "bundle_id": verified.bundle_id,
                "schema_version": manifest["schema_version"],
                "built_at": manifest["built_at"],
                "installed_at": installed_at,
                "bundle": bundle.name,
                "files": files,
            }
            _write_json(staging / INSTALLED_RECORD, record)
            # The dataset manifest is computed over the directory as it will be
            # after the commit — the staged files over whatever else is there —
            # and committed with them, so the two never disagree.
            _write_json(
                staging / enrichment_manifest.MANIFEST_NAME,
                _future_manifest(target, staging, verified, files),
            )
            paths = sorted(verified.staged) + [INSTALLED_RECORD, enrichment_manifest.MANIFEST_NAME]
            _commit(target, staging, backup, paths, verified.bundle_id)
            # After the commit, so best-effort: the install happened, and a full
            # disk refusing one more log line must not report that it did not.
            # The same line is on stdout, in the loader Job's log, either way.
            try:
                with (target / HISTORY).open("a", encoding="utf-8") as history:
                    history.write(
                        json.dumps(
                            {
                                "bundle_id": verified.bundle_id,
                                "built_at": manifest["built_at"],
                                "installed_at": installed_at,
                                "bundle": bundle.name,
                                "host": socket.gethostname(),
                                "user": _user(),
                                "files": len(files),
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
            except OSError as exc:
                print(f"warning: could not append to {HISTORY}: {exc}", file=sys.stderr)
            summary["installed"] = True
            summary["installed_at"] = installed_at
            return summary
        finally:
            shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(backup, ignore_errors=True)


def _user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - a uid with no passwd entry (any k8s pod)
        return str(os.getuid())


def _future_manifest(target: Path, staging: Path, verified: Verified, files: list[dict]) -> dict:
    """``enrichment-manifest.json`` for ``target`` once the staged files are in.

    Built in a scratch copy of the layout (hard links, no data copied), so the
    inspection sees exactly the post-commit directory.
    """
    view = Path(tempfile.mkdtemp(prefix=".view-", dir=staging))
    try:
        for rel in dataset_paths():
            src = verified.staged.get(rel) or (target / rel)
            if not src.is_file() or src.is_symlink():
                continue
            dest = view / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(src, dest)
            except OSError:
                shutil.copy2(src, dest)
        previous = target / enrichment_manifest.MANIFEST_NAME
        if previous.is_file():
            shutil.copy2(previous, view / enrichment_manifest.MANIFEST_NAME)
        by_dataset = {entry["dataset"]: entry for entry in files}
        manifest = enrichment_manifest.build_manifest(
            view,
            refreshed=set(),
            failed=set(),
            bundled=set(by_dataset),
            sources={
                name: str(entry["source"])
                for name, entry in by_dataset.items()
                if name in enrichment_manifest._BINARY_DATASETS and entry.get("source")
            },
            origin_urls={
                name: [str(u) for u in entry.get("source_urls") or []]
                for name, entry in by_dataset.items()
                if entry.get("source_urls")
            },
        )
    finally:
        shutil.rmtree(view, ignore_errors=True)
    # Paths as the readers will see them, not the scratch view's.
    for name, record in manifest["datasets"].items():
        relative = (
            enrichment_manifest._JSON_DATASETS[name][0]
            if name in enrichment_manifest._JSON_DATASETS
            else enrichment_manifest._BINARY_DATASETS[name]
        )
        record["path"] = str(target / relative)
    manifest["bundle_id"] = verified.bundle_id
    return manifest


def verify(bundle: Path, *, limits: Limits = Limits()) -> Verified:
    """Everything ``install`` checks about the archive itself, touching nothing."""
    with tempfile.TemporaryDirectory(prefix="enrichment-bundle-verify-") as scratch:
        verified = read_bundle(bundle, Path(scratch), limits=limits)
        check_content(verified, None)
        # The staged paths die with the scratch directory.
        return Verified(manifest=verified.manifest, bundle_id=verified.bundle_id, staged={})


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _limits(args: argparse.Namespace) -> Limits:
    return Limits(max_bytes=args.max_bytes, max_ratio=args.max_ratio)


def _cmd_build(args: argparse.Namespace) -> int:
    try:
        manifest = build_bundle(args.dir, args.output, compress=not args.no_compress, built_at=args.built_at)
    except (BundleError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REJECTED
    digest, size = _sha256_file(args.output)
    print(f"==> {args.output} ({size} bytes, sha256 {digest})")
    print(f"    built_at {manifest['built_at']}, schema {SCHEMA_VERSION}")
    for entry in manifest["files"]:
        print(
            f"    {entry['path']}: {entry['size']} bytes, updated={entry.get('updated')}, "
            f"origin={entry.get('origin')}, usable={entry.get('usable')}"
        )
    unusable = [e["dataset"] for e in manifest["files"] if e.get("usable") is False]
    if unusable:
        print(f"warning: not usable (below the manifest floor): {', '.join(unusable)}", file=sys.stderr)
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        verified = verify(args.bundle, limits=_limits(args))
    except (BundleError, OSError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return EXIT_REJECTED
    manifest = verified.manifest
    print(f"OK {args.bundle}: bundle_id {verified.bundle_id}, built_at {manifest['built_at']}")
    for entry in manifest["files"]:
        print(f"    {entry['path']}: updated={entry.get('updated')}, sha256={entry['sha256']}")
    return EXIT_OK


def _cmd_install(args: argparse.Namespace) -> int:
    if not args.bundle.exists():
        if args.missing_ok:
            print(f"no bundle at {args.bundle}; nothing to do")
            return EXIT_OK
        print(f"error: {args.bundle} does not exist", file=sys.stderr)
        return EXIT_ERROR
    try:
        summary = install(args.bundle, args.dir, limits=_limits(args), allow_older=args.allow_older)
    except BundleError as exc:
        print(json.dumps({"event": "enrichment.bundle.rejected", "bundle": args.bundle.name, "reason": str(exc)}))
        print(f"REJECTED: {exc} — nothing under {args.dir} was changed", file=sys.stderr)
        return EXIT_REJECTED
    except (InstallError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(json.dumps(summary, sort_keys=True))
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    record = installed_record(args.dir)
    if record is None:
        print(f"no bundle installed under {args.dir}")
        return EXIT_OK
    print(json.dumps(record, indent=2, sort_keys=True))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build", help="pack an enrichment directory into a bundle")
    build.add_argument("--dir", type=Path, required=True, help="Enrichment data directory (a refresh's OCTO_ENRICHMENT_DIR)")
    build.add_argument("-o", "--output", type=Path, required=True)
    build.add_argument("--no-compress", action="store_true", help="plain tar instead of tar.gz")
    build.add_argument("--built-at", default=None, help="ISO-8601 timestamp to record (default: the data's)")
    build.set_defaults(func=_cmd_build)

    for name, func, text in (
        ("verify", _cmd_verify, "check a bundle without installing it"),
        ("install", _cmd_install, "verify a bundle and install it into an enrichment directory"),
    ):
        command = sub.add_parser(name, help=text)
        command.add_argument("bundle", type=Path)
        command.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="cap on the uncompressed total")
        command.add_argument("--max-ratio", type=int, default=DEFAULT_MAX_RATIO, help="cap on uncompressed/compressed")
        command.set_defaults(func=func)
        if name == "install":
            command.add_argument("--dir", type=Path, required=True, help="Enrichment data directory to install into")
            command.add_argument("--allow-older", action="store_true", help="install a bundle built before the installed one")
            command.add_argument("--missing-ok", action="store_true", help="exit 0 when the bundle file does not exist")

    status = sub.add_parser("status", help="show the installed bundle")
    status.add_argument("--dir", type=Path, required=True)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
