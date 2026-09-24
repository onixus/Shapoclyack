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
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import IO, Any, Iterator

# Siblings, whichever way this file was loaded (script, or by path from tests).
sys.path.insert(0, str(Path(__file__).resolve().parent))

import enrichment_manifest  # noqa: E402 - needs the path above
import feed_fetch  # noqa: E402 - needs the path above

SCHEMA = "shapoclyack.enrichment-bundle"
SCHEMA_VERSION = 1
MANIFEST_MEMBER = "bundle-manifest.json"
INSTALLED_RECORD = "enrichment-bundle.json"
HISTORY = "enrichment-bundle-history.jsonl"
JOURNAL = ".enrichment-bundle-journal.json"
#: The enrichment directory's writer lock, shared with every manifest rewrite.
LOCK = enrichment_manifest.LOCK_NAME
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
#: How far ahead of this host's clock a bundle's built_at may be: clocks on
#: either side of an air gap drift, a day of it is not an attack.
MAX_CLOCK_SKEW = timedelta(days=1)
#: The largest mtime a ustar header holds (eleven octal digits): the year 2242.
USTAR_MAX_MTIME = 8**11 - 1
#: How long an install waits for a manifest rewrite (or another install) in
#: progress; well inside the loader Job's activeDeadlineSeconds.
DEFAULT_INSTALL_LOCK_TIMEOUT = 600.0

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
    """The install could not run (lock held, journal unusable, target unusable)."""


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
    if not 0 <= mtime <= USTAR_MAX_MTIME:
        raise BundleError(f"built_at {manifest['built_at']} is outside what a tar header can record")
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
    make this allocate more than the budget. A negative size is refused here
    as well as at the header: ``read(-1)`` means "everything" to the stream
    underneath, which is the one request the budget must never pass on.
    """

    def __init__(self, stream: IO[bytes], budget: int) -> None:
        self._stream = stream
        self.budget = budget
        self.consumed = 0

    def read(self, size: int) -> bytes:
        if size < 0:
            raise BundleError(f"a negative read size ({size}); refusing")
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
        if size < 0:
            raise BundleError(f"a negative size in {what} ({size}); refusing")
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
    # The size field is base-256 capable, so it can say -1 (review of #339).
    if info.size < 0:
        raise BundleError(f"member {info.name!r} has a negative size ({info.size}); refusing")
    return info


def _parse_manifest(raw: bytes, *, limits: Limits, compressed_size: int, now: datetime) -> dict:
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise BundleError(f"{MANIFEST_MEMBER} is not JSON: {type(exc).__name__}") from exc
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
    built = _parse_time(manifest.get("built_at"))
    if built is None:
        raise BundleError("built_at is missing or not an ISO-8601 timestamp")
    # Installed, a bundle "from the future" would make every genuine one older
    # than the installed one — and the scheduled loader cannot pass
    # --allow-older (review of #339).
    if built > now + MAX_CLOCK_SKEW:
        raise BundleError(
            f"the bundle says it was built {manifest['built_at']}, in the future of this host's "
            f"clock ({now.isoformat(timespec='seconds')}); refusing"
        )
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
        if _parse_time(entry.get("fetched_at")) is None:
            raise BundleError(f"{path!r} has no valid fetched_at")
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
    #: sha256 of the bundle file itself, over exactly the bytes that were parsed.
    sha256: str = ""


class _HashingFile:
    """The bundle file as it is read, hashed: a checksum pin then covers
    exactly the bytes that were parsed, not a second read of the path."""

    def __init__(self, handle: IO[bytes]) -> None:
        self._handle = handle
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        data = self._handle.read(size)
        self.digest.update(data)
        return data

    def drain(self) -> None:
        for chunk in iter(lambda: self._handle.read(CHUNK), b""):
            self.digest.update(chunk)


def _open_regular(bundle: Path) -> tuple[IO[bytes], int]:
    """Open ``bundle`` if, and only if, what was opened is a regular file.

    Decided with fstat on the open descriptor — a stat() of the path followed
    by an open() leaves room to swap a FIFO in between — and opened
    non-blocking, so that opening a FIFO cannot itself hang the loader until
    its deadline.
    """
    try:
        fd = os.open(bundle, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise InstallError(f"{bundle} cannot be opened: {exc.strerror}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BundleError(f"{bundle} is not a regular file")
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, "rb"), info.st_size


class _Reader:
    """One pass over a bundle: the manifest first, and the members only if the
    caller asks for them.

    The split is what makes a scheduled no-op cheap (review of #339): "is
    this bundle already installed" is answered from the manifest alone,
    instead of unpacking and fsyncing the whole archive every fifteen minutes
    to learn the same thing.
    """

    def __init__(self, bundle: Path, *, limits: Limits, now: datetime | None = None) -> None:
        self._raw, compressed_size = _open_regular(bundle)
        self._stream: IO[bytes] | None = None
        try:
            magic = self._raw.read(2)
            self._raw.seek(0)
            self._hashed = _HashingFile(self._raw)
            self._stream = (
                gzip.GzipFile(fileobj=self._hashed, mode="rb")  # type: ignore[arg-type]
                if magic == b"\x1f\x8b"
                else self._hashed  # type: ignore[assignment]
            )
            self._meter = _Meter(self._stream, BLOCK + MANIFEST_MAX_BYTES + BLOCK)
            with _corrupt_as_refusal():
                info = _header(self._meter.read_exact(BLOCK, "the first header"))
                if _check_name(info.name) != MANIFEST_MEMBER:
                    raise BundleError(f"the first member must be {MANIFEST_MEMBER}, not {info.name!r}")
                if info.size > MANIFEST_MAX_BYTES:
                    raise BundleError(f"{MANIFEST_MEMBER} is {info.size} bytes; refusing")
                manifest_bytes = self._meter.read_exact(info.size, MANIFEST_MEMBER)
                self._meter.read_exact(_padding(info.size), MANIFEST_MEMBER)
            self.manifest = _parse_manifest(
                manifest_bytes,
                limits=limits,
                compressed_size=compressed_size,
                now=now or datetime.now(timezone.utc),
            )
            self.bundle_id = hashlib.sha256(manifest_bytes).hexdigest()
            self.sha256 = ""
        except BaseException:
            self.close()
            raise

    def stage(self, staging: Path) -> dict[str, Path]:
        """Verify every member, writing each file under ``staging``."""
        expected = {entry["path"]: entry for entry in self.manifest["files"]}
        staged: dict[str, Path] = {}
        meter = self._meter
        # From here the budget is exact: every listed file with its header and
        # padding, the two end-of-archive blocks, and at most one record of
        # trailing zeros. A byte more is not something this tool wrote. (The
        # ratio was already checked against the declared sizes, so this budget
        # is within it too.)
        framing = sum(BLOCK + e["size"] + _padding(e["size"]) for e in expected.values())
        meter.budget = meter.consumed + framing + 2 * BLOCK + RECORD
        with _corrupt_as_refusal():
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

            # The second end-of-archive block, then only zero padding to the end
            # of the stream. Reading to EOF is also what makes gzip check its CRC.
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
        self._hashed.drain()
        self.sha256 = self._hashed.digest.hexdigest()
        return staged

    def close(self) -> None:
        if self._stream is not None and self._stream is not getattr(self, "_hashed", None):
            with contextlib.suppress(Exception):
                self._stream.close()
        self._raw.close()

    def __enter__(self) -> _Reader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@contextlib.contextmanager
def _corrupt_as_refusal() -> Iterator[None]:
    try:
        yield
    except (EOFError, zlib.error, gzip.BadGzipFile) as exc:
        raise BundleError(f"the archive is corrupt or truncated: {exc}") from exc


def read_bundle(bundle: Path, staging: Path, *, limits: Limits = Limits(), now: datetime | None = None) -> Verified:
    """Verify ``bundle`` member by member, writing each file under ``staging``."""
    with _Reader(bundle, limits=limits, now=now) as reader:
        staged = reader.stage(staging)
        return Verified(manifest=reader.manifest, bundle_id=reader.bundle_id, staged=staged, sha256=reader.sha256)


def _fetched_at(entry: dict) -> float:
    """When the connected side wrote this file, never later than now."""
    fetched = _parse_time(entry.get("fetched_at"))
    now = time.time()
    return now if fetched is None else min(fetched.timestamp(), now)


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
    # The file's age is the data's age: GET /api/system's age_days and stale,
    # and the risk model's overlay staleness, read the mtime. Stamped "now", a
    # bundle of 90-day-old data reads as fresh on exactly the installation that
    # cannot refresh it (review of #339).
    stamp = _fetched_at(entry)
    os.utime(dest, (stamp, stamp))
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
            # The marker is fourteen bytes; the reader is what the API uses.
            try:
                feed_fetch.open_mmdb(staged)
            except Exception as exc:  # noqa: BLE001 - any reader failure is "not a database"
                raise BundleError(f"{rel!r} is not a readable MaxMind DB ({type(exc).__name__}); refusing") from exc
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
        enrichment_manifest.fsync_dir(path.parent)
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise BundleError(f"{path} is not a plain directory; refusing to write through it")


def installed_record(target: Path) -> dict | None:
    try:
        payload = json.loads((target / INSTALLED_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return None
    return payload if isinstance(payload, dict) else None


@contextlib.contextmanager
def _locked(target: Path, timeout: float) -> Iterator[None]:
    """The enrichment directory's writer lock — the same one every manifest
    rewrite takes (enrichment_manifest.locked)."""
    try:
        with enrichment_manifest.locked(target, timeout=timeout):
            yield
    except TimeoutError as exc:
        raise InstallError(
            f"another bundle install or manifest rewrite holds {target / LOCK}; try again later"
        ) from exc


def _transaction_paths() -> set[str]:
    return set(dataset_paths()) | {INSTALLED_RECORD, enrichment_manifest.MANIFEST_NAME}


def _read_journal(journal_path: Path) -> dict:
    """The journal of an interrupted commit, or InstallError if it cannot be
    trusted to drive a rollback.

    Failing closed is the point: the backups the journal names are the only
    copy of the previous data, and a rollback driven by a journal that does
    not parse — or names a backup directory that is not ours, or a path that is
    not a dataset — could as easily destroy them as restore them. Nothing is
    touched and nothing is installed until someone has looked.
    """

    def unusable(reason: str) -> InstallError:
        return InstallError(
            f"{journal_path} is not a usable journal ({reason}). An install was interrupted and "
            f"its rollback cannot be trusted; nothing was changed. The previous data is in the "
            f"{BACKUP_PREFIX}* directory beside it: restore by hand, then remove the journal"
        )

    try:
        journal = json.loads(journal_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise unusable(type(exc).__name__) from exc
    if not isinstance(journal, dict):
        raise unusable("not an object")
    name = journal.get("backup")
    if not isinstance(name, str) or not name.startswith(BACKUP_PREFIX) or "/" in name:
        raise unusable("its backup directory is not one this tool creates")
    files = journal.get("files")
    if not isinstance(files, list):
        raise unusable("no file list")
    allowed = _transaction_paths()
    for item in files:
        if not isinstance(item, dict) or item.get("path") not in allowed or not isinstance(item.get("had_previous"), bool):
            raise unusable("an entry is not a dataset path")
        if item["had_previous"] and not (journal_path.parent / name / item["path"]).is_file():
            raise unusable(f"the backup of {item['path']} is missing")
    return journal


def recover(target: Path) -> bool:
    """Roll back an install that died mid-commit. True if there was one.

    Raises InstallError, leaving everything in place, when the journal cannot
    be trusted — see ``_read_journal``.
    """
    journal_path = target / JOURNAL
    # Killed while writing the journal: no rename, so no commit had started.
    (target / (JOURNAL + ".tmp")).unlink(missing_ok=True)
    rolled_back = False
    if journal_path.exists():
        journal = _read_journal(journal_path)
        backup = target / journal["backup"]
        for item in journal["files"]:
            live = target / item["path"]
            if item["had_previous"]:
                os.replace(backup / item["path"], live)
            else:
                live.unlink(missing_ok=True)
            enrichment_manifest.fsync_dir(live.parent)
        journal_path.unlink()
        enrichment_manifest.fsync_dir(target)
        rolled_back = True
    # Whatever a crashed run left behind and no journal refers to any more.
    for leftover in target.glob(f"{STAGING_PREFIX}*"):
        shutil.rmtree(leftover, ignore_errors=True)
    for leftover in target.glob(f"{BACKUP_PREFIX}*"):
        shutil.rmtree(leftover, ignore_errors=True)
    return rolled_back


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
                with saved.open("rb") as handle:
                    os.fsync(handle.fileno())
            enrichment_manifest.fsync_dir(saved.parent)
            had_previous = True
        journal["files"].append({"path": rel, "had_previous": had_previous})
    # Durable before the first rename: contents fsynced, rename fsynced. Every
    # staged file was fsynced when it was written, and each directory a rename
    # lands in is fsynced after the loop — so after a power loss the directory
    # holds either the journal and a rollback, or the finished commit.
    enrichment_manifest.write_json_durably(target / JOURNAL, journal)
    try:
        for rel in paths:
            os.replace(staging / rel, target / rel)
        for parent in sorted({(target / rel).parent for rel in paths}):
            enrichment_manifest.fsync_dir(parent)
    except BaseException:
        recover(target)
        raise
    (target / JOURNAL).unlink()
    enrichment_manifest.fsync_dir(target)


def _file_sha256_matches(actual: str, pin: str | None) -> None:
    if pin is not None and actual != pin:
        raise BundleError(f"the bundle's sha256 is {actual}, not the pinned {pin}; refusing")


def _normalise_pin(expect_sha256: str | None) -> str | None:
    pin = (expect_sha256 or "").strip().lower() or None
    if pin is not None and not _SHA256.fullmatch(pin):
        raise InstallError("the expected sha256 is not 64 hexadecimal characters")
    return pin


def install(
    bundle: Path,
    target: Path,
    *,
    limits: Limits = Limits(),
    allow_older: bool = False,
    expect_sha256: str | None = None,
    lock_timeout: float = DEFAULT_INSTALL_LOCK_TIMEOUT,
    now: datetime | None = None,
) -> dict:
    """Verify ``bundle`` and install it into ``target``. Returns a summary.

    ``summary["installed"]`` is False when this exact bundle is already the
    installed one — decided from its manifest, before anything is unpacked,
    so the loader can run on a schedule for the price of reading one header.

    ``expect_sha256`` pins the bundle file: only the bundle with that checksum
    is installed. Without it, whoever can write the file the loader reads
    chooses the data (docs/air-gap.md, "Trust").
    """
    pin = _normalise_pin(expect_sha256)
    # The directory the operator named is taken as given (a mount point, or a
    # symlink they chose); it is everything *under* it that must not be a link.
    target = target.resolve()
    target.mkdir(parents=True, exist_ok=True, mode=0o755)
    with _locked(target, lock_timeout):
        if recover(target):
            print(f"note: rolled back an install that did not finish under {target}", file=sys.stderr)
        with _Reader(bundle, limits=limits, now=now) as reader:
            manifest = reader.manifest
            summary: dict[str, Any] = {
                "event": "enrichment.bundle.install",
                "bundle": bundle.name,
                "bundle_id": reader.bundle_id,
                "built_at": manifest["built_at"],
                "target": str(target),
                "files": sorted(entry["path"] for entry in manifest["files"]),
                "installed": False,
            }
            current = installed_record(target) or {}
            if current.get("bundle_id") == reader.bundle_id:
                summary["reason"] = "already installed"
                return summary
            current_built = _parse_time(current.get("built_at"))
            new_built = _parse_time(manifest["built_at"])
            if current_built and new_built and new_built < current_built and not allow_older:
                raise BundleError(
                    f"the bundle was built {manifest['built_at']}, before the installed one "
                    f"({current['built_at']}); refusing without --allow-older"
                )
            staging = Path(tempfile.mkdtemp(prefix=STAGING_PREFIX, dir=target))
            backup = Path(tempfile.mkdtemp(prefix=BACKUP_PREFIX, dir=target))
            try:
                staged = reader.stage(staging)
                _file_sha256_matches(reader.sha256, pin)
                verified = Verified(manifest=manifest, bundle_id=reader.bundle_id, staged=staged, sha256=reader.sha256)
                check_content(verified, target)
                return _commit_install(bundle, target, staging, backup, verified, now)
            finally:
                shutil.rmtree(staging, ignore_errors=True)
                # A journal still on disk means a commit that was neither
                # finished nor rolled back (the rollback itself failed): its
                # backups are the previous data, and the next run needs them.
                if not (target / JOURNAL).exists():
                    shutil.rmtree(backup, ignore_errors=True)


def _commit_install(
    bundle: Path, target: Path, staging: Path, backup: Path, verified: Verified, now: datetime | None
) -> dict:
    manifest = verified.manifest
    installed_at = (now or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    files = [entry for entry in manifest["files"] if entry["path"] in verified.staged]
    record = {
        "bundle_id": verified.bundle_id,
        "sha256": verified.sha256,
        "schema_version": manifest["schema_version"],
        "built_at": manifest["built_at"],
        "installed_at": installed_at,
        "bundle": bundle.name,
        "files": files,
    }
    enrichment_manifest.write_json_durably(staging / INSTALLED_RECORD, record)
    # The dataset manifest is computed over the directory as it will be after
    # the commit — the staged files over whatever else is there — and committed
    # with them, so the two never disagree.
    enrichment_manifest.write_json_durably(
        staging / enrichment_manifest.MANIFEST_NAME,
        _future_manifest(target, staging, verified, files),
    )
    paths = sorted(verified.staged) + [INSTALLED_RECORD, enrichment_manifest.MANIFEST_NAME]
    _commit(target, staging, backup, paths, verified.bundle_id)
    # After the commit, so best-effort: the install happened, and a full disk
    # refusing one more log line must not report that it did not. The same line
    # is on stdout, in the loader Job's log, either way.
    try:
        with (target / HISTORY).open("a", encoding="utf-8") as history:
            history.write(
                json.dumps(
                    {
                        "bundle_id": verified.bundle_id,
                        "sha256": verified.sha256,
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
    return {
        "event": "enrichment.bundle.install",
        "bundle": bundle.name,
        "bundle_id": verified.bundle_id,
        "sha256": verified.sha256,
        "built_at": manifest["built_at"],
        "target": str(target),
        "files": sorted(verified.staged),
        "installed": True,
        "installed_at": installed_at,
    }


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
            # What the connected side called each dataset — `stale` above all —
            # so it is not laundered into a plain `bundle` (review of #339).
            source_origins={
                name: str(entry["origin"])
                for name, entry in by_dataset.items()
                if isinstance(entry.get("origin"), str)
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


def verify(bundle: Path, *, limits: Limits = Limits(), expect_sha256: str | None = None) -> Verified:
    """Everything ``install`` checks about the archive itself, touching nothing."""
    pin = _normalise_pin(expect_sha256)
    with tempfile.TemporaryDirectory(prefix="enrichment-bundle-verify-") as scratch:
        verified = read_bundle(bundle, Path(scratch), limits=limits)
        _file_sha256_matches(verified.sha256, pin)
        check_content(verified, None)
        # The staged paths die with the scratch directory.
        return Verified(manifest=verified.manifest, bundle_id=verified.bundle_id, staged={}, sha256=verified.sha256)


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
        verified = verify(args.bundle, limits=_limits(args), expect_sha256=args.expect_sha256)
    except (BundleError, InstallError, OSError) as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return EXIT_REJECTED
    manifest = verified.manifest
    print(f"OK {args.bundle}: sha256 {verified.sha256}, bundle_id {verified.bundle_id}, built_at {manifest['built_at']}")
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
        summary = install(
            args.bundle,
            args.dir,
            limits=_limits(args),
            allow_older=args.allow_older,
            expect_sha256=args.expect_sha256,
            lock_timeout=args.lock_timeout,
        )
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
        command.add_argument(
            "--expect-sha256",
            default=os.environ.get("OCTO_ENRICHMENT_BUNDLE_SHA256") or None,
            help="refuse any bundle file whose sha256 is not this (default: $OCTO_ENRICHMENT_BUNDLE_SHA256)",
        )
        command.set_defaults(func=func)
        if name == "install":
            command.add_argument("--dir", type=Path, required=True, help="Enrichment data directory to install into")
            command.add_argument("--allow-older", action="store_true", help="install a bundle built before the installed one")
            command.add_argument("--missing-ok", action="store_true", help="exit 0 when the bundle file does not exist")
            command.add_argument(
                "--lock-timeout",
                type=float,
                default=DEFAULT_INSTALL_LOCK_TIMEOUT,
                help="seconds to wait for a manifest rewrite or another install in progress",
            )

    status = sub.add_parser("status", help="show the installed bundle")
    status.add_argument("--dir", type=Path, required=True)
    status.set_defaults(func=_cmd_status)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
