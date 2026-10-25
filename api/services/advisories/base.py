"""Vendor-advisory source layer: the record shape and the offline JSON loader.

The matcher does not consult NVD version ranges (see
docs/software-cve-matching.md for why). It asks a *distribution* what it says
about a *source package* in a *release*, which is the only party that knows
whether a backported fix landed. This module defines that question's answer
type and the offline dataset format the concrete providers read.

**Offline-first, exactly like the enrichment overlays.** EPSS, KEV, CVSS4 and
exploit maturity are shipped as JSON files under ``scanner/data/`` with a
``{version, source, updated, entries}`` envelope, read through an
``OCTO_*_DATABASE`` environment override, inspected at build time by
``scripts/enrichment_manifest.py`` and reported by ``GET /api/system``. The
advisory datasets follow that pattern rather than inventing a second one: an
installation that cannot reach the internet still gets whatever the image
shipped, and an operator can tell a fresh feed from a seed on the System page
instead of from a build log.

Nothing here ever opens a socket. Fetching is a separate, opt-in step
(``api/services/advisories/fetch.py``, off by default) whose only job is to
write one of these files.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import weakref
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from itertools import islice
from pathlib import Path
from typing import Any, Iterator, Protocol, runtime_checkable

LOG = logging.getLogger("shapoclyack.advisories")

#: The release is affected and the distribution shipped a fix in
#: ``fixed_version``. The overwhelmingly common case.
STATE_RESOLVED = "resolved"
#: The release is affected and there is no fix yet. ``fixed_version`` is None.
STATE_OPEN = "open"
#: The distribution states this release is *not* affected — a package built
#: without the vulnerable feature, or a version that predates the flaw. This is
#: the record that turns a naive "version is lower, therefore vulnerable" into
#: a correct "not applicable".
STATE_NOT_AFFECTED = "not_affected"
STATES = (STATE_RESOLVED, STATE_OPEN, STATE_NOT_AFFECTED)


@dataclass(frozen=True)
class AdvisoryRecord:
    """One distribution statement about one source package in one release."""

    #: Vendor advisory identifier: ``DSA-5343-1``, ``USN-6188-1``, or the CVE
    #: id itself when the tracker has a per-release status but no advisory yet.
    advisory_id: str
    #: Every CVE the advisory covers *for this package/release pair*.
    cve_ids: tuple[str, ...]
    #: Release codename (``bullseye``, ``focal``) — never a version number, so
    #: it lines up with ``package_identity.resolve_distro``.
    release: str
    source_package: str
    #: Distribution EVR the fix landed in, or ``None`` for ``open``/
    #: ``not_affected``.
    fixed_version: str | None
    #: Vendor's own word (``critical``/``high``/``medium``/``low``/
    #: ``negligible``/``unknown``), never a CVSS score re-derived here.
    severity: str = "unknown"
    state: str = STATE_RESOLVED
    url: str | None = None
    #: Which provider produced this, carried on the match as evidence.
    provider: str = ""
    #: The date the feed stamped on itself, not the file's mtime.
    feed_date: str | None = None


@runtime_checkable
class AdvisoryProvider(Protocol):
    """What the matcher needs from a distribution's advisory source."""

    #: Stable identifier used in evidence and in the System page dataset name.
    name: str
    #: ``package_identity`` distro keys this provider answers for.
    distro: str

    def available(self) -> bool:
        """True when a dataset is loaded. A provider with no data answers
        nothing rather than answering "no advisories", which would read as
        "clean"."""

    def feed_date(self) -> str | None:
        """Date the feed stamped on itself, for the match's evidence."""

    def entry_count(self) -> int:
        """Records loaded, for ``GET /api/system``."""

    def source_label(self) -> str | None:
        """Where the dataset came from (``debian-security-tracker``)."""

    def releases(self) -> tuple[str, ...]:
        """Release codenames the dataset has any record for."""

    def advisories_for(
        self, *, release: str, source_package: str
    ) -> tuple[AdvisoryRecord, ...]:
        """Every record for this package in this release. Empty is a real
        answer only when :meth:`available` is True."""


# advisory_id, cve_ids, fixed_version, severity, state, url — what a record has
# beyond the (release, source_package) it is filed under and the two
# dataset-wide constants (provider, feed_date).
_Row = tuple[str, tuple[str, ...], "str | None", str, str, "str | None"]


def _coerce_entry(raw: Any) -> tuple[str, str, _Row] | None:
    """One dataset entry → ``(release, source_package, row)``, or ``None``."""
    if not isinstance(raw, dict):
        return None
    release = str(raw.get("release") or "").strip().lower()
    source_package = str(raw.get("source_package") or "").strip().lower()
    if not release or not source_package:
        return None
    cve_ids = raw.get("cve_ids")
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    if not isinstance(cve_ids, (list, tuple)):
        return None
    cves = tuple(
        sorted({str(cve).strip().upper() for cve in cve_ids if str(cve).strip()})
    )
    if not cves:
        return None
    state = str(raw.get("state") or STATE_RESOLVED).strip().lower()
    if state not in STATES:
        return None
    fixed_version = raw.get("fixed_version")
    fixed_version = str(fixed_version).strip() if fixed_version else None
    if state == STATE_RESOLVED and not fixed_version:
        # "Fixed, but we will not say in what" cannot be compared against an
        # installed version; the honest reading is that the release is open.
        state = STATE_OPEN
    if state != STATE_RESOLVED:
        fixed_version = None
    row: _Row = (
        str(raw.get("advisory_id") or cves[0]).strip(),
        cves,
        fixed_version,
        str(raw.get("severity") or "unknown").strip().lower() or "unknown",
        state,
        str(raw["url"]).strip() if raw.get("url") else None,
    )
    return release, source_package, row


def _coerce_record(
    raw: Any, *, provider: str, feed_date: str | None
) -> AdvisoryRecord | None:
    """One dataset entry → an :class:`AdvisoryRecord`, or ``None`` if unusable.

    Not on the production path any more (the loader packs rows via
    :func:`_coerce_entry`); kept as the reference the loader tests compare with.

    Dropped rather than raised: a single malformed entry in a third-party feed
    must not take the whole dataset — and therefore every match on the
    installation — offline.
    """
    coerced = _coerce_entry(raw)
    if coerced is None:
        return None
    release, source_package, row = coerced
    return _record_from_row(release, source_package, row, provider, feed_date)


def _record_from_row(
    release: str,
    source_package: str,
    row: _Row,
    provider: str,
    feed_date: str | None,
) -> AdvisoryRecord:
    advisory_id, cves, fixed_version, severity, state, url = row
    return AdvisoryRecord(
        advisory_id=advisory_id,
        cve_ids=cves,
        release=release,
        source_package=source_package,
        fixed_version=fixed_version,
        severity=severity,
        state=state,
        url=url,
        provider=provider,
        feed_date=feed_date,
    )


class _PackedStore:
    """Statements of a loaded feed, held compressed and decoded on demand.

    A vendor feed is millions of statements; one ``AdvisoryRecord`` object per
    statement cost several gigabytes of heap and OOM-killed the API pod. What
    the matcher asks for is always one ``(release, source_package)`` bucket, so
    each bucket is kept as one zlib blob of JSON rows and turned back into
    records only when asked for (the few hundred most recent buckets are
    cached). ``provider`` and ``feed_date`` are constant for the whole dataset
    and live here, not in every row.
    """

    def __init__(
        self,
        blobs: dict[tuple[str, str], bytes],
        count: int,
        provider: str,
        feed_date: str | None,
    ) -> None:
        self.blobs = blobs
        self.count = count
        self.provider = provider
        self.feed_date = feed_date
        # The cache must not keep ``self`` alive (a bound method would make a
        # reference cycle, and a replaced dataset would linger until a gc pass).
        store = weakref.ref(self)
        self.bucket = lru_cache(maxsize=512)(lambda key: store()._decode(key))

    def _decode(self, key: tuple[str, str]) -> tuple[AdvisoryRecord, ...]:
        release, source_package = key
        return tuple(
            _record_from_row(
                release, source_package, _row_from_json(line),
                self.provider, self.feed_date,
            )
            for line in zlib.decompress(self.blobs[key]).splitlines()
        )


def _row_from_json(line: bytes) -> _Row:
    advisory_id, cves, fixed_version, severity, state, url = json.loads(line)
    return advisory_id, tuple(cves), fixed_version, severity, state, url


class _PackedIndex(Mapping):
    """``(release, source_package) -> tuple[AdvisoryRecord, ...]`` over a store."""

    def __init__(self, store: _PackedStore) -> None:
        self._store = store

    def __getitem__(self, key: tuple[str, str]) -> tuple[AdvisoryRecord, ...]:
        if key not in self._store.blobs:
            raise KeyError(key)
        return self._store.bucket(key)

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self._store.blobs)

    def __len__(self) -> int:
        return len(self._store.blobs)

    def __contains__(self, key: object) -> bool:
        return key in self._store.blobs


class _PackedRecords(Sequence):
    """The flat record list, for callers that still want one. Iterating it
    decodes bucket by bucket; ``len``/``bool`` are free."""

    def __init__(self, store: _PackedStore) -> None:
        self._store = store

    def __len__(self) -> int:
        return self._store.count

    def __iter__(self) -> Iterator[AdvisoryRecord]:
        for key in self._store.blobs:
            yield from self._store.bucket(key)

    def __getitem__(self, index):  # type: ignore[override]
        """Walks buckets up to ``index`` instead of decoding the whole feed."""
        size = len(self)
        if isinstance(index, slice):
            start, stop, step = index.indices(size)
            if step < 0:
                raise NotImplementedError("negative slice steps are not supported")
            return tuple(islice(self, start, stop, step))
        if not isinstance(index, int):
            raise TypeError("record indices must be integers or slices")
        if index < 0:
            index += size
        if not 0 <= index < size:
            raise IndexError("record index out of range")
        return next(islice(self, index, index + 1))


@dataclass
class AdvisoryDataset:
    """A loaded dataset file, indexed by ``(release, source_package)``."""

    source: str | None = None
    updated: str | None = None
    origin_url: str | None = None
    records: Sequence[AdvisoryRecord] = ()
    index: Mapping[tuple[str, str], tuple[AdvisoryRecord, ...]] | None = None
    present: bool = False
    error: str | None = None
    #: Release codenames with any record, computed once at load: the retro
    #: matcher asks for them per CVE per listener, and a set over every record
    #: of a tens-of-megabytes feed is not a per-call cost.
    releases: tuple[str, ...] = ()
    #: Digest of the statements themselves (see :func:`load_dataset`).
    digest: str = ""

    def lookup(self, release: str, source_package: str) -> tuple[AdvisoryRecord, ...]:
        return (self.index or {}).get((release, source_package), ())


def load_dataset(path: Path, *, provider: str) -> AdvisoryDataset:
    """Read a dataset; data/encoding failures are unavailable for every consumer.

    Keep this at the shared loader, not only at the matching boundary: status,
    availability and closure checks must see the same cached failure. Do not
    swallow arbitrary exceptions from a broken provider or normalizer.
    """
    try:
        return _load_dataset(path, provider=provider)
    except (UnicodeError, RecursionError):
        # Includes invalid file encoding, excessive nesting and invalid Unicode
        # encountered while normalizing/hash-encoding the parsed statements.
        LOG.warning("advisories: invalid text or nesting in %s", path)
        return AdvisoryDataset(present=True, error="invalid advisory document")


_CHUNK_CHARS = 1 << 20
_JSON = json.JSONDecoder()


class _JsonReader:
    """Incremental ``raw_decode`` over a text stream.

    ``json.loads`` on a 400 MB feed holds the file text *and* every parsed
    dict at once. This keeps only a window of about one chunk, so the parsed
    form of an entry lives just until it is packed.
    """

    def __init__(self, stream: Any) -> None:
        self.stream = stream
        self.buf = ""
        self.pos = 0
        self.eof = False
        self.grow = _CHUNK_CHARS
        # What has been dropped from the front of the window, so an error can
        # be reported at the file offset ``json.loads`` would give.
        self.consumed = 0
        self.lines = 0
        self.line_start = 0

    def fill(self) -> bool:
        if self.eof:
            return False
        chunk = self.stream.read(self.grow)
        if not chunk:
            self.eof = True
            return False
        dropped = self.buf[: self.pos]
        if dropped:
            self.lines += dropped.count("\n")
            newline = dropped.rfind("\n")
            if newline >= 0:
                self.line_start = self.consumed + newline + 1
            self.consumed += len(dropped)
        self.buf = self.buf[self.pos:] + chunk
        self.pos = 0
        # A genuinely broken document keeps failing at the same place; double
        # the read so that costs O(log n) retries, not O(n / chunk).
        self.grow = max(_CHUNK_CHARS, len(self.buf))
        return True

    def peek(self) -> str:
        """Next non-whitespace character, or ``""`` at end of input."""
        while True:
            buf, pos, size = self.buf, self.pos, len(self.buf)
            while pos < size and buf[pos] in " \t\n\r":
                pos += 1
            self.pos = pos
            if pos < size:
                return buf[pos]
            if not self.fill():
                return ""

    def value(self) -> Any:
        self.peek()  # raw_decode, unlike loads, does not skip leading whitespace
        while True:
            try:
                obj, end = _JSON.raw_decode(self.buf, self.pos)
            except json.JSONDecodeError as exc:
                if self.fill():
                    continue
                # fill() has not moved the window: the position is still in it.
                raise self.error(exc.msg, exc.pos) from None
            if end == len(self.buf) and self.fill():
                continue  # a number or literal may continue in the next chunk
            self.pos = end
            return obj

    def error(self, message: str, at: int) -> json.JSONDecodeError:
        """A ``JSONDecodeError`` at window offset ``at``, numbered as in the file."""
        newline = self.buf.rfind("\n", 0, at)
        lineno = 1 + self.lines + self.buf.count("\n", 0, at)
        colno = at - newline if newline >= 0 else self.consumed + at - self.line_start + 1
        exc = json.JSONDecodeError(message, "", 0)
        exc.pos, exc.lineno, exc.colno = self.consumed + at, lineno, colno
        exc.args = (f"{message}: line {lineno} column {colno} (char {exc.pos})",)
        return exc

    def fail(self, message: str) -> json.JSONDecodeError:
        return self.error(message, self.pos)


def _stream_document(stream: Any) -> Iterator[tuple]:
    """Walk a top-level JSON object, yielding ``entries`` one element at a time.

    Events: ``("meta", key, value)``; ``("entries_list",)`` when an ``entries``
    array starts, then ``("entry", item)`` per element; ``("entries_value",
    value)`` when ``entries`` is not an array; ``("not_object",)`` when the
    document is valid JSON but not an object. Anything malformed raises
    ``json.JSONDecodeError``, exactly as ``json.loads`` would have.
    """
    reader = _JsonReader(stream)
    first = reader.peek()
    if first != "{":
        if first == "﻿":
            raise reader.fail("Unexpected UTF-8 BOM (decode using utf-8-sig)")
        if not first:
            raise reader.fail("Expecting value")
        reader.value()
        if reader.peek():
            raise reader.fail("Extra data")
        yield ("not_object",)
        return
    reader.pos += 1
    if reader.peek() == "}":
        reader.pos += 1
    else:
        while True:
            if reader.peek() != '"':
                raise reader.fail("Expecting property name enclosed in double quotes")
            key = reader.value()
            if reader.peek() != ":":
                raise reader.fail("Expecting ':' delimiter")
            reader.pos += 1
            if key == "entries" and reader.peek() == "[":
                reader.pos += 1
                yield ("entries_list",)
                if reader.peek() == "]":
                    reader.pos += 1
                else:
                    while True:
                        yield ("entry", reader.value())
                        nxt = reader.peek()
                        if nxt not in ("]", ","):
                            raise reader.fail("Expecting ',' delimiter")
                        reader.pos += 1
                        if nxt == "]":
                            break
            elif key == "entries":
                yield ("entries_value", reader.value())
            else:
                yield ("meta", key, reader.value())
            nxt = reader.peek()
            if nxt not in ("}", ","):
                raise reader.fail("Expecting ',' delimiter")
            reader.pos += 1
            if nxt == "}":
                break
    if reader.peek():
        raise reader.fail("Extra data")


def _line(release: str, source_package: str, row: _Row) -> str:
    advisory_id, cves, fixed_version, _severity, state, _url = row
    return (
        f"{release}|{source_package}|{','.join(cves)}|{state}|"
        f"{fixed_version or ''}|{advisory_id}"
    )


def _load_dataset(path: Path, *, provider: str) -> AdvisoryDataset:
    meta: dict[str, Any] = {}
    # Per bucket, one line of JSON per statement. Appended to a bytearray, not
    # kept as objects: a tuple, a list and four strings per statement is what
    # made the old loader cost gigabytes.
    buckets: dict[tuple[str, str], bytearray] = {}
    state: str | None = None  # None | "list" | "empty" | "bad"
    count = 0
    dropped = 0
    intern: dict[str, str] = {}
    try:
        with path.open("r", encoding="utf-8", newline="") as stream:
            for event in _stream_document(stream):
                kind = event[0]
                if kind == "meta":
                    meta[event[1]] = event[2]
                elif kind == "not_object":
                    return AdvisoryDataset(present=True, error="not an object")
                elif kind in ("entries_list", "entries_value"):
                    # A repeated key replaces the earlier value, as in json.loads.
                    buckets.clear()
                    count = dropped = 0
                    if kind == "entries_list":
                        state = "list"
                    else:
                        state = "empty" if not event[1] else "bad"
                else:
                    coerced = _coerce_entry(event[1])
                    if coerced is None:
                        dropped += 1
                        continue
                    release, source_package, row = coerced
                    key = (
                        intern.setdefault(release, release),
                        intern.setdefault(source_package, source_package),
                    )
                    line = json.dumps(row, separators=(",", ":")).encode("ascii")
                    buckets.setdefault(key, bytearray()).extend(line + b"\n")
                    count += 1
    except FileNotFoundError:
        return AdvisoryDataset(error="missing")
    except OSError as exc:
        LOG.warning("advisories: cannot read %s: %s", path, exc)
        return AdvisoryDataset(error=f"unreadable: {exc}")
    except json.JSONDecodeError as exc:
        LOG.warning("advisories: %s is not valid JSON: %s", path, exc)
        return AdvisoryDataset(present=True, error=f"invalid JSON: {exc}")
    except ValueError as exc:
        if isinstance(exc, UnicodeError):
            raise
        # json may raise a plain ValueError for Python's integer-string
        # conversion ceiling. Limit this handler to parsing, not normalization.
        LOG.warning("advisories: JSON value exceeds parser limits in %s", path)
        return AdvisoryDataset(present=True, error="invalid JSON value")

    if state == "bad":
        return AdvisoryDataset(present=True, error="entries is not a list")
    updated = str(meta.get("updated") or "") or None
    if dropped:
        LOG.warning("advisories: dropped %d unusable entries from %s", dropped, path)

    # What the dataset says, independent of when it was fetched and of entry
    # order: the retro matcher re-matches the estate when this moves, and a
    # daily refresh that re-stamped ``updated`` over the same statements must
    # not be a reason to (api/services/retro_match_worker.py). The value is the
    # sha256 of the sorted statement lines joined by newlines. Lines of one
    # bucket share their ``release|package|`` prefix, so sorting buckets by that
    # prefix and each bucket's lines among themselves is the global sort — unless
    # one prefix is a prefix of another, which only a ``|`` in a package name
    # can cause; that case sorts every line, as before.
    ordered = sorted((f"{key[0]}|{key[1]}|", key) for key in buckets)
    flat_sort = any(
        later.startswith(earlier)
        for (earlier, _), (later, _) in zip(ordered, ordered[1:])
    )
    digest = hashlib.sha256()
    all_lines: list[str] = []
    wrote = False
    blobs: dict[tuple[str, str], bytes] = {}
    for _prefix, key in ordered:
        raw = buckets.pop(key)
        lines = [_line(*key, _row_from_json(item)) for item in raw.splitlines()]
        if flat_sort:
            all_lines.extend(lines)
        else:
            for text in sorted(lines):
                digest.update((("\n" if wrote else "") + text).encode("utf-8"))
                wrote = True
        blobs[key] = zlib.compress(bytes(raw), 6)
    if flat_sort:
        digest.update("\n".join(sorted(all_lines)).encode("utf-8"))

    store = _PackedStore(blobs, count, provider, updated)
    return AdvisoryDataset(
        source=str(meta.get("source") or "") or None,
        updated=updated,
        origin_url=str(meta.get("origin_url") or "") or None,
        records=_PackedRecords(store),
        index=_PackedIndex(store),
        present=True,
        releases=tuple(sorted({key[0] for key in blobs})),
        digest=digest.hexdigest()[:16],
    )


class JsonAdvisoryProvider:
    """An :class:`AdvisoryProvider` backed by one offline JSON dataset.

    The dataset is loaded once and cached, and the cache key is the resolved
    path *and* the file's mtime, so remounting a refreshed volume takes effect
    without a restart while a hot path never stats-then-parses on every lookup.
    """

    #: Subclass hooks.
    name: str = "advisory"
    distro: str = ""
    env_var: str = ""
    default_path: str = ""
    case_sensitive_packages: bool = False

    def __init__(self, path: str | Path | None = None) -> None:
        self._explicit_path = Path(path) if path else None
        self._lock = threading.Lock()
        self._dataset: AdvisoryDataset | None = None
        self._cache_key: tuple[str, float, int] | None = None

    # -- path resolution ---------------------------------------------------
    def path(self) -> Path:
        if self._explicit_path is not None:
            return self._explicit_path
        return Path(os.environ.get(self.env_var) or self.default_path)

    def _stat_key(self, path: Path) -> tuple[str, float, int]:
        try:
            stat = path.stat()
        except OSError:
            return (str(path), 0.0, -1)
        return (str(path), stat.st_mtime, stat.st_size)

    def _load_dataset(self, path: Path) -> AdvisoryDataset:
        """Format hook; all providers share the same cache and snapshot rules."""
        return load_dataset(path, provider=self.name)

    def dataset(self) -> AdvisoryDataset:
        path = self.path()
        key = self._stat_key(path)
        with self._lock:
            if self._dataset is None or self._cache_key != key:
                self._dataset = self._load_dataset(path)
                self._cache_key = key
            return self._dataset

    def reload(self) -> None:
        """Drop the cache. Used by tests and after an opt-in fetch."""
        with self._lock:
            self._dataset = None
            self._cache_key = None

    # -- AdvisoryProvider --------------------------------------------------
    def available(self) -> bool:
        dataset = self.dataset()
        return bool(dataset.records)

    def feed_date(self) -> str | None:
        return self.dataset().updated

    def entry_count(self) -> int:
        return len(self.dataset().records)

    def source_label(self) -> str | None:
        return self.dataset().source

    def releases(self) -> tuple[str, ...]:
        return self.dataset().releases

    def content_digest(self) -> str:
        """Digest of what the loaded dataset says; ``""`` when nothing is loaded."""
        return self.dataset().digest

    def advisories_for(
        self, *, release: str, source_package: str
    ) -> tuple[AdvisoryRecord, ...]:
        package = (source_package or "").strip()
        if not self.case_sensitive_packages:
            package = package.lower()
        return self.dataset().lookup((release or "").strip().lower(), package)

    def status(self) -> dict[str, Any]:
        """Provenance for ``GET /api/system`` and the fetch script."""
        dataset = self.dataset()
        return {
            "name": self.name,
            "distro": self.distro,
            "path": str(self.path()),
            "present": dataset.present,
            "source": dataset.source,
            "updated": dataset.updated,
            "entries": len(dataset.records),
            "releases": list(self.releases()),
            "error": dataset.error,
        }
