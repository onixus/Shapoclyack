"""The offline NVD CPE-range dataset behind retro CVE matching.

``docs/retro-cve-matching.md`` is the design; this module is only the file.

NVD states, per CVE, which products and versions it affects as
``configurations[].nodes[].cpeMatch[]`` — a CPE ``criteria`` with an optional
version window (``versionStart/EndIncluding/Excluding``). That is the one
statement that can be re-asked of a fingerprint collected months ago, which is
the whole point of a *retro* match: Pulse's rules are compiled into its binary
and Nuclei's run against a live socket, so neither can answer "what does a CVE
published this morning say about the OpenSSH banner we recorded in June".

**Same envelope as every other overlay** — ``{version, source, updated,
entries}`` under ``scanner/data/``, an ``OCTO_*_DATABASE`` override, a floor in
``scripts/enrichment_manifest.py``, provenance on ``GET /api/system`` — with two
deviations, both for size. ``entries`` is keyed by ``part:vendor:product`` and
each statement is a short-keyed object (``v`` an exact version, ``si``/``se``
start including/excluding, ``ei``/``ee`` end including/excluding): the full NVD
corpus is millions of statements and every repeated long key costs a megabyte.
And per-CVE metadata (score, severity, published date) lives once in a
top-level ``cves`` map rather than on each statement that names the CVE.

**The dataset version is what wakes the worker.** ``marker`` is a digest of
what the file *says* — every statement and every CVE's metadata, canonically
ordered — and deliberately not of its bytes or its ``updated`` date: a refresh
that changed nothing (NVD had a quiet day, but the file was re-stamped and the
week's CVEs re-appended) must not re-match the estate, and one that changed a
single range must. It is computed once per load; nothing stats or hashes the
file on a lookup.

Nothing here opens a socket; ``api/services/cpe_ranges_fetch.py`` is the
opt-in step that writes the file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOG = logging.getLogger("shapoclyack.cpe-ranges")

ENV_VAR = "OCTO_NVD_CPE_DATABASE"
DEFAULT_PATH = "scanner/data/nvd-cpe/nvd-cpe-ranges.json"
SOURCE = "nvd-cve-api-2.0"

#: Short keys of one range statement, in the order a human reads them.
RANGE_KEYS = ("v", "si", "se", "ei", "ee")


@dataclass(frozen=True, slots=True)
class CpeRange:
    """One NVD statement: ``cve`` affects ``product`` in this version window.

    Exactly one of two shapes: ``exact`` set (the criteria named a version),
    or at least one bound set. A statement with neither — a bare ``*`` — says
    "every version" and is dropped at load, see :func:`_coerce_range`.
    """

    cve: str
    exact: str | None = None
    start_including: str | None = None
    start_excluding: str | None = None
    end_including: str | None = None
    end_excluding: str | None = None

    def parts(self) -> tuple[str | None, ...]:
        return (
            self.cve,
            self.exact,
            self.start_including,
            self.start_excluding,
            self.end_including,
            self.end_excluding,
        )

    def describe(self) -> str:
        """The window as an operator reads it, for a finding's evidence."""
        if self.exact:
            return f"= {self.exact}"
        low = (
            f">= {self.start_including}"
            if self.start_including
            else f"> {self.start_excluding}"
            if self.start_excluding
            else ""
        )
        high = (
            f"<= {self.end_including}"
            if self.end_including
            else f"< {self.end_excluding}"
            if self.end_excluding
            else ""
        )
        return ", ".join(part for part in (low, high) if part)


@dataclass
class CpeRangeDataset:
    """A loaded dataset file, indexed by ``part:vendor:product``."""

    source: str | None = None
    updated: str | None = None
    marker: str | None = None
    index: dict[str, tuple[CpeRange, ...]] = field(default_factory=dict)
    #: CVE → ``(cvss, severity, published)`` as loaded; a dict per CVE is
    #: accepted too (tests build datasets by hand).
    cves: dict[str, Any] = field(default_factory=dict)
    statements: int = 0
    present: bool = False
    error: str | None = None

    @property
    def available(self) -> bool:
        return bool(self.index)

    def ranges_for(self, key: str) -> tuple[CpeRange, ...]:
        return self.index.get(key, ())

    def cve_info(self, cve: str) -> dict[str, Any]:
        info = self.cves.get(cve)
        if isinstance(info, tuple):
            cvss, severity, published = info
            return {"cvss": cvss, "severity": severity, "published": published}
        return info or {}


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


def _interned(value: Any) -> str | None:
    text = _text(value)
    return sys.intern(text) if text else None


def _coerce_range(raw: Any) -> CpeRange | None:
    """One statement → :class:`CpeRange`, or ``None`` if it says nothing usable.

    A statement with no version at all is dropped rather than read as "every
    version is affected". NVD does publish those, usually for a product whose
    versions nobody enumerated, and taking them literally would put a finding
    on every host that runs the product — the unusable-by-volume failure
    ``docs/software-cve-matching.md`` describes, arrived at from the other end.
    """
    if not isinstance(raw, dict):
        return None
    cve = str(raw.get("cve") or "").strip().upper()
    if not cve.startswith("CVE-"):
        return None
    values = {key: _interned(raw.get(key)) for key in RANGE_KEYS}
    if not any(values.values()):
        return None
    return CpeRange(
        cve=sys.intern(cve),
        exact=values["v"],
        start_including=values["si"],
        start_excluding=values["se"],
        end_including=values["ei"],
        end_excluding=values["ee"],
    )


def load_dataset(path: Path) -> CpeRangeDataset:
    """Read one dataset. Fail-soft, like every enrichment overlay.

    Built for the full corpus (tens of thousands of products, millions of
    statements) living in every API replica, so memory is a design constraint
    here, measured in docs/retro-cve-matching.md (*Memory*):

    * the parsed JSON is consumed as the index is built (``popitem``), so the
      raw document and the index are not both whole at the peak;
    * statements are slotted tuples-in-disguise (:class:`CpeRange`), version
      strings and CVE ids are interned — "2.4" and "CVE-2021-44228" occur
      thousands of times and are stored once;
    * per-CVE metadata is a tuple, not a dict per CVE;
    * the content digest is streamed into a hash rather than built as one
      canonical string.
    """
    try:
        raw_bytes = path.read_bytes()
    except FileNotFoundError:
        return CpeRangeDataset(error="missing")
    except OSError as exc:
        LOG.warning("cpe-ranges: cannot read %s: %s", path, exc)
        return CpeRangeDataset(error=f"unreadable: {exc}")
    try:
        payload = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        LOG.warning("cpe-ranges: %s is not valid JSON: %s", path, exc)
        return CpeRangeDataset(present=True, error=f"invalid JSON: {exc}")
    del raw_bytes
    if not isinstance(payload, dict):
        return CpeRangeDataset(present=True, error="not an object")
    entries = payload.get("entries")
    if not isinstance(entries, dict):
        return CpeRangeDataset(present=True, error="entries is not a map")

    index: dict[str, tuple[CpeRange, ...]] = {}
    statements = dropped = 0
    while entries:
        key, raw_ranges = entries.popitem()
        product_key = sys.intern(str(key).strip().lower())
        if product_key.count(":") != 2 or not isinstance(raw_ranges, list):
            dropped += 1
            continue
        ranges = []
        for raw in raw_ranges:
            parsed = _coerce_range(raw)
            if parsed is None:
                dropped += 1
                continue
            ranges.append(parsed)
        if ranges:
            index[product_key] = tuple(ranges)
            statements += len(ranges)
    if dropped:
        LOG.warning("cpe-ranges: dropped %d unusable statements from %s", dropped, path)

    cves: dict[str, tuple[float | None, str | None, str | None]] = {}
    raw_cves = payload.get("cves")
    if isinstance(raw_cves, dict):
        while raw_cves:
            cve, info = raw_cves.popitem()
            if not isinstance(info, dict):
                continue
            cvss = info.get("cvss")
            try:
                score = float(cvss) if cvss is not None else None
            except (TypeError, ValueError):
                score = None
            severity = _text(info.get("severity"))
            published = _text(info.get("published"))
            cves[sys.intern(str(cve).strip().upper())] = (
                score,
                sys.intern(severity) if severity else None,
                sys.intern(published) if published else None,
            )

    return CpeRangeDataset(
        source=_text(payload.get("source")),
        updated=_text(payload.get("updated")),
        marker=f"nvd:{_content_digest(index, cves)}",
        index=index,
        cves=cves,
        statements=statements,
        present=True,
    )


def _content_digest(
    index: dict[str, tuple[CpeRange, ...]],
    cves: dict[str, tuple[float | None, str | None, str | None]],
) -> str:
    """Over what the dataset *says*, canonically ordered — not over the bytes.

    A daily refresh re-stamps ``updated`` and re-appends the week's CVEs even
    when NVD changed nothing, and a byte digest would then re-match the whole
    estate every night for nothing. Streamed into the hash product by product.
    """
    digest = hashlib.sha256()
    for key in sorted(index):
        digest.update(key.encode("utf-8"))
        for row in sorted("|".join(part or "" for part in s.parts()) for s in index[key]):
            digest.update(b"\n")
            digest.update(row.encode("utf-8"))
        digest.update(b"\x00")
    for cve in sorted(cves):
        score, severity, published = cves[cve]
        digest.update(f"{cve}|{score}|{severity}|{published}\n".encode("utf-8"))
    return digest.hexdigest()[:16]


class _Holder:
    """The process-wide dataset, reloaded when the file's mtime or size moves.

    Same cache key as ``advisories.base.JsonAdvisoryProvider``: remounting a
    refreshed volume takes effect without a restart, and a lookup never parses.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._dataset: CpeRangeDataset | None = None
        self._key: tuple[str, float, int] | None = None

    def get(self) -> CpeRangeDataset:
        path = dataset_path()
        try:
            stat = path.stat()
            key = (str(path), stat.st_mtime, stat.st_size)
        except OSError:
            key = (str(path), 0.0, -1)
        with self._lock:
            if self._dataset is None or self._key != key:
                # Let go of the old corpus before parsing the new one: holding
                # both at the parse's peak was the reload's whole excess. A
                # caller mid-sweep keeps its own reference, which is the
                # dataset its marker names; nothing else needs the old one.
                self._dataset = None
                self._dataset = load_dataset(path)
                self._key = key
            return self._dataset

    def peek(self) -> CpeRangeDataset | None:
        """What is loaded now, without checking the file or loading it."""
        with self._lock:
            return self._dataset

    def reset(self) -> None:
        with self._lock:
            self._dataset = None
            self._key = None


_HOLDER = _Holder()


def dataset_path() -> Path:
    return Path(os.environ.get(ENV_VAR) or DEFAULT_PATH)


def dataset() -> CpeRangeDataset:
    return _HOLDER.get()


def reload() -> None:
    """Drop the cached dataset. Used by tests and after an opt-in fetch."""
    _HOLDER.reset()


def status(*, load: bool = True) -> dict[str, Any]:
    """Provenance for the retro-match status route and the fetch script.

    ``load=False`` reports what this process already has loaded (the worker's
    view) and never parses the file: a request handler must not be the thing
    that loads a multi-hundred-megabyte corpus, on every replica, after every
    refresh. Nothing loaded yet reads as ``present: False`` with the reason.
    """
    loaded = dataset() if load else _HOLDER.peek()
    if loaded is None:
        loaded = CpeRangeDataset(error="not loaded in this process yet")
    return {
        "path": str(dataset_path()),
        "present": loaded.present,
        "source": loaded.source,
        "updated": loaded.updated,
        "marker": loaded.marker,
        "products": len(loaded.index),
        "statements": loaded.statements,
        "error": loaded.error,
    }
