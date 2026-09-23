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

**The dataset version is what wakes the worker.** ``marker`` is the feed date
plus a digest of the file's bytes, so a refresh that changed nothing (NVD had a
quiet day) does not re-match the estate, and one that changed a single range
does. The digest is taken over the bytes already read for parsing; nothing
stats or hashes the file on a lookup.

Nothing here opens a socket; ``api/services/cpe_ranges_fetch.py`` is the
opt-in step that writes the file.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
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


@dataclass(frozen=True)
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
    cves: dict[str, dict[str, Any]] = field(default_factory=dict)
    statements: int = 0
    present: bool = False
    error: str | None = None

    @property
    def available(self) -> bool:
        return bool(self.index)

    def ranges_for(self, key: str) -> tuple[CpeRange, ...]:
        return self.index.get(key, ())

    def cve_info(self, cve: str) -> dict[str, Any]:
        return self.cves.get(cve, {})


def _text(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


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
    values = {key: _text(raw.get(key)) for key in RANGE_KEYS}
    if not any(values.values()):
        return None
    return CpeRange(
        cve=cve,
        exact=values["v"],
        start_including=values["si"],
        start_excluding=values["se"],
        end_including=values["ei"],
        end_excluding=values["ee"],
    )


def load_dataset(path: Path) -> CpeRangeDataset:
    """Read one dataset. Fail-soft, like every enrichment overlay."""
    try:
        raw_bytes = path.read_bytes()
    except FileNotFoundError:
        return CpeRangeDataset(error="missing")
    except OSError as exc:
        LOG.warning("cpe-ranges: cannot read %s: %s", path, exc)
        return CpeRangeDataset(error=f"unreadable: {exc}")
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        LOG.warning("cpe-ranges: %s is not valid JSON: %s", path, exc)
        return CpeRangeDataset(present=True, error=f"invalid JSON: {exc}")
    if not isinstance(payload, dict):
        return CpeRangeDataset(present=True, error="not an object")
    entries = payload.get("entries")
    if not isinstance(entries, dict):
        return CpeRangeDataset(present=True, error="entries is not a map")

    index: dict[str, tuple[CpeRange, ...]] = {}
    statements = dropped = 0
    for key, raw_ranges in entries.items():
        product_key = str(key).strip().lower()
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

    cves: dict[str, dict[str, Any]] = {}
    raw_cves = payload.get("cves")
    if isinstance(raw_cves, dict):
        for cve, info in raw_cves.items():
            if isinstance(info, dict):
                cves[str(cve).strip().upper()] = info

    updated = _text(payload.get("updated"))
    digest = hashlib.sha256(raw_bytes).hexdigest()[:16]
    return CpeRangeDataset(
        source=_text(payload.get("source")),
        updated=updated,
        marker=f"{updated or 'undated'}:{digest}",
        index=index,
        cves=cves,
        statements=statements,
        present=True,
    )


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
                self._dataset = load_dataset(path)
                self._key = key
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


def status() -> dict[str, Any]:
    """Provenance for the retro-match status route and the fetch script."""
    loaded = dataset()
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
