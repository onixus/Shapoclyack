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

import json
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Protocol, runtime_checkable

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


def _coerce_record(
    raw: Any, *, provider: str, feed_date: str | None
) -> AdvisoryRecord | None:
    """One dataset entry → an :class:`AdvisoryRecord`, or ``None`` if unusable.

    Dropped rather than raised: a single malformed entry in a third-party feed
    must not take the whole dataset — and therefore every match on the
    installation — offline.
    """
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
    return AdvisoryRecord(
        advisory_id=str(raw.get("advisory_id") or cves[0]).strip(),
        cve_ids=cves,
        release=release,
        source_package=source_package,
        fixed_version=fixed_version,
        severity=str(raw.get("severity") or "unknown").strip().lower() or "unknown",
        state=state,
        url=str(raw["url"]).strip() if raw.get("url") else None,
        provider=provider,
        feed_date=feed_date,
    )


@dataclass
class AdvisoryDataset:
    """A loaded dataset file, indexed by ``(release, source_package)``."""

    source: str | None = None
    updated: str | None = None
    origin_url: str | None = None
    records: tuple[AdvisoryRecord, ...] = ()
    index: dict[tuple[str, str], tuple[AdvisoryRecord, ...]] | None = None
    present: bool = False
    error: str | None = None

    def lookup(self, release: str, source_package: str) -> tuple[AdvisoryRecord, ...]:
        return (self.index or {}).get((release, source_package), ())


def load_dataset(path: Path, *, provider: str) -> AdvisoryDataset:
    """Read one advisory dataset. Fail-soft, like every enrichment overlay."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return AdvisoryDataset(error="missing")
    except OSError as exc:
        LOG.warning("advisories: cannot read %s: %s", path, exc)
        return AdvisoryDataset(error=f"unreadable: {exc}")
    except json.JSONDecodeError as exc:
        LOG.warning("advisories: %s is not valid JSON: %s", path, exc)
        return AdvisoryDataset(present=True, error=f"invalid JSON: {exc}")

    if not isinstance(payload, dict):
        return AdvisoryDataset(present=True, error="not an object")
    updated = str(payload.get("updated") or "") or None
    entries: Iterable[Any] = payload.get("entries") or ()
    if not isinstance(entries, (list, tuple)):
        return AdvisoryDataset(present=True, error="entries is not a list")

    records: list[AdvisoryRecord] = []
    dropped = 0
    for raw in entries:
        record = _coerce_record(raw, provider=provider, feed_date=updated)
        if record is None:
            dropped += 1
            continue
        records.append(record)
    if dropped:
        LOG.warning("advisories: dropped %d unusable entries from %s", dropped, path)

    index: dict[tuple[str, str], list[AdvisoryRecord]] = {}
    for record in records:
        index.setdefault((record.release, record.source_package), []).append(record)

    return AdvisoryDataset(
        source=str(payload.get("source") or "") or None,
        updated=updated,
        origin_url=str(payload.get("origin_url") or "") or None,
        records=tuple(records),
        index={key: tuple(value) for key, value in index.items()},
        present=True,
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

    def dataset(self) -> AdvisoryDataset:
        path = self.path()
        key = self._stat_key(path)
        with self._lock:
            if self._dataset is None or self._cache_key != key:
                self._dataset = load_dataset(path, provider=self.name)
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
        return tuple(sorted({record.release for record in self.dataset().records}))

    def advisories_for(
        self, *, release: str, source_package: str
    ) -> tuple[AdvisoryRecord, ...]:
        return self.dataset().lookup(
            (release or "").strip().lower(), (source_package or "").strip().lower()
        )

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
