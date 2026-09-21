"""Run directories, when the run is not on this pod's disk.

A scan produces a *directory*: ``summary.json``, ``alive_hosts.json``,
``diff.json``, a ``screenshots/`` folder, two dozen more. The scanner writes
it with ordinary file calls and knows nothing about object storage, and the API
reads it the same way -- ``api/services/runs.py`` alone opens it from thirty
places. Rewriting all of that into key-addressed reads would be a large change
to the code that is *most* load-bearing, to buy nothing on the installations
that keep the filesystem backend.

So a run keeps being a directory, and this module decides *which* one:

* local backend -- the directory under ``output_dir/runs``, exactly as before.
  Nothing is copied, nothing is cached, and there is no second copy to go
  stale.
* remote backend -- a node-local working copy under the artifact cache,
  materialised from the store on first use and refreshed when it ages out.
  The pod's disk becomes a cache rather than the record, which is the whole
  point: a cache can be an ``emptyDir`` on any node, and two replicas can each
  have one.

A run is written locally and *published* when it is finished. It is not
streamed to the store as the scanner writes it: a half-written run in object
storage is a run another replica can list and read.
"""

from __future__ import annotations

import json
import logging
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from . import keys
from .base import ArtifactStoreError
from . import get_store, is_remote

if TYPE_CHECKING:  # pragma: no cover
    from api.settings import Settings

LOG = logging.getLogger("shapoclyack.artifacts")

#: Where the freshness of a working copy is recorded: one small file per run
#: under the cache root, *beside* the working copies rather than inside them.
#: Inside, it would be uploaded with the next publish and then listed by
#: ``GET /api/runs/{id}`` as one of the run's own artifacts -- a file the
#: scanner never produced, offered to an operator as part of the scan.
SYNC_DIR = ".sync"

#: Run id of the flat, single-run layout (``per_run_output=false``), where
#: artifacts sit directly in ``output_dir``. It has no subtree of its own and
#: is therefore local-only -- see :func:`run_dir`.
FLAT_RUN_ID = "default"


def cache_root(settings: Settings) -> Path:
    """Where working copies live on a remote backend."""
    configured = (settings.artifact_cache_dir or "").strip()
    if configured:
        return Path(configured)
    return Path(settings.state_dir) / "cache" / "runs"


def scratch_run_dir(settings: Settings, run_id: str) -> Path:
    """Where a *writer* builds a run before it is published.

    On the local backend this is the run's final home, so "publish" is a
    no-op and there is never a second copy. On a remote backend it is the
    cache -- the same directory a reader on this pod would get, so a scan that
    has just finished is readable here without a round trip.
    """
    if is_remote(settings):
        return cache_root(settings) / run_id
    if run_id == FLAT_RUN_ID:
        return Path(settings.output_dir)
    return Path(settings.output_dir) / "runs" / run_id


def staging_run_dir(settings: Settings, run_id: str, token: str) -> Path:
    """Where one *attempt's* upload is extracted before it is accepted.

    A run directory is named after the run, and a job keeps its run id across
    attempts, so extracting an upload straight into it publishes whatever
    arrived -- including a straggler from an attempt whose lease has already
    been given to somebody else. Staging is named after that upload's ingest
    token instead, and :func:`promote_staging` moves it into place only once
    the outcome has been written under the same token.

    A *sibling* of the run directory, and a dotted name: inside it would be
    uploaded with the run and listed by ``GET /api/runs/{id}`` as one of the
    scan's own artifacts, and a plain name in the cache root would be read as
    a run of its own by :func:`run_ids`.

    Taking one is also when the abandoned ones are collected. An ingest killed
    with its pod -- or one whose publication is recorded as owed and has run
    out of retries, which leaves its tree on purpose -- has nobody else to
    clean up after it: the cache eviction that sweeps
    these runs only on a remote backend, and a dotted directory is invisible to
    every listing there is, so on the local backend a full extracted run would
    sit in ``output_dir/runs`` for good and grow the disk where nothing reports
    it. Hung off this call rather than a timer because it is the one moment the
    directory is known and an ingest is already paying for I/O.
    """
    destination = scratch_run_dir(settings, run_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _sweep_abandoned(destination.parent)
    return destination.parent / f".ingest-{destination.name}-{token[:12]}"


def staged_archive_path(staging: Path) -> Path:
    """Where the upload's own archive is kept while its publication is owed.

    A *sibling* of the staging tree, not a file inside it: inside, it would be
    uploaded with the run and offered to an operator as one of the scan's
    artifacts — a 300 MB tarball of the directory it sits in.

    It is kept at all because the publication of a run outlives the request
    that accepted it (``api/services/run_publisher.py``). The bus message for
    ``ingest.results.{tenant}`` is built from these bytes and its ``Msg-Id``
    is their digest, so a republish after a broker outage — or after the
    replica was killed between the outcome and the publication — has to send
    *the same* archive. Re-packing the run directory would produce a different
    digest, which is a second message for one run rather than a retry of one.
    """
    staging = Path(staging)
    return staging.parent / f"{staging.name}.upload"


def stage_upload_archive(staging: Path, archive_bytes: bytes) -> Path:
    """Put the accepted upload's archive beside its staging tree."""
    path = staged_archive_path(staging)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(archive_bytes)
    return path


def promote_staging(settings: Settings, run_id: str, staging: Path) -> Path:
    """Move an accepted upload into the run's own directory. Answers where.

    Renamed when the run has no directory yet, which is every first upload and
    costs nothing however large the run is. Merged when it has one -- a run
    the local executor or an earlier partial upload already wrote -- because
    the alternative is deleting artifacts this upload did not carry.
    """
    destination = scratch_run_dir(settings, run_id)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        try:
            staging.rename(destination)
            return destination
        except OSError:
            # Across filesystems, or a directory that appeared between the
            # check and the rename. Copying is the same outcome, slower.
            LOG.debug("Could not rename staged run %s into place", run_id, exc_info=True)
    shutil.copytree(staging, destination, dirs_exist_ok=True)
    # The tree only. The archive beside it is still owed to the ingest bus,
    # and the publisher drops it when the whole publication is done.
    shutil.rmtree(staging, ignore_errors=True)
    return destination


def discard_staging(staging: Path) -> None:
    """Drop a staged upload that was refused, or one already promoted.

    The archive kept beside the tree (:func:`staged_archive_path`) goes with
    it: both belong to one upload, and leaving the tarball behind would keep
    the larger half of it on the disk for nobody.
    """
    shutil.rmtree(staging, ignore_errors=True)
    staged_archive_path(staging).unlink(missing_ok=True)


def run_dir(settings: Settings, run_id: str, *, refresh: bool = True) -> Path:
    """A local directory holding ``run_id``'s artifacts.

    The path is returned whether or not the run exists; callers already test
    ``is_dir()`` and turn the absence into a 404. ``refresh=False`` skips the
    store round trip for a caller that has just written the directory itself.
    """
    if not is_remote(settings):
        return scratch_run_dir(settings, run_id)
    if run_id == FLAT_RUN_ID:
        # The flat layout has no ``runs/<id>`` subtree to fetch, so there is
        # nothing to materialise. Answering with the local output directory
        # keeps a dev box that set per_run_output=false working; a remote
        # backend simply has no flat run to find.
        return Path(settings.output_dir)
    local = cache_root(settings) / run_id
    if refresh:
        _sync_run(settings, run_id, local)
    return local


def run_exists(settings: Settings, run_id: str) -> bool:
    if not is_remote(settings):
        return scratch_run_dir(settings, run_id).is_dir()
    if run_id == FLAT_RUN_ID:
        return Path(settings.output_dir).is_dir()
    store = get_store(settings)
    return any(True for _ in store.list_prefix(keys.run_prefix(run_id)))


def run_ids(settings: Settings) -> list[str]:
    """Every run in the store, newest-looking first.

    Sorted by id descending, which is the ordering the run listing has always
    used: ids are timestamps, so the name sorts the way the clock does without
    opening anything.

    Names beginning with a dot are skipped. The filesystem backend lists what is
    in the directory, and a ``.DS_Store`` beside the runs would otherwise be a
    run in the console with nothing in it -- the previous implementation only
    ever looked at directories and never had to say so.
    """
    store = get_store(settings)
    try:
        children = list(store.list_children(keys.RUNS))
    except ArtifactStoreError:
        LOG.warning("Could not list runs from the artifact store", exc_info=True)
        return []
    return sorted((name for name in children if not name.startswith(".")), reverse=True)


def publish_run(settings: Settings, run_id: str, *, source: Path | None = None) -> int:
    """Put a finished run in the store. Answers how many files went.

    A no-op on the local backend, where the run was written in its final place
    to begin with. Loud on failure, unlike most of the hooks around it: a run
    that is not in the store is a run the *other* replicas cannot see, and
    silently keeping it on one pod's disk is the failure mode #336 is about.
    """
    if not is_remote(settings):
        return 0
    directory = Path(source) if source is not None else scratch_run_dir(settings, run_id)
    if not directory.is_dir():
        return 0
    store = get_store(settings)
    count = store.upload_tree(keys.run_prefix(run_id), directory)
    _mark_synced(settings, run_id)
    LOG.info("Published run %s to the artifact store (%d files)", run_id, count)
    return count


def adopt_local_run(settings: Settings, run_id: str, source: Path) -> int:
    """Publish a run the scanner wrote somewhere of its own choosing.

    A local scan is a subprocess handed ``--output-dir``; it picks the run id
    itself and writes ``<output_dir>/runs/<run_id>``, which nothing here can
    redirect into the cache beforehand. So the directory is published and then
    *becomes* this pod's working copy -- moved, not copied, so a finished scan
    does not sit on the pod's disk twice, and marked synced so the hooks that
    run straight afterwards read it without a round trip.

    A no-op on the local backend: the scanner already wrote the run where it
    belongs.
    """
    source = Path(source)
    if not is_remote(settings) or not source.is_dir():
        return 0
    count = publish_run(settings, run_id, source=source)
    destination = cache_root(settings) / run_id
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(destination, ignore_errors=True)
    try:
        source.rename(destination)
    except OSError:
        # Different filesystems, most likely: the output dir and the cache need
        # not be the same volume. Copy and drop the original instead; the run
        # is already in the store either way, so this only decides whether the
        # next read costs a fetch.
        try:
            shutil.copytree(source, destination, dirs_exist_ok=True)
            shutil.rmtree(source, ignore_errors=True)
        except OSError:
            LOG.warning("Could not adopt the working copy of run %s", run_id, exc_info=True)
            return count
    _mark_synced(settings, run_id)
    return count


def publish_run_file(settings: Settings, run_id: str, relative_path: str, data: bytes) -> None:
    """Write one file into a published run, locally and in the store.

    Exists for the markers written *after* a run is published -- ``tenant.json``
    above all, which names the owner and is what a listing filters on. Writing
    it only to the local copy would leave every other replica reading the run
    as belonging to the default tenant.
    """
    local = scratch_run_dir(settings, run_id) / relative_path
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(data)
    if is_remote(settings):
        get_store(settings).put_bytes(keys.run_artifact(run_id, relative_path), data)


def delete_run(settings: Settings, run_id: str) -> int:
    """Remove a run from the store and from this pod's working copy."""
    store = get_store(settings)
    removed = store.delete_prefix(keys.run_prefix(run_id))
    if is_remote(settings):
        shutil.rmtree(cache_root(settings) / run_id, ignore_errors=True)
        _forget_synced(settings, run_id)
    return removed


def forget_cached_run(settings: Settings, run_id: str) -> None:
    """Drop this pod's working copy without touching the store."""
    if is_remote(settings):
        shutil.rmtree(cache_root(settings) / run_id, ignore_errors=True)
        _forget_synced(settings, run_id)


# -- materialisation ------------------------------------------------------


def _marker_path(settings: Settings, run_id: str) -> Path:
    return cache_root(settings) / SYNC_DIR / f"{run_id}.json"


def _mark_synced(settings: Settings, run_id: str) -> None:
    marker = _marker_path(settings, run_id)
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(json.dumps({"synced_at": time.time()}), encoding="utf-8")
    except OSError:
        # A working copy without a marker is re-fetched next time. Wasteful,
        # never wrong, and not worth failing a publish over.
        LOG.debug("Could not write the sync marker for run %s", run_id, exc_info=True)


def _synced_age(settings: Settings, run_id: str) -> float | None:
    try:
        payload = json.loads(_marker_path(settings, run_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    synced_at = payload.get("synced_at")
    if not isinstance(synced_at, (int, float)):
        return None
    return max(0.0, time.time() - float(synced_at))


def _forget_synced(settings: Settings, run_id: str) -> None:
    try:
        _marker_path(settings, run_id).unlink(missing_ok=True)
    except OSError:
        LOG.debug("Could not drop the sync marker for run %s", run_id, exc_info=True)


def _sync_run(settings: Settings, run_id: str, local: Path) -> None:
    """Bring the working copy of ``run_id`` up to date, if it is not already.

    The freshness window exists because a run is *almost* immutable: it is
    published once and then gains, at most, the markers a completing job
    writes. Re-fetching on every request would make each page of a run listing
    cost its own transfer; never re-fetching would pin whatever this pod saw
    first. A short TTL costs one listing per run per window and bounds how
    long a replica can disagree with the store.
    """
    ttl = max(0, int(settings.artifact_cache_ttl_seconds))
    age = _synced_age(settings, run_id)
    if age is not None and age <= ttl and local.is_dir():
        return
    # One fetch per run at a time in this process. Without it, the four
    # requests a console page makes about a run it has just opened would each
    # start their own transfer of the same directory and then race to rename
    # it into place. Re-checked inside, so the three that waited take the copy
    # the first one brought down.
    with _run_lock(run_id):
        age = _synced_age(settings, run_id)
        if age is not None and age <= ttl and local.is_dir():
            return
        _fetch_run(settings, run_id, local)


_FETCH_LOCKS: dict[str, threading.Lock] = {}
_FETCH_LOCKS_GUARD = threading.Lock()


def _run_lock(run_id: str) -> threading.Lock:
    with _FETCH_LOCKS_GUARD:
        # Never evicted: one Lock per run id this process has fetched, a few
        # dozen bytes each, against a cache that is bounded in gigabytes.
        # Clearing them would need a second lock to be safe about it.
        lock = _FETCH_LOCKS.get(run_id)
        if lock is None:
            lock = threading.Lock()
            _FETCH_LOCKS[run_id] = lock
        return lock


def _fetch_run(settings: Settings, run_id: str, local: Path) -> None:
    store = get_store(settings)
    prefix = keys.run_prefix(run_id)
    try:
        entries = list(store.list_prefix(prefix))
    except ArtifactStoreError:
        LOG.warning("Could not list run %s in the artifact store", run_id, exc_info=True)
        return
    if not entries:
        # Nothing in the store under this id. Any working copy is a leftover
        # from a run that retention has since swept, and keeping it would let
        # a deleted run go on being served by whichever pod happened to cache
        # it.
        shutil.rmtree(local, ignore_errors=True)
        _forget_synced(settings, run_id)
        return
    _evict_cache(settings, keep=run_id)
    # Unique per attempt: this process serialises its own fetches, but a second
    # pod sharing the cache directory -- or a replica restarted mid-fetch --
    # must not be able to delete a staging tree somebody else is filling.
    staging = local.with_name(f".{local.name}.{uuid.uuid4().hex[:8]}.sync")
    try:
        store.download_tree(prefix, staging)
    except ArtifactStoreError:
        shutil.rmtree(staging, ignore_errors=True)
        LOG.warning("Could not materialise run %s", run_id, exc_info=True)
        return
    # Swapped in rather than written in place: a request reading the working
    # copy while it is refreshed would otherwise see a directory that is
    # momentarily missing files it had a second ago.
    previous = staging.with_suffix(".old")
    try:
        if local.exists():
            local.rename(previous)
        staging.rename(local)
    except OSError:
        LOG.warning("Could not swap in the working copy of run %s", run_id, exc_info=True)
        shutil.rmtree(staging, ignore_errors=True)
        return
    finally:
        shutil.rmtree(previous, ignore_errors=True)
    # Marked only once the copy is in place: a crash between the two costs one
    # needless re-fetch, where marking first would serve a half-swapped run.
    _mark_synced(settings, run_id)


#: How long a half-finished transfer may sit in the cache before it is assumed
#: dead. Comfortably longer than any single run takes to fetch, and short
#: enough that a pod killed mid-fetch does not carry the debris for a day.
_ABANDONED_AFTER_SECONDS = 3600

#: The same, for an *ingest* staging tree and the archive beside it. Much
#: longer, because these two are not transfer debris: they are a complete run
#: an agent uploaded and a publication that is recorded as owed
#: (``run_publications``). A publication that has exhausted its retries stays
#: ``dead`` for an operator to decide about, and an hour is not a shift — a
#: day is long enough to be told and short enough that a disk does not carry
#: a failed installation's scans into next week.
_ABANDONED_INGEST_AFTER_SECONDS = 24 * 3600

#: Prefix :func:`staging_run_dir` gives an ingest's tree, and — with
#: ``.upload`` appended — its archive.
_INGEST_PREFIX = ".ingest-"


def _sweep_abandoned(root: Path) -> None:
    """Remove staging trees a killed fetch or a lost ingest left behind.

    They are hidden names, so eviction skips them and they would otherwise be
    the one thing in this directory that grows without a bound. Old ones only:
    a fresh one may be a transfer in progress, here or in another pod sharing
    the volume — or an ingest whose publication this installation still owes,
    which is why those get :data:`_ABANDONED_INGEST_AFTER_SECONDS` instead.
    """
    now = time.time()
    for child in root.iterdir():
        if child.name == SYNC_DIR or not child.name.startswith("."):
            continue
        ingest = child.name.startswith(_INGEST_PREFIX)
        if not child.is_dir() and not (ingest and child.name.endswith(".upload")):
            continue
        cutoff = now - (_ABANDONED_INGEST_AFTER_SECONDS if ingest else _ABANDONED_AFTER_SECONDS)
        try:
            if child.stat().st_mtime >= cutoff:
                continue
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except OSError:
            continue


def _directory_size(directory: Path) -> int:
    total = 0
    for path in directory.rglob("*"):
        try:
            if path.is_file():
                total += path.stat().st_size
        except OSError:
            continue
    return total


def _evict_cache(settings: Settings, *, keep: str) -> None:
    """Keep the working-copy cache under its budget.

    Unbounded, this directory grows to every run the pod has ever served --
    on an ``emptyDir`` sized for a cache, which is how a replica fills its
    node's disk and gets evicted. Oldest working copy goes first; the run
    about to be fetched is never the one evicted.
    """
    budget = max(0, int(settings.artifact_cache_max_mb)) * 1024 * 1024
    if budget <= 0:
        return
    root = cache_root(settings)
    if not root.is_dir():
        return
    _sweep_abandoned(root)
    copies: list[tuple[float, int, Path]] = []
    for child in root.iterdir():
        if not child.is_dir() or child.name == keep or child.name.startswith("."):
            continue
        age = _synced_age(settings, child.name)
        copies.append((age if age is not None else float("inf"), _directory_size(child), child))
    total = sum(size for _, size, _ in copies)
    if total <= budget:
        return
    for _, size, path in sorted(copies, key=lambda item: item[0], reverse=True):
        if total <= budget:
            return
        shutil.rmtree(path, ignore_errors=True)
        _forget_synced(settings, path.name)
        total -= size


# -- cheap per-run metadata ----------------------------------------------

#: ``runs/<id>/tenant.json`` -- who owns a run and what surface it scanned.
#: Read by the run listing for *every* run before paging, which is why it has
#: a cache of its own: on a remote backend that would otherwise be one GET per
#: run per page view.
RUN_MARKER = "tenant.json"

_MARKER_CACHE: dict[str, tuple[float, dict]] = {}
_MARKER_LOCK = threading.Lock()


def read_run_marker(settings: Settings, run_id: str) -> dict:
    """``tenant.json`` for one run, as a dict. ``{}`` when there is none.

    A run written before the marker existed has none, and so does a run
    produced by the plain ``scanner.main`` CLI outside the API -- callers read
    that as the default tenant, which is what those installations scanned as.

    On the local backend this is a file read and is not cached: the file is
    right there, and a cache would only add a window in which a just-written
    marker is invisible. On a remote backend it is cached for the same window
    as a working copy, because the listing asks for every run's marker on
    every page view.
    """
    if not is_remote(settings):
        return _read_marker_file(scratch_run_dir(settings, run_id) / RUN_MARKER)
    ttl = max(0, int(settings.artifact_cache_ttl_seconds))
    now = time.time()
    with _MARKER_LOCK:
        cached = _MARKER_CACHE.get(run_id)
        if cached is not None and now - cached[0] <= ttl:
            return cached[1]
    store = get_store(settings)
    try:
        payload = json.loads(
            store.get_bytes(keys.run_artifact(run_id, RUN_MARKER)).decode("utf-8")
        )
    except Exception:  # noqa: BLE001 - absent, unreadable or not JSON are one case
        payload = {}
    marker = payload if isinstance(payload, dict) else {}
    with _MARKER_LOCK:
        # Bounded crudely rather than with an LRU: the entries are a handful of
        # bytes each and the cap exists so a fleet-wide listing of a hundred
        # thousand runs cannot grow the process without limit.
        if len(_MARKER_CACHE) > 20000:
            _MARKER_CACHE.clear()
        _MARKER_CACHE[run_id] = (now, marker)
    return marker


def forget_run_marker(run_id: str) -> None:
    """Drop one run's cached marker, after this replica has rewritten it."""
    with _MARKER_LOCK:
        _MARKER_CACHE.pop(run_id, None)


def reset_marker_cache() -> None:
    with _MARKER_LOCK:
        _MARKER_CACHE.clear()


def _read_marker_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}
