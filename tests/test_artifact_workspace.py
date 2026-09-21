"""Run directories when the run is not on this pod's disk (#336).

The workspace is what keeps a run a *directory* for the thirty places in
``api/services/runs.py`` that open files out of one, while the record of it
lives in object storage. These tests are written as two replicas -- two
``Settings`` sharing one store and holding separate caches -- because that is
the arrangement the whole issue is about: a second API pod that can see the
first one's runs.
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from api.services import artifact_store
from api.services.artifact_store import keys, workspace
from tests.conftest import make_settings
from tests.fake_s3 import FakeS3Client


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    workspace.reset_marker_cache()


def _replica(tmp_path: Path, name: str, shared: FakeS3Client, **overrides):
    """One API pod: its own disk and cache, the same bucket as its neighbours."""
    root = tmp_path / name
    settings = make_settings(
        root,
        artifact_backend="s3",
        artifact_s3_bucket="artifacts",
        artifact_cache_dir=str(root / "cache"),
        **overrides,
    )
    store = artifact_store.get_store(settings)
    store._client = shared  # noqa: SLF001 - the seam the lazy client exists for
    return settings


def _write_run(directory: Path, *, summary: bytes = b'{"alive_hosts": 1}') -> Path:
    (directory / "screenshots").mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_bytes(summary)
    (directory / "screenshots" / "a.png").write_bytes(b"\x89PNG")
    return directory


# ------------------------------------------------------------ local backend


def test_the_local_backend_hands_back_the_real_directory(tmp_path: Path) -> None:
    """No copy, no cache, no round trip -- the behaviour every release had."""
    settings = make_settings(tmp_path)
    expected = settings.output_dir / "runs" / "r1"
    _write_run(expected)

    assert workspace.run_dir(settings, "r1") == expected
    assert workspace.scratch_run_dir(settings, "r1") == expected
    assert workspace.publish_run(settings, "r1") == 0
    assert not (settings.state_dir / "cache").exists()


def test_the_flat_layout_is_the_output_directory_itself(tmp_path: Path) -> None:
    """``per_run_output=false`` writes artifacts with no ``runs/<id>`` above them."""
    settings = make_settings(tmp_path)
    assert workspace.scratch_run_dir(settings, "default") == settings.output_dir


# ----------------------------------------------------- one bucket, two pods


def test_a_run_published_on_one_replica_is_readable_on_another(tmp_path: Path) -> None:
    shared = FakeS3Client()
    first = _replica(tmp_path, "pod-a", shared)
    second = _replica(tmp_path, "pod-b", shared)

    _write_run(workspace.scratch_run_dir(first, "r1"))
    assert workspace.publish_run(first, "r1") == 2

    materialised = workspace.run_dir(second, "r1")
    assert materialised == Path(second.artifact_cache_dir) / "r1"
    assert (materialised / "summary.json").read_bytes() == b'{"alive_hosts": 1}'
    assert (materialised / "screenshots" / "a.png").read_bytes() == b"\x89PNG"
    # And the second pod sees it in the listing, which is the actual complaint
    # in #336: a run on one pod's volume is invisible to every other.
    assert workspace.run_ids(second) == ["r1"]


def test_a_working_copy_is_not_refetched_inside_the_freshness_window(
    tmp_path: Path,
) -> None:
    """A page of a run listing must not cost one transfer per run per view."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared, artifact_cache_ttl_seconds=300)

    _write_run(workspace.scratch_run_dir(writer, "r1"))
    workspace.publish_run(writer, "r1")
    assert (workspace.run_dir(reader, "r1") / "summary.json").read_bytes() == b'{"alive_hosts": 1}'

    shared.objects[keys.run_artifact("r1", "summary.json")] = (
        b'{"alive_hosts": 99}',
        datetime.now(UTC),
    )
    # Within the window the pod answers from what it has -- which is the point,
    # and the cost: a replica can disagree with the store for this long.
    assert (workspace.run_dir(reader, "r1") / "summary.json").read_bytes() == b'{"alive_hosts": 1}'


def test_a_working_copy_is_refreshed_once_the_window_passes(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared, artifact_cache_ttl_seconds=0)

    _write_run(workspace.scratch_run_dir(writer, "r1"))
    workspace.publish_run(writer, "r1")
    workspace.run_dir(reader, "r1")

    _write_run(workspace.scratch_run_dir(writer, "r1"), summary=b'{"alive_hosts": 99}')
    workspace.publish_run(writer, "r1")
    assert (workspace.run_dir(reader, "r1") / "summary.json").read_bytes() == b'{"alive_hosts": 99}'


def test_a_run_deleted_from_the_store_stops_being_served_from_the_cache(
    tmp_path: Path,
) -> None:
    """Otherwise retention deletes a run and whichever pod cached it keeps it."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared, artifact_cache_ttl_seconds=0)

    _write_run(workspace.scratch_run_dir(writer, "r1"))
    workspace.publish_run(writer, "r1")
    assert workspace.run_dir(reader, "r1").is_dir()

    workspace.delete_run(writer, "r1")
    assert not workspace.run_dir(reader, "r1").is_dir()


def test_a_marker_written_after_publication_reaches_the_store(tmp_path: Path) -> None:
    """``tenant.json`` is written *after* the run is published.

    Locally only, it would leave the run reading back as the default tenant on
    every other replica -- which is the run list of every tenant on the
    installation.
    """
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)

    _write_run(workspace.scratch_run_dir(writer, "r1"))
    workspace.publish_run(writer, "r1")
    workspace.publish_run_file(
        writer, "r1", "tenant.json", json.dumps({"tenant_id": "acme"}).encode("utf-8")
    )

    assert workspace.read_run_marker(reader, "r1")["tenant_id"] == "acme"
    assert (workspace.scratch_run_dir(writer, "r1") / "tenant.json").is_file()


def test_a_run_with_no_marker_reads_as_an_empty_one(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    _write_run(workspace.scratch_run_dir(writer, "r1"))
    workspace.publish_run(writer, "r1")
    assert workspace.read_run_marker(writer, "r1") == {}


# ------------------------------------------------------------- adoption


def test_a_locally_scanned_run_is_published_and_becomes_the_working_copy(
    tmp_path: Path,
) -> None:
    """The scanner picks the run id and writes the directory itself.

    So there is nothing to redirect beforehand: it is published afterwards and
    then *moved* into the cache, rather than copied, so a finished scan does not
    sit on the pod's disk twice.
    """
    shared = FakeS3Client()
    settings = _replica(tmp_path, "pod-a", shared)
    scanner_output = settings.output_dir / "runs" / "r1"
    _write_run(scanner_output)

    assert workspace.adopt_local_run(settings, "r1", scanner_output) == 2
    assert not scanner_output.exists()
    working = workspace.run_dir(settings, "r1", refresh=False)
    assert (working / "summary.json").read_bytes() == b'{"alive_hosts": 1}'
    # Marked synced, so the hooks that run straight afterwards pay nothing --
    # and the marker lives beside the working copies, not inside one, or it
    # would be published with the run and listed as one of its artifacts.
    assert not (working / ".octo-synced").exists()
    assert (Path(settings.artifact_cache_dir) / workspace.SYNC_DIR / "r1.json").is_file()


def test_adoption_is_a_no_op_on_the_local_backend(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    scanner_output = settings.output_dir / "runs" / "r1"
    _write_run(scanner_output)
    assert workspace.adopt_local_run(settings, "r1", scanner_output) == 0
    assert (scanner_output / "summary.json").is_file()


# --------------------------------------------------------------- eviction


def test_the_cache_is_evicted_down_to_its_budget(tmp_path: Path) -> None:
    """An emptyDir sized for a cache must not grow to every run ever served."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(
        tmp_path, "pod-b", shared, artifact_cache_max_mb=1, artifact_cache_ttl_seconds=0
    )

    big = b"x" * (600 * 1024)
    for run_id in ("r1", "r2", "r3"):
        directory = workspace.scratch_run_dir(writer, run_id)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "blob.bin").write_bytes(big)
        workspace.publish_run(writer, run_id)

    for run_id in ("r1", "r2", "r3"):
        workspace.run_dir(reader, run_id)
        # Each copy carries its own sync time, so "oldest first" is decidable.
        time.sleep(0.01)

    cached = sorted(
        path.name
        for path in Path(reader.artifact_cache_dir).iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )
    # The run being fetched is never the one evicted, so the newest survives.
    assert "r3" in cached
    assert len(cached) < 3


def test_eviction_is_off_when_the_budget_is_zero(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(
        tmp_path, "pod-b", shared, artifact_cache_max_mb=0, artifact_cache_ttl_seconds=0
    )
    for run_id in ("r1", "r2"):
        _write_run(workspace.scratch_run_dir(writer, run_id))
        workspace.publish_run(writer, run_id)
        workspace.run_dir(reader, run_id)
    cached = sorted(
        path.name
        for path in Path(reader.artifact_cache_dir).iterdir()
        if path.is_dir() and not path.name.startswith(".")
    )
    assert cached == ["r1", "r2"]


def test_a_staging_tree_an_ingest_never_finished_is_collected(tmp_path):
    """Nobody else cleans up after a killed ingest on the local backend.

    The sweep that collects these trees was reachable only through the cache
    eviction, which runs on a remote backend and nowhere else; and a staging
    directory is dotted, so no listing, no retention pass and no run id ever
    names it. A pod killed mid-ingest therefore left a fully extracted run in
    ``output_dir/runs`` for good — invisible growth on the disk the scans are
    written to. Taking a staging directory is when the old ones go."""
    settings = make_settings(tmp_path, output_dir=tmp_path / "output")
    runs = Path(settings.output_dir) / "runs"
    runs.mkdir(parents=True, exist_ok=True)

    abandoned = runs / ".ingest-20260101T000000Z-deadbeefcafe"
    abandoned.mkdir()
    (abandoned / "summary.json").write_text("{}", encoding="utf-8")
    old = time.time() - 7200
    os.utime(abandoned, (old, old))

    fresh = runs / ".ingest-20260101T000000Z-0badc0ffee11"
    fresh.mkdir()
    real_run = runs / "20260101T000000Z"
    real_run.mkdir()

    staging = workspace.staging_run_dir(settings, "20260102T000000Z", "feedfacefeedface")

    assert not abandoned.exists()
    # Only the abandoned one: a fresh tree may be an ingest in progress in this
    # process or in another pod sharing the volume, and a run is not staging.
    assert fresh.is_dir()
    assert real_run.is_dir()
    assert staging.name.startswith(".ingest-20260102T000000Z-")
