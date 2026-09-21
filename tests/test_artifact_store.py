"""The artifact store itself: keys, the two backends, and the run workspace (#336).

What makes these tests worth their length is that the *default* backend must
not have changed. Every assertion about the local store is an assertion that an
installation which upgrades and sets nothing finds its runs exactly where it
left them -- so the paths are written out literally rather than derived from
the code under test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.services import artifact_store
from api.services.artifact_store import keys, workspace
from api.services.artifact_store.base import normalize_key
from api.services.artifact_store.local import LocalArtifactStore
from api.services.artifact_store.s3 import S3ArtifactStore, S3Config
from tests.conftest import make_settings
from tests.fake_s3 import FakeClientError, FakeS3Client


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    workspace.reset_marker_cache()


# ------------------------------------------------------------------- keys


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "/", "..", "runs/../../etc/passwd", "../secrets", "runs/\x00/x"],
)
def test_a_key_that_escapes_the_store_is_refused(bad: str) -> None:
    """The check that has to exist once, at the bottom.

    Run ids and report filenames reach a key from URLs and database rows. On
    the filesystem backend a key is joined onto a directory, so ``..`` here is
    a write outside the artifact root -- refusing in :func:`normalize_key`
    means no backend has to remember to.
    """
    with pytest.raises(ValueError):
        normalize_key(bad)


def test_keys_are_the_paths_the_product_already_used() -> None:
    assert keys.run_prefix("20260915T101112Z") == "runs/20260915T101112Z"
    assert keys.run_artifact("r1", "screenshots/a.png") == "runs/r1/screenshots/a.png"
    assert keys.report_key("acme", "rpt_0123456789abcdef.pdf") == (
        "reports/acme/rpt_0123456789abcdef.pdf"
    )
    assert keys.job_inputs_prefix("job-1") == "job_inputs/job-1"


def test_a_backslash_is_a_separator_not_a_filename() -> None:
    """An agent on Windows uploads ``screenshots\\a.png``.

    Left alone, that is one filename on POSIX and a folder on S3 -- the same
    artifact under two keys depending on who wrote it.
    """
    assert normalize_key("runs/r1\\screenshots\\a.png") == "runs/r1/screenshots/a.png"


# ------------------------------------------------------------ local backend


def _local(tmp_path: Path) -> LocalArtifactStore:
    return LocalArtifactStore(output_root=tmp_path / "output", state_root=tmp_path / "state")


def test_local_keys_land_where_the_product_has_always_written_them(tmp_path: Path) -> None:
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("reports/acme/rpt_1.pdf", b"%PDF")
    store.put_bytes("job_inputs/job-1/scan_scope.json", b"[]")

    # Run output and reports under OCTO_OUTPUT_DIR; scratch under OCTO_STATE_DIR.
    # Two roots because an operator has always been able to point them at
    # different volumes, and collapsing them would relocate every existing file.
    assert (tmp_path / "output" / "runs" / "r1" / "summary.json").read_bytes() == b"{}"
    assert (tmp_path / "output" / "reports" / "acme" / "rpt_1.pdf").read_bytes() == b"%PDF"
    assert (tmp_path / "state" / "job_inputs" / "job-1" / "scan_scope.json").read_bytes() == b"[]"


def test_local_round_trip_and_absence(tmp_path: Path) -> None:
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"hello")
    assert store.get_bytes("runs/r1/summary.json") == b"hello"
    assert b"".join(store.stream("runs/r1/summary.json", chunk_size=2)) == b"hello"
    assert store.exists("runs/r1/summary.json")
    assert store.size("runs/r1/summary.json") == 5

    assert not store.exists("runs/r1/absent.json")
    assert store.size("runs/r1/absent.json") is None
    with pytest.raises(artifact_store.ArtifactNotFound):
        store.get_bytes("runs/r1/absent.json")
    with pytest.raises(artifact_store.ArtifactNotFound):
        store.stream("runs/r1/absent.json")


def test_local_directory_is_not_an_object(tmp_path: Path) -> None:
    """``size`` of a prefix is ``None``, not the directory's 4096 bytes.

    Object storage has no directory to report a size for, so a caller that got
    a number back here would believe a run was a file.
    """
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    assert store.size("runs/r1") is None
    assert store.stat("runs/r1") is None


def test_local_listing_and_children(tmp_path: Path) -> None:
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("runs/r1/screenshots/a.png", b"\x89PNG")
    store.put_bytes("runs/r2/summary.json", b"{}")

    assert {entry.key for entry in store.list_prefix("runs/r1")} == {
        "runs/r1/summary.json",
        "runs/r1/screenshots/a.png",
    }
    assert sorted(store.list_children("runs")) == ["r1", "r2"]
    assert sorted(store.list_children("runs/r1")) == ["screenshots", "summary.json"]


def test_local_delete_prefix_removes_the_subtree_and_nothing_beside_it(tmp_path: Path) -> None:
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("runs/r1/screenshots/a.png", b"x")
    store.put_bytes("runs/r10/summary.json", b"{}")

    assert store.delete_prefix("runs/r1") == 2
    assert not store.exists("runs/r1/summary.json")
    # `runs/r1` is a string prefix of `runs/r10`. On a filesystem that is two
    # directories; the S3 backend has to add the slash itself to agree.
    assert store.exists("runs/r10/summary.json")


def test_local_upload_tree_into_itself_copies_nothing(tmp_path: Path) -> None:
    """Publishing on the local backend must not double every run's bytes."""
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    source = tmp_path / "output" / "runs" / "r1"
    assert store.upload_tree("runs/r1", source) == 1
    assert sorted(p.name for p in source.iterdir()) == ["summary.json"]


def test_local_never_presigns(tmp_path: Path) -> None:
    """There is no URL a browser could fetch a file on the API's disk from."""
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    assert store.presigned_url("runs/r1/summary.json", expires_seconds=60) is None


# --------------------------------------------------------------- s3 backend


def _s3(**overrides) -> tuple[S3ArtifactStore, FakeS3Client]:
    config = S3Config(bucket="artifacts", **overrides)
    store = S3ArtifactStore(config)
    client = FakeS3Client()
    store._client = client  # noqa: SLF001 - the seam the lazy client exists for
    return store, client


def test_s3_prefixes_every_key_with_the_installation_prefix() -> None:
    store, client = _s3(prefix="shapoclyack")
    store.put_bytes("runs/r1/summary.json", b"{}")
    assert list(client.objects) == ["shapoclyack/runs/r1/summary.json"]
    # ...and strips it again, so callers never see it.
    assert [entry.key for entry in store.list_prefix("runs/r1")] == ["runs/r1/summary.json"]
    assert store.get_bytes("runs/r1/summary.json") == b"{}"


def test_s3_listing_a_run_does_not_match_its_longer_sibling() -> None:
    store, _ = _s3()
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("runs/r10/summary.json", b"{}")
    assert [entry.key for entry in store.list_prefix("runs/r1")] == ["runs/r1/summary.json"]


def test_s3_children_are_folders_not_every_object_below_them() -> None:
    """What makes the run listing affordable: one delimited call, not a walk."""
    store, _ = _s3()
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("runs/r1/screenshots/a.png", b"x")
    store.put_bytes("runs/r2/summary.json", b"{}")
    assert sorted(store.list_children("runs")) == ["r1", "r2"]


def test_s3_missing_object_is_not_found_rather_than_an_error() -> None:
    store, _ = _s3()
    with pytest.raises(artifact_store.ArtifactNotFound):
        store.get_bytes("runs/r1/summary.json")
    assert store.size("runs/r1/summary.json") is None
    assert store.stat("runs/r1/summary.json") is None
    assert not store.exists("runs/r1/summary.json")


def test_s3_failure_is_a_store_error_not_a_missing_file() -> None:
    """A gateway that refuses must not read as an empty installation.

    This is the distinction :class:`ArtifactStoreError` exists for: callers
    that wrap artifact access in ``except OSError`` would otherwise swallow a
    bad credential and show the operator a console with no runs in it.
    """
    store, client = _s3()
    client.fail_with = FakeClientError("AccessDenied", status=403)
    with pytest.raises(artifact_store.ArtifactStoreError):
        store.put_bytes("runs/r1/summary.json", b"{}")


def test_s3_tree_round_trip(tmp_path: Path) -> None:
    store, _ = _s3()
    source = tmp_path / "run"
    (source / "screenshots").mkdir(parents=True)
    (source / "summary.json").write_bytes(b"{}")
    (source / "screenshots" / "a.png").write_bytes(b"\x89PNG")

    assert store.upload_tree("runs/r1", source) == 2
    dest = tmp_path / "back"
    assert store.download_tree("runs/r1", dest) == 2
    assert (dest / "summary.json").read_bytes() == b"{}"
    assert (dest / "screenshots" / "a.png").read_bytes() == b"\x89PNG"


def test_s3_delete_prefix_batches() -> None:
    store, client = _s3()
    for index in range(1005):
        store.put_bytes(f"runs/r1/screenshots/{index}.png", b"x")
    assert store.delete_prefix("runs/r1") == 1005
    # delete_objects takes a thousand keys per call, and a long-retained run
    # exceeds that on screenshots alone.
    assert [len(batch) for batch in client.deleted_batches] == [1000, 5]
    assert client.objects == {}


def test_s3_delete_keys_takes_the_named_objects_and_leaves_their_neighbours() -> None:
    """The rollback of a half-finished upload, which is not a prefix delete.

    A run prefix can hold keys the failed transfer never wrote — an attempt in
    another replica that succeeded, or an operator's hand-loaded artifact — and
    ``delete_prefix`` on that prefix is a run deleter, not a rollback. Batched
    like the prefix delete, because a run that failed late wrote thousands of
    screenshots.
    """
    store, client = _s3()
    for index in range(1005):
        store.put_bytes(f"runs/r1/screenshots/{index}.png", b"x")
    store.put_bytes("runs/r1/not-ours.json", b"{}")

    mine = [f"runs/r1/screenshots/{index}.png" for index in range(1005)]
    assert store.delete_keys(mine) == 1005
    assert [len(batch) for batch in client.deleted_batches] == [1000, 5]
    assert list(client.objects) == ["runs/r1/not-ours.json"]


def test_local_delete_keys_takes_the_named_objects_only(tmp_path: Path) -> None:
    store = _local(tmp_path)
    store.put_bytes("runs/r1/summary.json", b"{}")
    store.put_bytes("runs/r1/not-ours.json", b"{}")
    assert store.delete_keys(["runs/r1/summary.json", "runs/r1/gone.json"]) == 1
    assert not store.exists("runs/r1/summary.json")
    assert store.exists("runs/r1/not-ours.json")


def test_s3_upload_tree_reports_the_keys_it_wrote_before_it_failed(tmp_path: Path) -> None:
    """What a rollback has to know, and what the return value cannot carry.

    ``upload_tree`` raises when the store refuses a file halfway, so its count
    is lost; the source directory describes the keys it *would* have written,
    not the ones it did. The collector is how the caller learns the difference.
    """
    store, client = _s3()
    source = tmp_path / "run"
    source.mkdir()
    (source / "a.json").write_bytes(b"{}")
    (source / "b.json").write_bytes(b"{}")
    (source / "c.json").write_bytes(b"{}")
    client.refuse_keys = {"runs/r1/b.json", "runs/r1/c.json"}

    written: list[str] = []
    with pytest.raises(artifact_store.ArtifactStoreError):
        store.upload_tree("runs/r1", source, written=written)
    assert written == ["runs/r1/a.json"]


def test_s3_presign_carries_the_filename_and_the_expiry() -> None:
    store, client = _s3(presign_enabled=True)
    store.put_bytes("reports/acme/rpt_1.pdf", b"%PDF")
    url = store.presigned_url(
        "reports/acme/rpt_1.pdf",
        expires_seconds=120,
        filename="Q3 report.pdf",
        content_type="application/pdf",
    )
    assert url
    params = client.presign_calls[0]["params"]
    assert params["ResponseContentDisposition"] == 'attachment; filename="Q3 report.pdf"'
    assert params["ResponseContentType"] == "application/pdf"
    assert client.presign_calls[0]["expires"] == 120


def test_s3_does_not_presign_unless_asked_to() -> None:
    """Off by default, and the default is the interesting half.

    The console downloads through XHR, so a redirect to the bucket is a
    cross-origin request the browser blocks unless the bucket sends CORS
    headers -- and an in-cluster MinIO is usually not reachable from a browser
    at all. Streaming always works, so that is what an installation gets until
    it asks for the other thing.
    """
    store, _ = _s3()
    store.put_bytes("reports/acme/rpt_1.pdf", b"%PDF")
    assert store.presigned_url("reports/acme/rpt_1.pdf", expires_seconds=120) is None


def test_s3_health_is_a_head_of_the_bucket() -> None:
    store, client = _s3()
    assert store.healthy() == (True, "ok")
    assert client.buckets_headed == ["artifacts"]
    client.fail_with = FakeClientError("AccessDenied", status=403)
    ok, detail = store.healthy()
    assert not ok and "artifacts" in detail


# ----------------------------------------------------------------- factory


def test_the_default_backend_is_the_filesystem(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    store = artifact_store.get_store(settings)
    assert store.backend == "local"
    assert not artifact_store.is_remote(settings)


def test_a_misspelt_backend_is_refused_not_quietly_local(tmp_path: Path) -> None:
    """An operator who asked for object storage and got a filesystem would find
    out when the second replica could not see the first one's runs -- which is
    the failure the whole module exists to end."""
    settings = make_settings(tmp_path, artifact_backend="s4")
    with pytest.raises(artifact_store.ArtifactStoreError):
        artifact_store.build_store(settings)


def test_s3_without_a_bucket_is_refused(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, artifact_backend="s3", artifact_s3_bucket="")
    with pytest.raises(artifact_store.ArtifactStoreError):
        artifact_store.build_store(settings)


def test_the_store_is_cached_per_configuration(tmp_path: Path) -> None:
    """One boto3 client and its connection pool per process, not per request."""
    settings = make_settings(tmp_path)
    assert artifact_store.get_store(settings) is artifact_store.get_store(settings)
    other = make_settings(tmp_path, artifact_backend="s3", artifact_s3_bucket="b")
    assert artifact_store.get_store(other) is not artifact_store.get_store(settings)


# --------------------------------------------------------------- downloads


def test_a_download_streams_when_the_backend_cannot_presign(tmp_path: Path) -> None:
    from api.routes import _artifact_download as download

    settings = make_settings(tmp_path)
    artifact_store.get_store(settings).put_bytes("reports/acme/rpt_1.pdf", b"%PDF-1.7")

    response = download.respond(
        settings, "reports/acme/rpt_1.pdf", media_type="application/pdf", filename="q3.pdf"
    )
    assert response.status_code == 200
    assert response.headers["content-length"] == "8"
    assert 'filename="q3.pdf"' in response.headers["content-disposition"]


def test_a_download_redirects_when_presigning_is_turned_on(tmp_path: Path) -> None:
    from api.routes import _artifact_download as download

    settings = make_settings(
        tmp_path,
        artifact_backend="s3",
        artifact_s3_bucket="artifacts",
        artifact_presign_enabled=True,
    )
    store = artifact_store.get_store(settings)
    store._client = FakeS3Client()  # noqa: SLF001
    store.put_bytes("reports/acme/rpt_1.pdf", b"%PDF-1.7")

    response = download.respond(
        settings, "reports/acme/rpt_1.pdf", media_type="application/pdf", filename="q3.pdf"
    )
    assert response.status_code == 307
    assert "reports/acme/rpt_1.pdf" in response.headers["location"]


def test_a_download_of_something_that_went_away_is_a_404(tmp_path: Path) -> None:
    """Every caller checked existence a moment ago; the gap is where retention runs."""
    from fastapi import HTTPException

    from api.routes import _artifact_download as download

    settings = make_settings(tmp_path)
    with pytest.raises(HTTPException) as refusal:
        download.respond(settings, "reports/acme/absent.pdf", media_type="x", filename="a.pdf")
    assert refusal.value.status_code == 404


def test_a_content_disposition_cannot_be_talked_out_of_its_header() -> None:
    """The filename comes from a report title and from run artifact names.

    A quote or a newline in a header value is response splitting, not a
    cosmetic problem -- and the non-ASCII half has to survive as well, or a
    Russian-titled report downloads as a row of question marks.
    """
    from api.routes._artifact_download import content_disposition

    hostile = content_disposition('evil"; filename="passwd\nX-Injected: 1')
    assert "\n" not in hostile and hostile.count('"') == 2

    cyrillic = content_disposition("отчёт.pdf")
    assert "filename*=UTF-8''" in cyrillic
    assert "%D0%BE" in cyrillic
