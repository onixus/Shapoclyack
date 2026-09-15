"""The run service, reading from object storage instead of a volume (#336).

The point of the exercise is the one thing #336 is for: a run produced by one
API replica has to be listed, scoped, opened and downloaded by another. So each
test writes through one ``Settings`` and reads through a second that shares the
bucket and nothing else.

``api/services/runs.py`` is barely touched by this change -- it still opens
files out of a directory -- so what is being tested here is the seam beneath
it: that the directory it is handed is the right one, and that the listing does
not have to fetch a run to decide whether it may show it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.services import artifact_store
from api.services import runs as runs_service
from api.services.artifact_store import workspace
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
    root = tmp_path / name
    settings = make_settings(
        root,
        artifact_backend="s3",
        artifact_s3_bucket="artifacts",
        artifact_cache_dir=str(root / "cache"),
        artifact_cache_ttl_seconds=0,
        **overrides,
    )
    artifact_store.get_store(settings)._client = shared  # noqa: SLF001
    return settings


def _publish(settings, run_id: str, *, tenant: str | None, surface: str | None = None) -> None:
    directory = workspace.scratch_run_dir(settings, run_id)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "run_meta.json").write_text(
        json.dumps({"profile": "balanced", "started_at": "2026-09-15T10:00:00Z"}),
        encoding="utf-8",
    )
    (directory / "summary.json").write_text(json.dumps({"alive_hosts": 3}), encoding="utf-8")
    workspace.publish_run(settings, run_id)
    if tenant:
        runs_service.write_run_tenant(settings, run_id, tenant, surface=surface)


def test_a_run_published_on_one_replica_is_listed_by_another(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme")

    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1
    assert page[0].run_id == "20260915T100000Z"
    assert page[0].tenant_id == "acme"
    # Read out of the run itself, so the working copy really was materialised.
    assert page[0].alive_hosts == 3
    assert page[0].profile == "balanced"


def test_the_listing_is_newest_first_and_pages(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    for run_id in ("20260913T100000Z", "20260914T100000Z", "20260915T100000Z"):
        _publish(writer, run_id, tenant="acme")

    page, total = runs_service.list_runs(reader, tenant_id="acme", limit=2)
    assert total == 3
    assert [row.run_id for row in page] == ["20260915T100000Z", "20260914T100000Z"]


def test_another_tenants_run_is_not_listed_and_does_not_resolve(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme")
    _publish(writer, "20260915T110000Z", tenant="other")

    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1 and page[0].run_id == "20260915T100000Z"
    assert runs_service.get_run_dir(reader, "20260915T110000Z", tenant_id="acme") is None


def test_a_foreign_run_is_refused_before_it_is_fetched(tmp_path: Path) -> None:
    """Not only a 404 -- it must not cost a transfer either.

    Materialising first and checking the tenant afterwards would let an
    unauthorised caller fill this pod's cache with runs they cannot read, one
    guessed id at a time.
    """
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T110000Z", tenant="other")

    assert runs_service.get_run_dir(reader, "20260915T110000Z", tenant_id="acme") is None
    cache = Path(reader.artifact_cache_dir)
    assert not cache.exists() or not (cache / "20260915T110000Z").exists()


def test_the_surface_filter_reads_the_marker_not_the_run(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme", surface="external")
    _publish(writer, "20260915T110000Z", tenant="acme", surface="internal")

    page, total = runs_service.list_runs(reader, tenant_id="acme", surface="external")
    assert total == 1 and page[0].run_id == "20260915T100000Z"


def test_an_untagged_run_belongs_to_the_default_tenant(tmp_path: Path) -> None:
    """A run from the plain CLI, or from before the marker existed."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant=None)

    _page, total = runs_service.list_runs(reader, tenant_id="default")
    assert total == 1


def test_an_artifact_resolves_to_a_key_without_materialising_the_run(
    tmp_path: Path,
) -> None:
    """Downloading one screenshot must not pull down the scan it came from."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme")

    key = runs_service.artifact_key(
        reader, "20260915T100000Z", "summary.json", tenant_id="acme", allow_restricted=True
    )
    assert key == "runs/20260915T100000Z/summary.json"
    cache = Path(reader.artifact_cache_dir)
    assert not cache.exists() or not (cache / "20260915T100000Z").exists()


def test_an_artifact_key_refuses_what_the_path_resolver_refuses(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme")
    run_id = "20260915T100000Z"

    # Traversal, another tenant's run, a screenshot without the flag, and an
    # object that is simply not there.
    assert runs_service.artifact_key(reader, run_id, "../../etc/passwd", tenant_id="acme") is None
    assert runs_service.artifact_key(reader, run_id, "summary.json", tenant_id="other") is None
    assert (
        runs_service.artifact_key(reader, run_id, "screenshots/a.png", tenant_id="acme") is None
    )
    assert runs_service.artifact_key(reader, run_id, "absent.json", tenant_id="acme") is None


def test_run_detail_lists_the_artifacts_of_the_materialised_copy(tmp_path: Path) -> None:
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared)
    _publish(writer, "20260915T100000Z", tenant="acme")

    detail = runs_service.get_run_detail(reader, "20260915T100000Z", tenant_id="acme")
    assert detail is not None
    assert detail.summary == {"alive_hosts": 3}
    assert "summary.json" in detail.artifacts
    # The artifact list is the scan's own files and nothing the workspace
    # needed to fetch them: bookkeeping inside the working copy would be
    # offered to an operator as part of the run.
    assert sorted(detail.artifacts) == ["run_meta.json", "summary.json", "tenant.json"]
