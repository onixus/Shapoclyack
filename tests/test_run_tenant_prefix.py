"""Run keys carry their owner, and runs from before that still read (#427).

Two defects, one layout. The scanner CLI minted a bare second as its run id
after the API had stopped doing so (#421), and a run's key was ``runs/<id>``
with no tenant in it, so a run id was the *only* thing between one tenant's
scan and another's (#311). A run now lives at ``runs/_tenants/<tenant>/<id>``,
and the flat ``runs/<id>`` of every earlier release is still read -- by its
owner, and by nobody else.

The store-level tests run against both backends, because the layout is the
same path on a filesystem and in a bucket, and the fallback has to hold on
each: the local backend is where the scanner writes, the S3 one is where two
replicas meet.
"""

from __future__ import annotations

import io
import json
import re
import tarfile
import time
from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import agents as agents_service
from api.services import artifact_store
from api.services import jobs as jobs_service
from api.services import run_publisher
from api.services import run_retention
from api.services import runs as runs_service
from api.services import tenants as tenants_service
from api.services.artifact_store import keys, workspace
from api.services.jobs import get_job
from scanner.pipeline.config_schema import RuntimeConfig
from scanner.pipeline.run_context import resolve_run_paths
from tests.conftest import approve_scan_scope, make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client

RUN = "20260923T100000Z-a1b2c3"


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


@pytest.fixture(params=["local", "s3"])
def pair(request, tmp_path: Path):
    """``(writer, reader)``: one installation on a volume, or two pods on a bucket."""
    if request.param == "local":
        settings = make_settings(tmp_path)
        return settings, settings
    shared = FakeS3Client()
    return _replica(tmp_path, "pod-a", shared), _replica(tmp_path, "pod-b", shared)


def _write(settings, run, *, alive: int, marker: str | None = None) -> None:
    """A finished run at ``run`` -- a :class:`keys.RunRef`, or a flat id."""
    directory = workspace.scratch_run_dir(settings, run)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "run_meta.json").write_text(
        json.dumps({"profile": "balanced", "started_at": "2026-09-23T10:00:00Z"}),
        encoding="utf-8",
    )
    (directory / "summary.json").write_text(json.dumps({"alive_hosts": alive}), encoding="utf-8")
    if marker is not None:
        (directory / "tenant.json").write_text(json.dumps({"tenant_id": marker}), encoding="utf-8")
    workspace.publish_run(settings, run)


def _alive(run_dir: Path | None) -> int | None:
    if run_dir is None:
        return None
    return json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))["alive_hosts"]


# ------------------------------------------------------------ run id minting


def test_the_cli_mints_run_ids_the_way_the_api_does(tmp_path: Path) -> None:
    """The bare second was not unique, and the CLI kept minting it after #421."""
    runtime = RuntimeConfig(
        output_dir=str(tmp_path / "out"), state_dir=str(tmp_path / "state"), per_run_output=True
    )
    first = resolve_run_paths(runtime, run_id=None, resume=False).run_id
    second = resolve_run_paths(runtime, run_id=None, resume=False).run_id

    shape = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{6}")
    assert shape.fullmatch(first) and shape.fullmatch(second)
    assert first != second

    # One function, not two copies that agree today.
    from api.services import run_ids as api_run_ids
    from scanner.pipeline import run_ids as scanner_run_ids

    assert api_run_ids.mint is scanner_run_ids.mint
    assert api_run_ids.validate is scanner_run_ids.validate


@pytest.mark.parametrize("bad", ["../escape", "a/b", "_tenants", ".hidden", "x" * 65])
def test_the_cli_refuses_a_run_id_that_is_not_one_path_segment(tmp_path: Path, bad: str) -> None:
    runtime = RuntimeConfig(
        output_dir=str(tmp_path / "out"), state_dir=str(tmp_path / "state"), per_run_output=True
    )
    with pytest.raises(ValueError, match="run_id"):
        resolve_run_paths(runtime, run_id=bad, resume=False)
    assert not (tmp_path / "out").exists()


# --------------------------------------------------------------------- keys


def test_a_tenants_run_is_keyed_under_its_tenant() -> None:
    assert keys.run_prefix(keys.run_ref(RUN, "acme")) == f"runs/_tenants/acme/{RUN}"
    assert keys.run_artifact(keys.run_ref(RUN, "acme"), "summary.json") == (
        f"runs/_tenants/acme/{RUN}/summary.json"
    )
    # The flat layout is still addressable, for the runs that are there.
    assert keys.run_prefix(RUN) == f"runs/{RUN}"
    assert keys.run_prefix(keys.run_ref(RUN)) == f"runs/{RUN}"


def test_a_tenant_id_that_is_not_a_safe_segment_is_encoded_not_trusted() -> None:
    """Ids from before tenant validation exist, and a path is not built from them."""
    assert keys.tenant_segment("acme_eu") == "acme_eu"
    dotted = keys.tenant_segment("acme.eu")
    assert dotted.startswith("h_") and dotted != "acme_eu"
    assert keys.tenant_segment("../../etc").startswith("h_")
    # ``h_`` is the encoded namespace; a literal id there is encoded too, so
    # it can never land on another tenant's hash.
    assert keys.tenant_segment("h_abc") != "h_abc"
    with pytest.raises(ValueError):
        keys.tenant_segment("")


@pytest.mark.parametrize("bad", ["_tenants", "a/b", ".sync", ""])
def test_the_reserved_namespace_is_not_a_run_id(bad: str) -> None:
    """``runs/_tenants`` taken as one flat run is every tenant's runs at once."""
    with pytest.raises(ValueError):
        keys.run_ref(bad)
    with pytest.raises(ValueError):
        keys.run_ref(bad, "acme")


# ------------------------------------------- two tenants, one run id


def test_two_tenants_with_one_run_id_are_two_runs(pair) -> None:
    writer, reader = pair
    _write(writer, keys.run_ref(RUN, "acme"), alive=1, marker="acme")
    _write(writer, keys.run_ref(RUN, "globex"), alive=2, marker="globex")

    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="acme")) == 1
    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="globex")) == 2

    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1 and page[0].alive_hosts == 1 and page[0].tenant_id == "acme"
    page, total = runs_service.list_runs(reader, tenant_id="globex")
    assert total == 1 and page[0].alive_hosts == 2 and page[0].tenant_id == "globex"
    # The fleet-wide view sees both, each with its owner.
    page, total = runs_service.list_runs(reader)
    assert total == 2
    assert sorted((row.tenant_id, row.alive_hosts) for row in page) == [
        ("acme", 1),
        ("globex", 2),
    ]

    assert runs_service.artifact_key(reader, RUN, "summary.json", tenant_id="acme") == (
        f"runs/_tenants/acme/{RUN}/summary.json"
    )
    assert runs_service.artifact_key(reader, RUN, "summary.json", tenant_id="globex") == (
        f"runs/_tenants/globex/{RUN}/summary.json"
    )


def test_removing_one_tenants_run_leaves_the_others(pair) -> None:
    """The failure #421 papered over: one shared prefix, one delete for both."""
    writer, reader = pair
    _write(writer, keys.run_ref(RUN, "acme"), alive=1)
    _write(writer, keys.run_ref(RUN, "globex"), alive=2)

    workspace.delete_run(writer, keys.run_ref(RUN, "acme"))

    assert runs_service.get_run_dir(reader, RUN, tenant_id="acme") is None
    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="globex")) == 2


def test_a_guessed_run_id_does_not_cross_tenants(pair) -> None:
    writer, reader = pair
    _write(writer, keys.run_ref(RUN, "acme"), alive=1, marker="acme")

    assert runs_service.get_run_dir(reader, RUN, tenant_id="globex") is None
    assert runs_service.artifact_key(reader, RUN, "summary.json", tenant_id="globex") is None
    assert runs_service.list_runs(reader, tenant_id="globex") == ([], 0)
    # Nor through the flat path, by naming the namespace as if it were a run:
    # the default tenant is the one every unmarked flat run belongs to, so it
    # is the one a flat-path escape would have worked for.
    for guess in ("_tenants", "_tenants/acme/" + RUN):
        assert runs_service.get_run_dir(reader, guess, tenant_id="default") is None
        assert runs_service.artifact_key(reader, guess, "summary.json", tenant_id="default") is None


# ------------------------------------------------ runs from before #427


def test_a_run_from_before_the_upgrade_is_read_by_its_owner_only(pair) -> None:
    """The fallback: a flat run, owned by what its marker says."""
    writer, reader = pair
    _write(writer, RUN, alive=7, marker="acme")

    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="acme")) == 7
    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1 and page[0].run_id == RUN and page[0].tenant_id == "acme"
    assert runs_service.artifact_key(reader, RUN, "summary.json", tenant_id="acme") == (
        f"runs/{RUN}/summary.json"
    )

    assert runs_service.get_run_dir(reader, RUN, tenant_id="globex") is None
    assert runs_service.list_runs(reader, tenant_id="globex") == ([], 0)
    assert runs_service.artifact_key(reader, RUN, "summary.json", tenant_id="globex") is None


def test_an_unmarked_old_run_still_belongs_to_the_default_tenant(pair) -> None:
    writer, reader = pair
    _write(writer, RUN, alive=3)

    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="default")) == 3
    assert runs_service.get_run_dir(reader, RUN, tenant_id="acme") is None


def test_the_owners_copy_wins_over_an_old_one_of_the_same_id(pair) -> None:
    writer, reader = pair
    _write(writer, RUN, alive=1, marker="acme")
    _write(writer, keys.run_ref(RUN, "acme"), alive=2, marker="acme")

    assert _alive(runs_service.get_run_dir(reader, RUN, tenant_id="acme")) == 2
    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1 and page[0].alive_hosts == 2


def test_the_listing_orders_both_layouts_together(pair) -> None:
    writer, reader = pair
    _write(writer, "20260920T100000Z", alive=1, marker="acme")
    _write(writer, keys.run_ref("20260921T100000Z-000001", "acme"), alive=2)
    _write(writer, "20260922T100000Z", alive=3, marker="acme")

    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 3
    assert [row.run_id for row in page] == [
        "20260922T100000Z",
        "20260921T100000Z-000001",
        "20260920T100000Z",
    ]


# ----------------------------------------------------------------- writers


def test_a_local_scan_moves_into_its_tenants_subtree(tmp_path: Path) -> None:
    """The scanner writes the flat directory; the job knows whose it is."""
    settings = make_settings(tmp_path)
    flat = settings.output_dir / "runs" / RUN
    flat.mkdir(parents=True)
    (flat / "summary.json").write_text('{"alive_hosts": 4}', encoding="utf-8")

    workspace.adopt_local_run(settings, keys.run_ref(RUN, "acme"), flat)

    assert not flat.exists()
    owned = settings.output_dir / "runs" / "_tenants" / "acme" / RUN
    assert _alive(owned) == 4
    assert runs_service.write_run_tenant(settings, RUN, "acme")
    assert _alive(runs_service.get_run_dir(settings, RUN, tenant_id="acme")) == 4


def test_a_flat_run_that_already_names_an_owner_is_not_taken(tmp_path: Path) -> None:
    """An older run the scanner wrote into is not a fresh scan to adopt."""
    settings = make_settings(tmp_path)
    _write(settings, RUN, alive=5, marker="globex")

    workspace.adopt_local_run(
        settings, keys.run_ref(RUN, "acme"), settings.output_dir / "runs" / RUN
    )

    assert _alive(runs_service.get_run_dir(settings, RUN, tenant_id="globex")) == 5
    assert runs_service.get_run_dir(settings, RUN, tenant_id="acme") is None


def test_retention_reaches_runs_in_both_layouts(pair) -> None:
    writer, reader = pair
    old = {"profile": "balanced", "started_at": "2020-01-01T00:00:00Z"}
    for run in (RUN, keys.run_ref(RUN, "acme")):
        directory = workspace.scratch_run_dir(writer, run)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "run_meta.json").write_text(json.dumps(old), encoding="utf-8")
        workspace.publish_run(writer, run)

    stats = run_retention.sweep(writer)

    assert stats["deleted"] == 2
    assert workspace.run_refs(reader) == []


def test_a_tenants_working_copies_are_evicted_one_by_one(tmp_path: Path) -> None:
    """``_tenants`` is a directory of copies, not one very large copy."""
    shared = FakeS3Client()
    writer = _replica(tmp_path, "pod-a", shared)
    reader = _replica(tmp_path, "pod-b", shared, artifact_cache_max_mb=1)
    big = b"x" * (600 * 1024)
    refs = [keys.run_ref(f"2026092{i}T100000Z-00000{i}", "acme") for i in (1, 2, 3)]
    for ref in refs:
        directory = workspace.scratch_run_dir(writer, ref)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "blob.bin").write_bytes(big)
        workspace.publish_run(writer, ref)

    for ref in refs:
        workspace.run_dir(reader, ref)
        time.sleep(0.01)

    tenant_cache = Path(reader.artifact_cache_dir) / "_tenants" / "acme"
    cached = sorted(p.name for p in tenant_cache.iterdir() if not p.name.startswith("."))
    assert refs[-1].run_id in cached
    assert len(cached) < 3


# -------------------------------------------------- through the real ingest


def _archive(alive: int) -> bytes:
    payload = json.dumps({"alive_hosts": alive}).encode("utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="summary.json")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


@requires_postgres
def test_two_tenants_uploading_one_run_id_keep_two_runs(tmp_path: Path) -> None:
    """The probe #427 asks for, end to end: a custom run id is the tenant's to
    choose, so two tenants can pick the same one -- and before this their
    uploads landed in one directory under one key prefix."""
    settings = make_settings(
        tmp_path,
        state_dir=tmp_path / "state",
        output_dir=tmp_path / "output",
        job_execution_mode="agent",
    )
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    agents_service.configure(settings)
    jobs_service.reset_for_tests(settings)
    run_publisher.reset_for_tests(settings)

    for tenant, alive in (("ten_acme", 1), ("ten_globex", 2)):
        tenants_service.create_tenant(tenant_id=tenant, name=tenant)
        approve_scan_scope(settings, tenant_id=tenant)
        agents_service.register_agent(agent_id=f"agent-{tenant}", tenant_id=tenant)
        job = jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", tenant_id=tenant, run_id=RUN),
            username="admin",
        )
        claim = jobs_service.claim_job(settings, f"agent-{tenant}")
        assert claim is not None and claim.run_id == RUN
        jobs_service.complete_job(
            settings,
            job.job_id,
            agent_id=f"agent-{tenant}",
            exit_code=0,
            run_id=RUN,
            archive_bytes=_archive(alive),
            attempt=claim.attempt,
            idempotency_key=f"upload-{tenant}",
            tenant_id=tenant,
        )
        assert get_job(settings, job.job_id).status == "succeeded"

    assert _alive(runs_service.get_run_dir(settings, RUN, tenant_id="ten_acme")) == 1
    assert _alive(runs_service.get_run_dir(settings, RUN, tenant_id="ten_globex")) == 2
    for tenant in ("ten_acme", "ten_globex"):
        owned = settings.output_dir / "runs" / "_tenants" / tenant / RUN
        marker = json.loads((owned / "tenant.json").read_text(encoding="utf-8"))
        assert marker["tenant_id"] == tenant
    assert not (settings.output_dir / "runs" / RUN).exists()


# ------------------------------------------------ review of the first cut


def test_the_flat_single_run_layout_does_not_expose_the_runs_beneath_it(tmp_path: Path) -> None:
    """``default`` is ``OCTO_OUTPUT_DIR`` itself, which holds ``runs/`` -- every
    tenant's subtree included. Owned by the default tenant for want of a marker,
    it was a window onto all of them."""
    settings = make_settings(tmp_path)
    _write(settings, keys.run_ref(RUN, "acme"), alive=1, marker="acme")
    (settings.output_dir / "summary.json").write_text('{"alive_hosts": 9}', encoding="utf-8")

    foreign = f"runs/_tenants/acme/{RUN}/summary.json"
    assert runs_service.get_run_dir(settings, "default", tenant_id="default") is None
    assert runs_service.resolve_artifact(settings, "default", foreign, tenant_id="default") is None
    assert runs_service.resolve_artifact(settings, "default", foreign) is None


def test_the_flat_single_run_layout_still_reads_when_it_is_all_there_is(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    (settings.output_dir / "summary.json").write_text('{"alive_hosts": 9}', encoding="utf-8")
    assert _alive(runs_service.get_run_dir(settings, "default", tenant_id="default")) == 9


def test_a_run_id_scanned_twice_by_one_tenant_stays_that_tenants(tmp_path: Path) -> None:
    """A custom run id reused: the scanner writes the flat directory again, and
    the second scan must land in the tenant's run, not stay flat and unmarked
    -- which reads as the default tenant's."""
    settings = make_settings(tmp_path)
    flat = settings.output_dir / "runs" / RUN
    for name in ("first.json", "second.json"):
        flat.mkdir(parents=True, exist_ok=True)
        (flat / name).write_text("{}", encoding="utf-8")
        workspace.adopt_local_run(settings, keys.run_ref(RUN, "acme"), flat)
        assert runs_service.write_run_tenant(settings, RUN, "acme")

    assert not flat.exists()
    owned = runs_service.get_run_dir(settings, RUN, tenant_id="acme")
    assert (owned / "first.json").is_file() and (owned / "second.json").is_file()
    assert runs_service.get_run_dir(settings, RUN, tenant_id="default") is None


def test_an_old_run_id_with_a_dot_still_reads(pair) -> None:
    """The flat layout never validated ``--run-id``; such a run stays readable."""
    writer, reader = pair
    odd = "nightly.2026-09-01"
    _write(writer, odd, alive=6, marker="acme")

    assert _alive(runs_service.get_run_dir(reader, odd, tenant_id="acme")) == 6
    assert runs_service.artifact_key(reader, odd, "summary.json", tenant_id="acme") == (
        f"runs/{odd}/summary.json"
    )
    page, total = runs_service.list_runs(reader, tenant_id="acme")
    assert total == 1 and page[0].alive_hosts == 6
    assert runs_service.get_run_dir(reader, odd, tenant_id="globex") is None


def test_a_publication_an_older_replica_promoted_flat_counts_as_stored(tmp_path: Path) -> None:
    """In flight across the upgrade: the old code put the tree at ``runs/<id>``
    and died before the bus. The retry must not call that tree gone."""
    import types
    from datetime import datetime

    settings = make_settings(tmp_path)
    _write(settings, RUN, alive=1, marker="acme")
    publication = types.SimpleNamespace(
        run_id=RUN, tenant_id="acme", stored_at=datetime(2026, 9, 23)
    )
    assert run_publisher._tree_is_stored(settings, publication)  # noqa: SLF001
    # A flat run of another tenant under the same id is not this one's tree.
    other = types.SimpleNamespace(run_id=RUN, tenant_id="globex", stored_at=publication.stored_at)
    assert not run_publisher._tree_is_stored(settings, other)  # noqa: SLF001


def test_an_older_replica_does_not_read_the_namespace_as_a_default_run(pair) -> None:
    """During a rolling update the old code lists ``runs/_tenants`` as a flat
    run, and reads it as the default tenant's unless something says otherwise."""
    writer, reader = pair
    _write(writer, keys.run_ref(RUN, "acme"), alive=1, marker="acme")

    store = artifact_store.get_store(reader)
    raw = store.get_bytes(f"runs/{keys.TENANT_RUNS}/tenant.json")
    # What the pre-#427 ``run_tenant_of`` makes of it.
    owner = runs_service._tenant_from_marker(json.loads(raw))  # noqa: SLF001
    assert owner != "default"
    assert not tenants_service._TENANT_ID_RE.match(owner)  # noqa: SLF001
    # And the new code does not take the guard for a tenant or a run.
    assert [ref.tenant for ref in workspace.run_refs(reader)] == ["acme"]


def test_the_flat_single_run_layout_does_not_serve_other_families(tmp_path: Path) -> None:
    """``reports/<tenant>/…`` also lives in the output directory."""
    settings = make_settings(tmp_path)
    reports = settings.output_dir / "reports" / "acme"
    reports.mkdir(parents=True)
    (reports / "r1.pdf").write_bytes(b"%PDF")
    (settings.output_dir / "summary.json").write_text('{"alive_hosts": 9}', encoding="utf-8")

    assert _alive(runs_service.get_run_dir(settings, "default", tenant_id="default")) == 9
    assert (
        runs_service.resolve_artifact(settings, "default", "reports/acme/r1.pdf", tenant_id="default")
        is None
    )
    detail = runs_service.get_run_detail(settings, "default", tenant_id="default")
    assert not any(name.startswith("reports/") for name in detail.artifacts)


def test_a_merge_that_fails_leaves_the_scan_marked_not_default(tmp_path: Path, monkeypatch) -> None:
    """The second scan under a reused run id could not be merged: it stays
    flat, and must not stay flat *unmarked* -- that is the default tenant's."""
    import shutil

    settings = make_settings(tmp_path)
    _write(settings, keys.run_ref(RUN, "acme"), alive=1, marker="acme")
    flat = settings.output_dir / "runs" / RUN
    flat.mkdir(parents=True)
    (flat / "summary.json").write_text('{"alive_hosts": 2}', encoding="utf-8")

    def _fail(*_a, **_k):
        raise shutil.Error([("a", "b", "disk full")])

    monkeypatch.setattr(shutil, "copytree", _fail)
    # Loud: the caller records it on the job.
    with pytest.raises(artifact_store.ArtifactStoreError, match="left at"):
        workspace.adopt_local_run(settings, keys.run_ref(RUN, "acme"), flat)

    assert flat.is_dir()
    assert runs_service.get_run_dir(settings, RUN, tenant_id="default") is None
    assert runs_service.read_run_tenant(flat) == "acme"


@pytest.mark.parametrize("rel", ["Reports/acme/r1.pdf", "RUNS/_tenants/acme/x", "reports/a"])
def test_other_families_are_refused_whatever_their_case(rel: str) -> None:
    """A case-insensitive filesystem opens ``Reports/`` as ``reports/``."""
    assert runs_service._outside_flat_run("default", Path(rel))  # noqa: SLF001
    assert not runs_service._outside_flat_run(RUN, Path(rel))  # noqa: SLF001
