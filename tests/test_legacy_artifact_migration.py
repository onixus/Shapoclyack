from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.services import artifact_store
from api.services import legacy_artifact_migration as migration
from api.services import runs as runs_service
from api.services.artifact_store import keys, workspace
from api.settings import Settings
from tests.conftest import make_settings, requires_postgres
from tests.fake_s3 import FakeS3Client

RUN = "20260923T100000Z-a1b2c3"


@pytest.fixture(autouse=True)
def _clean_store_cache():
    artifact_store.reset_cache()
    workspace.reset_marker_cache()
    yield
    artifact_store.reset_cache()
    workspace.reset_marker_cache()


@pytest.fixture(params=["local", "s3"])
def settings(request, tmp_path: Path, monkeypatch) -> Settings:
    monkeypatch.setattr(migration, "_tenant_ids", lambda _settings: {"default", "acme"})
    value = Settings(
        env="dev",
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=f"sqlite:///{tmp_path / 'migration.db'}",
        artifact_cache_ttl_seconds=0,
    )
    if request.param == "s3":
        value.artifact_backend = "s3"
        value.artifact_s3_bucket = "artifacts"
        value.artifact_cache_dir = str(tmp_path / "cache")
        artifact_store.get_store(value)._client = FakeS3Client()  # noqa: SLF001
    return value


def _write_flat(settings: Settings, run_id: str = RUN, marker=...):
    ref = keys.run_ref(run_id)
    directory = workspace.scratch_run_dir(settings, ref)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text('{"alive_hosts": 7}', encoding="utf-8")
    if marker is not ... and marker is not None:
        (directory / "tenant.json").write_text(marker, encoding="utf-8")
    workspace.publish_run(settings, ref)
    return ref


def test_dry_run_validates_owner_without_moving_anything(settings):
    ref = _write_flat(settings, marker=json.dumps({"tenant_id": "acme"}))
    store = artifact_store.get_store(settings)

    manifest = migration.build_plan(settings)

    assert migration.summary(manifest)["runs"] == {"pending": 1}
    assert store.exists(keys.run_artifact(ref, "summary.json"))
    assert not store.exists(keys.run_artifact(keys.run_ref(RUN, "acme"), "summary.json"))
    assert not list(store.list_prefix(migration.BACKUP_ROOT))


@pytest.mark.parametrize("marker", [None, "{broken", "{}", '{"tenant_id": 42}'])
def test_missing_or_damaged_owner_is_refused_and_never_default(settings, marker):
    ref = _write_flat(settings, marker=marker)

    manifest = migration.build_plan(settings)

    assert manifest["runs"][0]["status"] == "refused"
    assert not store_objects(settings, keys.run_prefix(keys.run_ref(RUN, "acme")))
    assert runs_service.get_run_dir(settings, RUN, tenant_id="default") is None
    assert runs_service.get_run_dir(settings, RUN, tenant_id="acme") is None
    assert runs_service.list_runs(settings, tenant_id="default") == ([], 0)
    with pytest.raises(migration.MigrationError, match="owner metadata"):
        migration.apply_migration(settings, manifest)
    assert store_objects(settings, keys.run_prefix(ref))


def store_objects(settings: Settings, prefix: str) -> list[str]:
    return [entry.key for entry in artifact_store.get_store(settings).list_prefix(prefix)]


def test_marker_naming_an_unknown_tenant_is_refused(settings):
    _write_flat(settings, marker='{"tenant_id": "removed-tenant"}')
    manifest = migration.build_plan(settings)
    assert manifest["runs"][0]["status"] == "refused"
    assert "does not exist" in manifest["runs"][0]["error"]


def test_apply_is_repeatable_and_preserves_run_links(settings, tmp_path: Path):
    ref = _write_flat(settings, marker='{"tenant_id": "acme", "surface": "external"}')
    manifest_path = tmp_path / "migration.json"
    manifest = migration.build_plan(settings)
    migration.save_manifest(manifest, manifest_path)

    migration.apply_migration(settings, manifest, manifest_path=manifest_path)
    migration.apply_migration(settings, migration.load_manifest(manifest_path))

    assert not store_objects(settings, keys.run_prefix(ref))
    owned = keys.run_ref(RUN, "acme")
    assert runs_service.get_run_dir(settings, RUN, tenant_id="acme") is not None
    assert runs_service.get_run_dir(settings, RUN, tenant_id="default") is None
    assert runs_service.artifact_key(settings, RUN, "summary.json", tenant_id="acme") == (
        keys.run_artifact(owned, "summary.json")
    )
    assert len(store_objects(settings, migration.BACKUP_ROOT)) == 2
    assert migration.summary(manifest)["runs"] == {"migrated": 1}


def test_rollback_restores_the_original_bytes(settings, tmp_path: Path):
    ref = _write_flat(settings, marker='{"tenant_id": "acme"}')
    store = artifact_store.get_store(settings)
    original = store.get_bytes(keys.run_artifact(ref, "summary.json"))
    manifest = migration.build_plan(settings)
    migration.apply_migration(settings, manifest)

    migration.rollback_migration(settings, manifest)

    assert store.get_bytes(keys.run_artifact(ref, "summary.json")) == original
    assert not store_objects(settings, keys.run_prefix(keys.run_ref(RUN, "acme")))
    assert len(store_objects(settings, migration.BACKUP_ROOT)) == 2


def test_explicit_assignment_recovers_an_unmarked_run(settings):
    _write_flat(settings, marker=None)
    manifest = migration.build_plan(settings, assignments={RUN: "acme"})
    migration.apply_migration(settings, manifest)

    owned = keys.run_ref(RUN, "acme")
    marker = json.loads(
        artifact_store.get_store(settings).get_bytes(keys.run_artifact(owned, "tenant.json"))
    )
    assert marker["tenant_id"] == "acme"
    assert runs_service.get_run_dir(settings, RUN, tenant_id="acme") is not None


def test_a_destination_conflict_never_deletes_the_flat_source(settings):
    ref = _write_flat(settings, marker='{"tenant_id": "acme"}')
    store = artifact_store.get_store(settings)
    destination = keys.run_artifact(keys.run_ref(RUN, "acme"), "summary.json")
    store.put_bytes(destination, b'{"alive_hosts": 999}')

    manifest = migration.build_plan(settings)

    assert manifest["runs"][0]["status"] == "conflict"
    with pytest.raises(migration.MigrationError, match="not safe"):
        migration.apply_migration(settings, manifest)
    assert store.exists(keys.run_artifact(ref, "summary.json"))
    assert store.get_bytes(destination) == b'{"alive_hosts": 999}'


def test_an_old_id_that_cannot_be_tenant_scoped_stays_readable_in_place(settings):
    ref = _write_flat(settings, "nightly.2026-09-01", marker='{"tenant_id": "acme"}')
    manifest = migration.build_plan(settings)
    assert manifest["runs"][0]["status"] == "unsupported"
    assert runs_service.get_run_dir(
        settings, "nightly.2026-09-01", tenant_id="acme"
    ) is not None
    assert store_objects(settings, keys.run_prefix(ref))


@requires_postgres
def test_owner_is_checked_against_the_real_tenant_table(tmp_path: Path):
    settings = make_settings(tmp_path)
    _write_flat(settings, marker='{"tenant_id": "default"}')

    manifest = migration.build_plan(settings)

    assert manifest["runs"][0]["status"] == "pending"
    migration.apply_migration(settings, manifest)
    assert runs_service.get_run_dir(settings, RUN, tenant_id="default") is not None
