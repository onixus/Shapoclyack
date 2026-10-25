"""Full workstation bundle trust and archive boundaries with tiny payloads."""
import hashlib
from datetime import UTC, datetime
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/operator-offline-bundle.py"


@pytest.fixture
def module():
    spec = importlib.util.spec_from_file_location("operator_offline_package", SCRIPT)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def _tar(path, files):
    with tarfile.open(path, "w:") as archive:
        for name, data in files.items():
            item = tarfile.TarInfo(name)
            item.size = len(data)
            archive.addfile(item, io.BytesIO(data))


def _manifest(root, value):
    raw = json.dumps(value, sort_keys=True).encode()
    (root / "manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def _native_feeds(module, root, *, updated="2026-10-25", origin="fetch"):
    root.mkdir()
    metadata = {}
    for name, (relative, _, required) in module.FEED_SPECS.items():
        if not required:
            continue
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"source": "fixture-source", "updated": updated, "entries": {"CVE-2026-1234": {}}}))
        metadata[name] = {"origin": origin}
    (root / "enrichment-manifest.json").write_text(json.dumps({"datasets": metadata}))
    return root


@pytest.fixture
def bundle(module, tmp_path):
    root = tmp_path / "bundle"
    root.mkdir()
    _tar(root / "source.tar", dict.fromkeys(module.SOURCE_FILES, b"fixture"))
    _tar(root / "ui.tar", {"operator.html": b'<script src="/_next/example.js"></script>', "_next/example.js": b"fixture"})
    _tar(root / "images.tar", {"manifest.json": b"[]"})
    for name, content in {"model.gguf": b"GGUFmodel-fixture", "embedding.gguf": b"GGUFembedding-fixture",
                          "license-000.txt": b"license fixture", "sbom.spdx.json": b'{"spdxVersion":"SPDX-2.3"}',
                          "image-sbom.json": b'{"spdxVersion":"SPDX-2.3"}'}.items():
        (root / name).write_bytes(content)
    native = _native_feeds(module, tmp_path / "local-feeds")
    staged = tmp_path / "staged-feeds"
    module.stage_feeds(native, staged, root / "feed-inventory.json")
    module.tree_archive(staged, root / "feeds.tar")
    (root / "image-sbom.json").write_text(json.dumps({"schema_version": 1, "images": {
        "sha256:" + char * 64: {"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}
        for char in "def"}}))
    artifacts = [module.artifact(root, role, name) for role, name in module.CORE.items()]
    artifacts.append(module.artifact(root, "license", "license-000.txt"))
    value = {"schema_version": 1, "kind": "shapoclyack-operator-mac-offline", "platform": "linux/arm64",
        "source_revision": "a" * 40, "ui_source_revision": "a" * 40,
        "runtime_reference": "ghcr.io/ggml-org/llama.cpp:server@sha256:" + "b" * 64, "runtime_revision": "c" * 40,
        "image_ids": {name: "sha256:" + char * 64 for name, char in (("runtime", "d"), ("application", "e"), ("postgres", "f"))},
        "model": "Qwen3.5-9B-Q4_K_M", "model_revision": "1" * 40, "embedding": "Qwen3-Embedding-0.6B-Q8_0",
        "embedding_revision": "2" * 40, "context_tokens": 8192, "parallel": 1, "artifacts": artifacts,
        "created_at": "2026-10-25T00:00:00Z", "feed_status": "local_snapshot_included_freshness_and_coverage_not_guaranteed", "sbom_scope": "bundle_files"}
    return root, value, _manifest(root, value)


@pytest.mark.parametrize("mutation", ["wrong_image", "empty_packages", "file_bom"])
def test_image_sbom_requires_all_exact_image_package_inventories(module, bundle, mutation):
    root, value, _ = bundle
    document = json.loads((root / "image-sbom.json").read_text())
    key = next(iter(document["images"]))
    if mutation == "wrong_image":
        document["images"]["sha256:" + "0" * 64] = document["images"].pop(key)
    elif mutation == "empty_packages":
        document["images"][key]["packages"] = []
    else:
        document = {"spdxVersion": "SPDX-2.3", "files": []}
    (root / "image-sbom.json").write_text(json.dumps(document))
    value["artifacts"] = [module.artifact(root, a["role"], a["path"]) for a in value["artifacts"]]
    with pytest.raises(module.BundleError, match="bundle_image_sbom_invalid"):
        module.verify_bundle(root, _manifest(root, value))


def test_verify_has_no_docker_or_network_side_effect(module, bundle, monkeypatch):
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("executed during verification"))
    root, value, trusted = bundle
    assert module.verify_bundle(root, trusted) == value


@pytest.mark.parametrize("mutation", ["absent", "empty", "missing_required", "empty_required", "empty_entries", "oversized_header", "symlink"])
def test_full_feed_snapshot_rejects_absent_empty_or_unbounded_native_inputs(module, tmp_path, mutation):
    source = tmp_path / "feeds"
    if mutation == "empty":
        source.mkdir()
    elif mutation != "absent":
        _native_feeds(module, source)
        path = source / "epss/epss-overlay.json"
        if mutation == "missing_required":
            path.unlink()
        elif mutation == "empty_required":
            path.write_bytes(b"")
        elif mutation == "empty_entries":
            path.write_text(json.dumps({"source": "fixture", "updated": None, "entries": {}}))
        elif mutation == "oversized_header":
            path.write_text(json.dumps({"source": "fixture", "notes": "x" * module.FEED_HEADER_BYTES, "entries": {"one": 1}}))
        else:
            path.unlink()
            path.symlink_to(source / "kev/kev-overlay.json")
    with pytest.raises(module.BundleError):
        module.stage_feeds(source, tmp_path / "staged", tmp_path / "inventory.json")


@pytest.mark.parametrize("stamp,expected", [(None, "unknown"), ("invalid", "unknown"),
    ("2026-01-01", "stale"), ("2030-01-01", "unknown"), ("2026-10-24", "fresh_by_feed_date_only")])
def test_feed_age_uses_data_stamp_never_export_time(module, stamp, expected):
    assert module.feed_freshness(stamp, datetime(2026, 10, 25, tzinfo=UTC)) == expected


def test_large_feed_header_inspection_does_not_load_full_corpus(module, tmp_path, monkeypatch):
    path = tmp_path / "large.json"
    path.write_text(json.dumps({"source": "vendor-seed", "updated": "2026-10-24",
        "entries": {"CVE-2026-1234": {"padding": "x" * 1024}}}))
    monkeypatch.setattr(module, "FEED_PARSE_BYTES", 128)
    original = Path.read_bytes

    def bounded_read(self):
        if self == path:
            pytest.fail("Loaded full optional corpus during header inspection")
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", bounded_read)
    record = module.inspect_feed(path, minimum=1, origin="fetch", now=datetime(2026, 10, 25, tzinfo=UTC))
    assert record["entries"] is None and record["entry_count_checked"] is False
    assert record["freshness_at_snapshot"] == "fresh_by_feed_date_only"
    assert record["coverage"] == "seed_or_unknown" and record["usable"] is False


def test_small_native_feed_metadata_after_entries_is_checked_from_bounded_full_payload(module, tmp_path):
    path = tmp_path / "sorted.json"
    path.write_text(json.dumps({"entries": {"one": {}}, "source": "vendor-seed", "updated": "2026-09-15"}, sort_keys=True))
    record = module.inspect_feed(path, minimum=1, origin="seed", now=datetime(2026, 10, 25, tzinfo=UTC))
    assert record["updated"] == "2026-09-15" and record["freshness_at_snapshot"] == "stale"
    assert record["entry_count_checked"] is True and record["coverage"] == "seed_or_unknown"


def test_full_export_cli_requires_explicit_local_feed_tree_before_any_operation(module, monkeypatch):
    arguments = ["operator-offline-bundle.py", "export", "--destination", "/unused/bundle", "--ui-source-revision", "a" * 40,
        "--ui", "/unused/ui", "--model", "/unused/model", "--embedding", "/unused/embedding",
        "--model-revision", "a" * 40, "--embedding-revision", "b" * 40,
        "--model-sha256", "a" * 64, "--embedding-sha256", "b" * 64,
        "--runtime-image", "ghcr.io/ggml-org/llama.cpp:server@sha256:" + "c" * 64,
        "--app-image", "sha256:" + "d" * 64, "--postgres-image", "sha256:" + "e" * 64,
        "--image-sbom", "/unused/sbom", "--license", "/unused/license"]
    monkeypatch.setattr(sys, "argv", arguments)
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("Missing feeds reached runtime operation"))
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 2


def test_snapshot_preserves_seed_unknown_data_and_never_mutates_input_manifest(module, tmp_path):
    source = _native_feeds(module, tmp_path / "feeds", updated=None, origin="seed")
    before = (source / "enrichment-manifest.json").read_bytes()
    target, inventory = tmp_path / "staged", tmp_path / "inventory.json"
    value = module.stage_feeds(source, target, inventory)
    assert (source / "enrichment-manifest.json").read_bytes() == before
    assert value["coverage_complete"] is False
    assert value["datasets"]["epss"]["updated"] is None
    assert value["datasets"]["epss"]["freshness_at_snapshot"] == "unknown"
    assert value["datasets"]["epss"]["coverage"] == "seed_or_unknown"
    assert value["datasets"]["advisories_debian"]["coverage"] == "missing"
    regenerated = json.loads((target / "enrichment-manifest.json").read_text())
    assert regenerated["datasets"]["epss"]["path"] == "/app/scanner/data/epss/epss-overlay.json"


def test_failed_refresh_origin_survives_another_offline_snapshot(module, tmp_path):
    source = _native_feeds(module, tmp_path / "feeds", origin="bundle")
    manifest_path = source / "enrichment-manifest.json"
    metadata = json.loads(manifest_path.read_text())
    metadata["datasets"]["epss"]["source_origin"] = "stale"
    manifest_path.write_text(json.dumps(metadata))
    target, inventory = tmp_path / "staged", tmp_path / "inventory.json"
    value = module.stage_feeds(source, target, inventory)
    assert value["datasets"]["epss"]["origin"] == "bundle"
    assert value["datasets"]["epss"]["source_origin"] == "stale"
    archive = tmp_path / "feeds.tar"
    module.tree_archive(target, archive)
    assert module.verify_feeds(archive, inventory)["datasets"]["epss"]["source_origin"] == "stale"


def test_native_feed_writer_lock_and_install_history_are_not_published_as_data(module, tmp_path):
    source = _native_feeds(module, tmp_path / "feeds")
    for name in module.FEED_ADMIN_FILES:
        (source / name).write_text("" if name.startswith(".") else "private installation metadata")
    value = module.stage_feeds(source, tmp_path / "staged", tmp_path / "inventory.json")
    assert not module.FEED_ADMIN_FILES.intersection(item["path"] for item in value["files"])
    assert all((source / name).exists() for name in module.FEED_ADMIN_FILES)


def test_optional_binary_feed_is_byte_verified_without_inventing_validity_or_freshness(module, tmp_path):
    source = _native_feeds(module, tmp_path / "feeds")
    path = source / "geoip/geoip.mmdb"
    path.parent.mkdir()
    path.write_text(json.dumps({"source": "not-a-real-mmdb", "updated": "2026-10-25", "entries": {"one": 1}}))
    inventory, target, archive = tmp_path / "inventory.json", tmp_path / "staged", tmp_path / "feeds.tar"
    value = module.stage_feeds(source, target, inventory)
    assert value["datasets"]["geoip"]["usable"] is False
    assert value["datasets"]["geoip"]["freshness_at_snapshot"] == "unknown"
    assert value["datasets"]["geoip"]["coverage"] == "unknown"
    module.tree_archive(target, archive)
    assert module.verify_feeds(archive, inventory)["datasets"]["geoip"]["coverage"] == "unknown"


@pytest.mark.parametrize("mutation", ["file_hash", "date_laundering", "coverage_laundering", "complete_claim", "nondict_metadata", "unknown_metadata"])
def test_feed_inventory_cannot_launder_bytes_dates_or_coverage_before_docker(module, bundle, tmp_path, monkeypatch, mutation):
    root, value, _ = bundle
    inventory = json.loads((root / "feed-inventory.json").read_text())
    if mutation == "file_hash":
        inventory["files"][0]["sha256"] = "0" * 64
    elif mutation == "date_laundering":
        inventory["datasets"]["epss"]["updated"] = "2030-01-01"
    elif mutation == "coverage_laundering":
        inventory["datasets"]["epss"].update(usable=True, entries=999999, coverage="not_assessed")
    elif mutation == "nondict_metadata":
        inventory["datasets"]["epss"] = []
    elif mutation == "unknown_metadata":
        inventory["datasets"]["epss"]["private_secret"] = "must-not-cross"
    else:
        inventory["coverage_complete"] = True
    (root / "feed-inventory.json").chmod(0o644)
    (root / "feed-inventory.json").write_text(json.dumps(inventory))
    value["artifacts"] = [module.artifact(root, item["role"], item["path"]) for item in value["artifacts"]]
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("invalid feed reached Docker"))
    with pytest.raises(module.BundleError, match="bundle_feed_inventory_invalid"):
        module.import_bundle(root, _manifest(root, value), tmp_path / "installation")
    assert not (tmp_path / "installation").exists()


@pytest.mark.parametrize("mutation", ["manifest", "model", "extra_file", "symlink", "duplicate", "bool_size",
    "unknown_field", "missing_license", "missing_image_sbom", "missing_feeds", "mutable_image", "foreign_profile"])
def test_invalid_payload_never_reaches_docker_load(module, bundle, tmp_path, monkeypatch, mutation):
    root, value, trusted = bundle
    if mutation == "manifest":
        trusted = "0" * 64
    elif mutation == "model":
        (root / "model.gguf").write_bytes(b"X" * (root / "model.gguf").stat().st_size)
    elif mutation == "extra_file":
        (root / "unlisted.env").write_text("secret fixture")
    elif mutation == "symlink":
        (root / "model.gguf").unlink()
        (root / "model.gguf").symlink_to(root / "embedding.gguf")
    else:
        if mutation == "duplicate":
            value["artifacts"].append(value["artifacts"][0])
        elif mutation == "bool_size":
            value["artifacts"][0]["size"] = True
        elif mutation == "unknown_field":
            value["shell"] = "arbitrary"
        elif mutation == "missing_license":
            value["artifacts"] = [a for a in value["artifacts"] if a["role"] != "license"]
        elif mutation == "missing_image_sbom":
            value["artifacts"] = [a for a in value["artifacts"] if a["role"] != "image_sbom"]
        elif mutation == "missing_feeds":
            value["artifacts"] = [a for a in value["artifacts"] if a["role"] != "feeds"]
        elif mutation == "mutable_image":
            value["image_ids"]["runtime"] = "runtime:latest"
        else:
            value["platform"] = "linux/amd64"
        trusted = _manifest(root, value)
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("unverified Docker command"))
    with pytest.raises((module.BundleError, OSError)):
        module.import_bundle(root, trusted, tmp_path / "installation")
    assert not (tmp_path / "installation").exists()


@pytest.mark.parametrize("kind", ["absolute", "parent", "backslash", "symlink", "hardlink", "device", "fifo", "oversized", "duplicate", "file_parent"])
def test_trusted_digest_does_not_authorize_unsafe_extraction(module, bundle, tmp_path, monkeypatch, kind):
    root, value, _ = bundle
    with tarfile.open(root / "source.tar", "w:") as archive:
        item = tarfile.TarInfo({"absolute": "/outside", "parent": "../outside", "backslash": "dir\\outside"}.get(kind, "unsafe"))
        if kind in {"symlink", "hardlink", "device", "fifo"}:
            item.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                         "device": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}[kind]
            item.linkname = "../outside"
        if kind == "oversized":
            item.size = module.MAX_TREE + 1
        archive.addfile(item)
        if kind == "duplicate":
            archive.addfile(item)
        if kind == "file_parent":
            archive.addfile(tarfile.TarInfo("unsafe/child"))
    for i, item in enumerate(value["artifacts"]):
        if item["role"] == "source":
            value["artifacts"][i] = module.artifact(root, "source", "source.tar")
    trusted = _manifest(root, value)
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("unsafe payload reached Docker"))
    with pytest.raises(module.BundleError):
        module.import_bundle(root, trusted, tmp_path / "installation")
    assert not (tmp_path / "outside").exists()


def test_import_without_docker_materializes_source_ui_models_and_refuses_overwrite(module, bundle, tmp_path, monkeypatch):
    root, _, trusted = bundle
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("unexpected Docker invocation"))
    target = tmp_path / "installation"
    result = module.import_bundle(root, trusted, target, load=False)
    assert result["images_loaded"] is False and result["started"] is False
    assert (target / "source/api/app.py").read_bytes() == b"fixture"
    assert (target / "ui/operator.html").is_file()
    assert module.verify_bundle(target / "payloads", trusted)["source_revision"] == "a" * 40
    with pytest.raises(module.BundleError, match="destination_exists"):
        module.import_bundle(root, trusted, target, load=False)
    assert (target / "ui/operator.html").is_file()


def test_copy_mutation_is_caught_before_docker_load(module, bundle, tmp_path, monkeypatch):
    root, _, trusted = bundle
    original = module.copy_checked

    def changed(source, target, expected=None):
        result = original(source, target, expected)
        if target.name == "images.tar":
            target.chmod(0o644)
            target.write_bytes(b"X" * target.stat().st_size)
        return result

    monkeypatch.setattr(module, "copy_checked", changed)
    monkeypatch.setattr(module, "run", lambda *a, **k: pytest.fail("changed copy reached Docker"))
    with pytest.raises(module.BundleError, match="artifact_mismatch"):
        module.import_bundle(root, trusted, tmp_path / "installation")
    assert not (tmp_path / "installation").exists()


def test_generated_startup_is_isolated_offline_nonroot_and_has_no_downloads(module, bundle, tmp_path):
    _, value, _ = bundle
    root = tmp_path / "installation"
    root.mkdir()
    project, compose_file, credentials = module.deployment(root, value)
    compose = json.loads(compose_file.read_text())
    assert project.startswith("shapo-offline-")
    assert compose["networks"]["isolated"]["internal"] is True
    for name in ("inference", "embeddings"):
        service = compose["services"][name]
        assert service["networks"].keys() == {"isolated"}
        assert service["user"] == "65532:65532" and service["read_only"]
        assert service["dns"] == ["127.0.0.1"]
        assert "ports" not in service and "build" not in service
        assert "--offline" in service["command"] and "--no-agent" in service["command"]
        assert service["pull_policy"] == "never"
    assert compose["services"]["gateway"]["ports"] == ["127.0.0.1:8085:8080"]
    assert compose["services"]["gateway"]["environment"] == {"OCTO_OPERATOR_CONSOLE_PORT": "8085"}
    assert all(service["image"].startswith("sha256:") for service in compose["services"].values())
    env = (root / ".offline/app.env").read_text()
    assert "OCTO_OPERATOR_ALLOW_EXTERNAL=false" in env
    assert "OCTO_OPERATOR_EMBEDDINGS_ENABLED=true" in env
    assert "OCTO_ALLOW_SCAN_START=false" in env
    assert credentials["password"] not in compose_file.read_text()
    assert (root / ".offline/credentials.json").stat().st_mode & 0o777 == 0o600


@pytest.fixture
def running_deployment(module, bundle, tmp_path, monkeypatch):
    import copy

    source, manifest, _ = bundle
    root = tmp_path / "actual-installation"
    root.mkdir()
    (root / "payloads").mkdir()
    for name in ("model.gguf", "embedding.gguf"):
        module.copy_checked(source / name, root / "payloads" / name)
    project, path, _ = module.deployment(root, manifest)
    compose = json.loads(path.read_text())
    image = {"Config": {"Labels": {"org.opencontainers.image.revision": manifest["runtime_revision"]}, "Entrypoint": ["/server"]}}
    containers = {}
    for role, char, filename in (("inference", "a", "model.gguf"), ("embeddings", "b", "embedding.gguf")):
        containers[char * 64] = {"Image": manifest["image_ids"]["runtime"],
            "Config": {"Image": manifest["image_ids"]["runtime"], "User": "65532:65532", "Entrypoint": ["/server"],
                "Cmd": copy.deepcopy(compose["services"][role]["command"])},
            "State": {"Status": "running", "Health": {"Status": "healthy"}},
            "HostConfig": {"ReadonlyRootfs": True, "PortBindings": {}, "CapDrop": ["ALL"], "Privileged": False},
            "NetworkSettings": {"Networks": {"owned-network": {}}},
            "Mounts": [{"Type": "bind", "Source": str(root / "payloads" / filename),
                "Destination": "/models/" + filename, "RW": False}]}
    network = {"Internal": True, "Labels": {"com.docker.compose.project": project}}

    def run(args, **kwargs):
        if args[:3] == ["docker", "compose", "-p"]:
            return (("a" if args[-1] == "inference" else "b") * 64).encode()
        if args[:3] == ["docker", "container", "inspect"]:
            return json.dumps([containers[args[-1]]]).encode()
        if args[:3] == ["docker", "network", "inspect"]:
            return json.dumps([network]).encode()
        pytest.fail("Unexpected operation during startup attestation: " + str(args))

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "image_info", lambda _: image)
    return root, manifest, project, path, containers, network, image


def test_runtime_attestation_binds_actual_containers_and_imported_immutable_payloads(module, running_deployment):
    root, manifest, project, path, *_ = running_deployment
    record = module.attest_deployment(root, manifest, project, path)
    raw = (root / ".offline/verification.json").read_bytes()
    assert record["model_sha256"] == next(a["sha256"] for a in manifest["artifacts"] if a["role"] == "model")
    assert record["runtime_revision"] == manifest["runtime_revision"]
    assert record["application_source_revision"] == manifest["source_revision"]
    assert (root / ".offline/verification.json").stat().st_mode & 0o777 == 0o444
    assert "OCTO_OPERATOR_RUNTIME_MANIFEST_SHA256=" + hashlib.sha256(raw).hexdigest() in (root / ".offline/app.env").read_text()
    compose = json.loads(path.read_text())
    for service in ("api", "worker"):
        assert str(root / ".offline/verification.json") + ":/operator-runtime.json:ro" in compose["services"][service]["volumes"]
    assert not any("operator-runtime.json" in v for v in compose["services"]["migrate"]["volumes"])


@pytest.mark.parametrize("mutation", ["image", "revision", "stopped", "unhealthy", "root", "writable_root",
    "ports", "arguments", "entrypoint", "privileged", "capabilities", "external_network", "foreign_network",
    "extra_network", "writable_mount", "foreign_mount", "extra_mount", "mutable_payload"])
def test_uninspected_or_mismatched_runtime_never_gets_integrity_record(module, running_deployment, mutation):
    root, manifest, project, path, containers, network, image = running_deployment
    value = containers["a" * 64]
    if mutation == "image":
        value["Image"] = "sha256:" + "0" * 64
    elif mutation == "revision":
        image["Config"]["Labels"]["org.opencontainers.image.revision"] = "0" * 40
    elif mutation == "stopped":
        value["State"]["Status"] = "exited"
    elif mutation == "unhealthy":
        value["State"]["Health"]["Status"] = "unhealthy"
    elif mutation == "root":
        value["Config"]["User"] = "0:0"
    elif mutation == "writable_root":
        value["HostConfig"]["ReadonlyRootfs"] = False
    elif mutation == "ports":
        value["HostConfig"]["PortBindings"] = {"8082/tcp": [{"HostPort": "8082"}]}
    elif mutation == "arguments":
        value["Config"]["Cmd"] += ["--tools", "shell"]
    elif mutation == "entrypoint":
        value["Config"]["Entrypoint"] = ["/other"]
    elif mutation == "privileged":
        value["HostConfig"]["Privileged"] = True
    elif mutation == "capabilities":
        value["HostConfig"]["CapDrop"] = []
    elif mutation == "external_network":
        network["Internal"] = False
    elif mutation == "foreign_network":
        network["Labels"]["com.docker.compose.project"] = "foreign"
    elif mutation == "extra_network":
        value["NetworkSettings"]["Networks"]["other"] = {}
    elif mutation == "writable_mount":
        value["Mounts"][0]["RW"] = True
    elif mutation == "foreign_mount":
        value["Mounts"][0]["Source"] = "/unverified/model.gguf"
    elif mutation == "extra_mount":
        value["Mounts"].append({"Destination": "/models/other.gguf"})
    else:
        (root / "payloads/model.gguf").chmod(0o644)
    with pytest.raises(module.BundleError):
        module.attest_deployment(root, manifest, project, path)
    assert not (root / ".offline/verification.json").exists()
    assert "OCTO_OPERATOR_RUNTIME_MANIFEST_SHA256" not in (root / ".offline/app.env").read_text()
