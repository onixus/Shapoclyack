"""Full workstation bundle trust and archive boundaries with tiny payloads."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile

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
        "created_at": "2026-10-25T00:00:00Z", "feed_status": "source_seed_only_unaccepted", "sbom_scope": "bundle_files"}
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


@pytest.mark.parametrize("mutation", ["manifest", "model", "extra_file", "symlink", "duplicate", "bool_size",
    "unknown_field", "missing_license", "missing_image_sbom", "mutable_image", "foreign_profile"])
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
