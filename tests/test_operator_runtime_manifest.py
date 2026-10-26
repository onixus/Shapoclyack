"""Startup trust binds the hashed artifact to the inspected container mount."""
import hashlib
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("operator_runtime_manifest", Path(__file__).parents[1] / "scripts/operator-runtime-manifest.py")
manifest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manifest)


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    pins = {}
    for name in manifest.PINS:
        (tmp_path / name).write_bytes(name.encode())
        pins[name] = hashlib.sha256(name.encode()).hexdigest()
    monkeypatch.setattr(manifest, "PINS", pins)
    containers = {}
    for role in ("inference", "embeddings"):
        source = tmp_path / ("Qwen3.5-9B-Q4_K_M.gguf" if role == "inference" else "Qwen3-Embedding-0.6B-Q8_0.gguf")
        target = "/models/model.gguf" if role == "inference" else "/models/embedding.gguf"
        args = ["--model", target, "--alias", manifest.MODEL if role == "inference" else "Qwen3-Embedding-0.6B",
                "--n-gpu-layers", "0", "--parallel", "1", "--offline", "--no-agent"]
        if role == "inference":
            args += ["--ctx-size", "8192", "--temp", "0", "--seed", "42", "--reasoning", "off", "--n-predict", "1024"]
        containers[role] = {"Config": {"Image": manifest.RUNTIME, "User": "65532:65532", "Cmd": args},
            "State": {"Status": "running"}, "HostConfig": {"ReadonlyRootfs": True, "PortBindings": {},
                "Sysctls": {"net.ipv6.conf.all.disable_ipv6": "1", "net.ipv6.conf.default.disable_ipv6": "1"}},
            "NetworkSettings": {"Networks": {"private": {}}}, "Image": "actual-image-id",
            "Mounts": [{"Type": "bind", "Source": str(source), "Destination": target, "RW": False}]}
    def inspect(kind, name):
        if kind == "network":
            return {"Internal": True}
        if kind == "image":
            return {"Config": {"Labels": {"org.opencontainers.image.revision": manifest.REVISION}}}
        return containers["inference" if name.endswith("inference-1") else "embeddings"]
    monkeypatch.setattr(manifest, "inspect", inspect)
    return tmp_path, containers


def test_verified_runtime_binds_actual_model_files(runtime):
    root, _ = runtime
    assert manifest.build(root)["profile"] == "mac-arm64-cpu"


@pytest.mark.parametrize("role", ["inference", "embeddings"])
def test_runtime_requires_ipv4_only_namespace(runtime, role):
    root, containers = runtime
    containers[role]["HostConfig"]["Sysctls"]["net.ipv6.conf.all.disable_ipv6"] = "0"
    with pytest.raises(ValueError, match="IPv4-only"):
        manifest.build(root)


@pytest.mark.parametrize("mode", ["source", "writable", "destination", "shadow", "argument", "duplicate", "unknown_flag"])
def test_mismatched_runtime_cannot_attest_other_verified_artifact(runtime, mode):
    root, containers = runtime
    container = containers["inference"]
    mount = container["Mounts"][0]
    if mode == "source":
        mount["Source"] = str(root / "other.gguf")
    elif mode == "writable":
        mount["RW"] = True
    elif mode == "destination":
        mount["Destination"] = "/models/other.gguf"
    elif mode == "shadow":
        container["Mounts"].append({"Type": "bind", "Source": str(root), "Destination": "/models", "RW": False})
    elif mode == "argument":
        container["Config"]["Cmd"][1] = "/models/other.gguf"
    elif mode == "duplicate":
        container["Config"]["Cmd"] += ["--model", "/models/other.gguf"]
    else:
        container["Config"]["Cmd"] += ["--model-url", "https://external.invalid/model"]
    with pytest.raises(ValueError):
        manifest.build(root)
