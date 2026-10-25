#!/usr/bin/env python3
"""Verify pinned local runtime inputs and emit a small startup integrity record."""
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MODEL = "Qwen3.5-9B-Q4_K_M"
RUNTIME = "ghcr.io/ggml-org/llama.cpp:server@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44"
REVISION = "8e5a58df87ab59dfceb5b961ae26691e39f30c24"
PINS = {
    "Qwen3.5-9B-Q4_K_M.gguf": "03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8",
    "Qwen3-Embedding-0.6B-Q8_0.gguf": "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
}


def inspect(kind, name):
    return json.loads(subprocess.check_output(["docker", kind, "inspect", name], timeout=15))[0]


def build(model_dir):
    model_dir = Path(model_dir)
    if model_dir.is_symlink():
        raise ValueError("Refusing symlink model directory")
    for name, expected in PINS.items():
        path = model_dir / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing regular model artifact")
        with path.open("rb") as handle:
            if hashlib.file_digest(handle, "sha256").hexdigest() != expected:
                raise ValueError("Model integrity mismatch")
    containers = {}
    for role in ("inference", "embeddings"):
        value = inspect("container", "shapo-operator-" + role + "-1")
        if value["Config"]["Image"] != RUNTIME or value["State"]["Status"] != "running":
            raise ValueError("Runtime deployment mismatch")
        if not value["HostConfig"]["ReadonlyRootfs"] or value["Config"]["User"] != "65532:65532":
            raise ValueError("Runtime privilege mismatch")
        for network in value["NetworkSettings"]["Networks"]:
            if not inspect("network", network)["Internal"]:
                raise ValueError("Runtime has external network")
        if value["HostConfig"].get("PortBindings"):
            raise ValueError("Runtime has direct published ports")
        image = inspect("image", value["Image"])
        if image["Config"]["Labels"].get("org.opencontainers.image.revision") != REVISION:
            raise ValueError("Runtime revision mismatch")
        arguments = value["Config"]["Cmd"]
        artifact = "Qwen3.5-9B-Q4_K_M.gguf" if role == "inference" else "Qwen3-Embedding-0.6B-Q8_0.gguf"
        mounted_path = "/models/model.gguf" if role == "inference" else "/models/embedding.gguf"
        model_mounts = [item for item in value["Mounts"] if item["Destination"] == "/models"
                        or item["Destination"].startswith("/models/")]
        if (len(model_mounts) != 1 or model_mounts[0]["Type"] != "bind"
                or model_mounts[0]["Destination"] != mounted_path or model_mounts[0]["RW"]
                or Path(model_mounts[0]["Source"]).resolve() != (model_dir / artifact).resolve()):
            raise ValueError("Runtime model mount does not match verified artifact")
        permitted_flags = {"--model", "--alias", "--host", "--port", "--ctx-size", "--parallel",
            "--threads", "--batch-size", "--ubatch-size", "--n-gpu-layers", "--n-predict", "--temp",
            "--seed", "--reasoning", "--offline", "--no-webui", "--no-agent", "--no-ui-mcp-proxy", "--embedding", "--pooling"}
        if any(item.startswith("-") and item not in permitted_flags for item in arguments):
            raise ValueError("Unexpected runtime flag")
        required = {"--model": mounted_path, "--n-gpu-layers": "0", "--parallel": "1",
                    "--alias": MODEL if role == "inference" else "Qwen3-Embedding-0.6B"}
        if role == "inference":
            required.update({"--ctx-size": "8192", "--temp": "0", "--seed": "42",
                             "--reasoning": "off", "--n-predict": "1024"})
        for flag, expected in required.items():
            if arguments.count(flag) != 1 or arguments[arguments.index(flag) + 1] != expected:
                raise ValueError("Runtime argument mismatch")
        if "--offline" not in arguments or "--no-agent" not in arguments:
            raise ValueError("Runtime offline/tool boundary missing")
        containers[role] = {"image_id": value["Image"], "arguments": arguments}
    return {"schema_version": 1, "profile": "mac-arm64-cpu", "model": MODEL,
            "model_sha256": PINS["Qwen3.5-9B-Q4_K_M.gguf"], "runtime_image": RUNTIME,
            "runtime_revision": REVISION, "context_tokens": 8192, "parallel": 1,
            "embedding_sha256": PINS["Qwen3-Embedding-0.6B-Q8_0.gguf"],
            "embedding_revision": "370f27d7550e0def9b39c1f16d3fbaa13aa67728",
            "embedding_dimensions": 1024, "verified_at": datetime.now(UTC).isoformat(),
            "containers": containers}


def main():
    target = ROOT / ".operator-local/runtime/verification.json"
    if target.parent.is_symlink() or target.parent.parent.is_symlink():
        raise SystemExit("Refusing symlink runtime metadata directory")
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.parent.chmod(0o755)
    if target.is_symlink():
        raise SystemExit("Refusing symlink manifest")
    value = build(Path(os.environ.get("OPERATOR_MODELS_DIR", ROOT / ".operator-models")))
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    fd, temporary = tempfile.mkstemp(prefix=".runtime-", dir=target.parent)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
    Path(temporary).chmod(0o444)
    os.replace(temporary, target)
    print(json.dumps({"integrity": "verified_at_startup", "manifest_sha256": hashlib.sha256(raw).hexdigest(),
                      "model": MODEL, "profile": value["profile"]}))


if __name__ == "__main__":
    main()
