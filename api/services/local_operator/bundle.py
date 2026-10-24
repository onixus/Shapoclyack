"""Offline bundle verification. Trust comes from an independently pinned digest.

No extraction, download, environment-based model selection, or shell execution.
The deployment must make the verified directory immutable before launch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

MAX_MANIFEST = 65536
MAX_BUNDLE_BYTES = 18 * 1024**3
MODEL = "Qwen3.5-9B-Q4_K_M"


class BundleError(ValueError):
    """Sanitized failure, without paths or untrusted manifest content."""


class Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    path: str = Field(min_length=1, max_length=240)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size: int = Field(gt=0, le=12 * 1024**3)
    role: Literal["runtime", "model", "template", "license", "embedding", "support"]


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    schema_version: Literal[1]
    model: Literal["Qwen3.5-9B-Q4_K_M"]
    model_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    runtime_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    embedding_revision: str = Field(pattern=r"^[a-f0-9]{40}$")
    embedding_model: Literal["Qwen3-Embedding-0.6B"]
    context_tokens: Literal[8192]
    parallel: Literal[1]
    artifacts: list[Artifact] = Field(min_length=5, max_length=128)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise BundleError("bundle_duplicate_key")
        value[key] = item
    return value


def _safe_file(root: Path, name: str) -> Path:
    parts = PurePosixPath(name).parts
    if (not parts or name.startswith("/") or "\\" in name
            or any(part in {".", ".."} for part in name.split("/"))
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]*", p) for p in parts)):
        raise BundleError("bundle_invalid_path")
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise BundleError("bundle_symlink")
    if not stat.S_ISREG(current.stat().st_mode):
        raise BundleError("bundle_not_regular")
    return current


def verify_bundle(root: Path, expected_sha256: str) -> Manifest:
    """Validate exact manifest bytes and every listed artifact before any exec.

    The hash argument must be obtained via trusted release metadata, never from
    a checksum file bundled alongside untrusted weights. Hashes are integrity,
    not provenance by themselves. This function does not accept archives.
    """
    try:
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise BundleError("bundle_trust_digest_required")
        root = Path(root)
        if root.is_symlink() or not root.is_dir() or root.resolve() != root.absolute():
            raise BundleError("bundle_invalid_root")
        manifest_file = _safe_file(root, "manifest.json")
        if manifest_file.stat().st_size > MAX_MANIFEST:
            raise BundleError("bundle_manifest_too_large")
        with manifest_file.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST + 1)
        if len(raw) > MAX_MANIFEST or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise BundleError("bundle_manifest_mismatch")
        manifest = Manifest.model_validate(json.loads(raw, object_pairs_hook=_unique))
        names = [a.path for a in manifest.artifacts]
        if len(set(names)) != len(names) or "manifest.json" in names:
            raise BundleError("bundle_duplicate_artifact")
        for role in ("runtime", "model", "template", "embedding"):
            if sum(a.role == role for a in manifest.artifacts) != 1:
                raise BundleError("bundle_required_artifact")
        if not any(a.role == "license" for a in manifest.artifacts):
            raise BundleError("bundle_license_required")
        if sum(a.size for a in manifest.artifacts) > MAX_BUNDLE_BYTES:
            raise BundleError("bundle_too_large")
        for artifact in manifest.artifacts:
            path = _safe_file(root, artifact.path)
            if path.stat().st_size != artifact.size:
                raise BundleError("bundle_size_mismatch")
            digest = hashlib.sha256()
            count = 0
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    count += len(chunk)
                    if count > artifact.size:
                        raise BundleError("bundle_size_mismatch")
                    digest.update(chunk)
            if count != artifact.size or digest.hexdigest() != artifact.sha256:
                raise BundleError("bundle_artifact_mismatch")
        return manifest
    except BundleError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, ValidationError):
        raise BundleError("bundle_invalid") from None


def launch_command(root: Path, manifest: Manifest, *, port: int = 8082) -> list[str]:
    if type(port) is not int or not 1024 <= port <= 65535:
        raise BundleError("bundle_invalid_port")
    files = {a.role: str(root / a.path) for a in manifest.artifacts}
    return [files["runtime"], "--model", files["model"], "--chat-template-file", files["template"],
            "--alias", MODEL, "--host", "127.0.0.1", "--port", str(port),
            "--ctx-size", "8192", "--parallel", "1", "--n-gpu-layers", "999",
            "--n-predict", "1024", "--offline", "--no-webui"]


def launch_environment() -> dict[str, str]:
    # Inherited LLAMA_ARG_*, proxy/provider keys and preload hooks must not
    # override the fixed command or disclose credentials to the runtime.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HF_HUB_OFFLINE": "1",
            "HF_HUB_DISABLE_TELEMETRY": "1", "DO_NOT_TRACK": "1"}


def main():
    parser = argparse.ArgumentParser(description="Verify a trusted offline AI bundle")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()
    try:
        manifest = verify_bundle(args.bundle, args.manifest_sha256)
        command = launch_command(args.bundle, manifest, port=args.port)
        if args.launch:
            if not hasattr(os, "geteuid") or os.geteuid() == 0:
                raise BundleError("bundle_nonroot_required")
            if not os.access(command[0], os.X_OK):
                raise BundleError("bundle_runtime_not_executable")
            # CLI-only deployment operation, never reachable from an API/tool.
            # Every executable byte was verified against the administrator's
            # independently trusted manifest digest; argv is fixed and env is
            # a fresh constant whitelist, with no inherited LLAMA_ARG_* values.
            os.execve(command[0], command, launch_environment())  # nosemgrep: python.lang.security.audit.dangerous-os-exec-tainted-env-args.dangerous-os-exec-tainted-env-args
        print(json.dumps({"integrity": "verified", "model": manifest.model,
                          "manifest_sha256": args.manifest_sha256,
                          "runtime_status": "not_checked", "hardware_accepted": False}))
    except BundleError as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
