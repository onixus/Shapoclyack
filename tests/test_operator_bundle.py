"""Offline integrity gates use tiny fixtures, never downloaded weights."""
import hashlib
import json

import pytest

from api.services.local_operator.bundle import (
    BundleError, launch_command, launch_environment, verify_bundle,
)


@pytest.fixture
def bundle(tmp_path):
    artifacts = []
    for role in ("runtime", "model", "template", "license", "embedding"):
        data = ("fixture-" + role).encode()
        (tmp_path / role).write_bytes(data)
        artifacts.append({"role": role, "path": role, "size": len(data),
                          "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {"schema_version": 1, "model": "Qwen3.5-9B-Q4_K_M",
                "model_revision": "a" * 40, "runtime_revision": "b" * 40,
                "embedding_revision": "c" * 40, "embedding_model": "Qwen3-Embedding-0.6B",
                "context_tokens": 8192, "parallel": 1, "artifacts": artifacts}
    return tmp_path, manifest


def _write(root, manifest):
    raw = json.dumps(manifest).encode()
    (root / "manifest.json").write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_exact_integrity_is_not_runtime_acceptance(bundle):
    root, data = bundle
    manifest = verify_bundle(root, _write(root, data))
    command = launch_command(root, manifest)
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert command[command.index("--ctx-size") + 1] == "8192"
    assert command[command.index("--parallel") + 1] == "1"
    assert "--offline" in command
    assert "--hf-repo" not in command


def test_corrupt_weights_rejected_before_launch(bundle):
    root, data = bundle
    digest = _write(root, data)
    (root / "model").write_bytes(b"x" * data["artifacts"][1]["size"])
    with pytest.raises(BundleError, match="artifact_mismatch"):
        verify_bundle(root, digest)


def test_untrusted_manifest_digest_fails(bundle):
    root, data = bundle
    _write(root, data)
    with pytest.raises(BundleError, match="manifest_mismatch"):
        verify_bundle(root, "0" * 64)


@pytest.mark.parametrize("path", ["../outside", "/etc/passwd", "a/../../x", "a/./x",
                                 "a//x", "a\\x", "--model", "a/$HOME", "a/$(id)"])
def test_paths_cannot_escape_or_become_options(bundle, path):
    root, data = bundle
    data["artifacts"][0]["path"] = path
    with pytest.raises(BundleError):
        verify_bundle(root, _write(root, data))


@pytest.mark.parametrize("field,value", [("context_tokens", 4096), ("parallel", 2),
                                        ("model", "other-model"), ("runtime_revision", "main"),
                                        ("embedding_model", "cloud"), ("unknown", "x")])
def test_incompatible_baseline_rejected(bundle, field, value):
    root, data = bundle
    data[field] = value
    with pytest.raises(BundleError):
        verify_bundle(root, _write(root, data))


def test_symlink_and_parent_symlink_rejected(bundle, tmp_path):
    root, data = bundle
    (root / "model").rename(root / "real-model")
    (root / "model").symlink_to(root / "real-model")
    with pytest.raises(BundleError, match="symlink"):
        verify_bundle(root, _write(root, data))
    (root / "model").unlink()
    (root / "dir").symlink_to(root, target_is_directory=True)
    data["artifacts"][1]["path"] = "dir/real-model"
    with pytest.raises(BundleError, match="symlink"):
        verify_bundle(root, _write(root, data))


def test_duplicate_manifest_key_rejected(bundle):
    root, data = bundle
    raw = json.dumps(data).replace('"parallel": 1', '"parallel": 1, "parallel": 1').encode()
    (root / "manifest.json").write_bytes(raw)
    with pytest.raises(BundleError, match="duplicate_key"):
        verify_bundle(root, hashlib.sha256(raw).hexdigest())


@pytest.mark.parametrize("change", ["duplicate", "role", "oversize", "negative", "bool"])
def test_invalid_artifact_inventory(bundle, change):
    root, data = bundle
    if change == "duplicate":
        data["artifacts"].append(data["artifacts"][0])
    elif change == "role":
        data["artifacts"][0]["role"] = "support"
    else:
        data["artifacts"][0]["size"] = {"oversize": 13 * 1024**3, "negative": -1, "bool": True}[change]
    with pytest.raises(BundleError):
        verify_bundle(root, _write(root, data))


def test_runtime_cannot_inherit_credentials_or_llama_overrides(monkeypatch):
    for name in ("OPENAI_API_KEY", "LLAMA_ARG_HOST", "LLAMA_ARG_HF_REPO", "LD_PRELOAD",
                 "HTTP_PROXY", "LLAMA_ARG_TOOLS", "LLAMA_ARG_MCP_SERVERS_JSON"):
        monkeypatch.setenv(name, "do-not-inherit")
    assert "do-not-inherit" not in json.dumps(launch_environment())


def test_cli_refuses_untrusted_executable_before_exec(bundle, monkeypatch):
    from api.services.local_operator import bundle as module

    root, data = bundle
    _write(root, data)
    called = []
    monkeypatch.setattr(module.os, "execve", lambda *args: called.append(args))
    monkeypatch.setattr("sys.argv", ["bundle", str(root), "--manifest-sha256", "0" * 64, "--launch"])
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 1
    assert not called


def test_cli_executes_only_verified_runtime_with_fixed_environment(bundle, monkeypatch):
    from api.services.local_operator import bundle as module

    root, data = bundle
    trusted = _write(root, data)
    (root / "runtime").chmod(0o555)
    called = []
    monkeypatch.setattr(module.os, "geteuid", lambda: 65532)
    monkeypatch.setattr(module.os, "execve", lambda *args: called.append(args))
    monkeypatch.setattr("sys.argv", ["bundle", str(root), "--manifest-sha256", trusted, "--launch"])
    module.main()
    assert len(called) == 1
    executable, arguments, environment = called[0]
    assert executable == str(root / "runtime") == arguments[0]
    assert arguments == launch_command(root, module.Manifest.model_validate(data))
    assert environment == launch_environment()
