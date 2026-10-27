"""Native GGUF staging boundaries; synthetic bytes only, no Docker/model calls."""
import asyncio
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("model_storage", Path(__file__).parents[1] / "scripts/operator-runtime-manifest.py")
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


@pytest.fixture
def files(tmp_path):
    sources = {}
    for name in storage.TARGETS:
        path = tmp_path / name
        path.write_bytes(name.encode())
        sources[name] = path
    return sources, {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sources.items()}


def identity():
    return {"name": "owned", "driver": "local", "scope": "local", "created_at": "fixture",
            "labels": {storage.OWNER_LABEL: "local-operator-models", storage.NONCE_LABEL: "a" * 32}}


def readback(pins):
    return {"artifacts": {name: {"sha256": value, "size_bytes": 1, "mode": 0o444} for name, value in pins.items()}, "directory_mode": 0o555}


def test_reuse_fresh_readback_and_atomic_readonly_receipt(files, tmp_path, monkeypatch):
    sources, pins = files
    calls = []
    monkeypatch.setattr(storage, "_volume_identity", lambda _: identity())
    monkeypatch.setattr(storage, "_no_writers", lambda _: calls.append("no_writers"))
    monkeypatch.setattr(storage, "_stream_models", lambda *a: pytest.fail("Existing data must not be overwritten"))
    def read(_volume, expected, _image, *, seal=False):
        calls.append("seal" if seal else "fresh_readonly_hash")
        return readback(expected)
    monkeypatch.setattr(storage, "_readback", read)
    receipt = tmp_path / "proof.json"
    proof = storage.stage_models(sources, pins, volume="owned", receipt_path=receipt)
    assert calls == ["no_writers", "seal", "no_writers", "fresh_readonly_hash", "no_writers"]
    assert proof["source_sha256"] == pins and proof["readback_verified"]
    assert json.loads(receipt.read_text())["artifacts"] == readback(pins)["artifacts"]
    assert receipt.stat().st_mode & 0o777 == 0o444


@pytest.mark.parametrize("change", ["source", "dest_hash", "mode", "writer"])
def test_failed_reuse_never_publishes_valid_receipt(files, tmp_path, monkeypatch, change):
    sources, pins = files
    monkeypatch.setattr(storage, "_volume_identity", lambda _: identity())
    def no_writers(_):
        if change == "writer":
            raise ValueError("Writable attachment")
    monkeypatch.setattr(storage, "_no_writers", no_writers)
    def read(*args, **kwargs):
        result = readback(pins)
        if change == "dest_hash":
            result["artifacts"]["model.gguf"]["sha256"] = "0" * 64
        if change == "mode":
            result["artifacts"]["model.gguf"]["mode"] = 0o644
        return result
    monkeypatch.setattr(storage, "_readback", read)
    if change == "source":
        sources["model.gguf"].write_bytes(b"changed")
    receipt = tmp_path / "proof.json"
    with pytest.raises(ValueError):
        storage.stage_models(sources, pins, volume="owned", receipt_path=receipt)
    assert not receipt.exists()


def test_stopped_writable_container_is_still_a_writer(monkeypatch):
    monkeypatch.setattr(storage, "_docker", lambda argv: "a" * 12)
    monkeypatch.setattr(storage, "inspect", lambda *args: {"State": {"Status": "exited"},
        "Mounts": [{"Type": "volume", "Name": "owned", "RW": True}]})
    with pytest.raises(ValueError, match="writable attachment"):
        storage._no_writers("owned")


@pytest.mark.parametrize("change", ["driver", "options", "owner", "nonce"])
def test_volume_name_is_not_authority(monkeypatch, change):
    value = {"Name": "owned", "Driver": "local", "Scope": "local", "CreatedAt": "fixture",
             "Labels": identity()["labels"], "Options": None}
    if change == "driver":
        value["Driver"] = "nfs"
    elif change == "options":
        value["Options"] = {"device": "/host/path", "type": "none", "o": "bind"}
    elif change == "owner":
        value["Labels"][storage.OWNER_LABEL] = "foreign"
    else:
        value["Labels"][storage.NONCE_LABEL] = ""
    monkeypatch.setattr(storage, "inspect", lambda *args: value)
    with pytest.raises(ValueError, match="identity/ownership"):
        storage._volume_identity("owned")


def test_source_symlink_rejected_before_docker(files, tmp_path, monkeypatch):
    sources, pins = files
    link = tmp_path / "link.gguf"
    link.symlink_to(sources["model.gguf"])
    sources["model.gguf"] = link
    monkeypatch.setattr(storage, "_docker", lambda *a, **k: pytest.fail("No Docker on invalid input"))
    with pytest.raises(ValueError, match="non-symlink"):
        storage.stage_models(sources, pins)


@pytest.mark.parametrize("broken", [False, True])
def test_stream_is_bounded_stdin_and_always_cleans_owned_writer(files, monkeypatch, broken):
    sources, pins = files
    sources["model.gguf"].write_bytes(b"x" * (2 * 1048576 + 7))
    pins["model.gguf"] = hashlib.sha256(sources["model.gguf"].read_bytes()).hexdigest()
    removed, commands = [], []
    class Writer:
        def __init__(self):
            self.chunks = []
        def write(self, chunk):
            assert len(chunk) <= 1048576
            self.chunks.append(chunk)
        async def drain(self):
            if broken:
                raise BrokenPipeError
        def close(self):
            pass
        async def wait_closed(self):
            pass
    class Process:
        returncode = None
        stdin = Writer()
        async def communicate(self):
            self.returncode = 0
            return b'{"copied":true}', b''
        def kill(self):
            self.returncode = -9
        async def wait(self):
            return self.returncode
    process = Process()
    async def spawn(*argv, **kwargs):
        commands.append(argv)
        return process
    monkeypatch.setattr(storage.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(storage, "_remove_helper", removed.append)
    monkeypatch.setattr(storage, "_helper_state", lambda _: {"Status": "exited", "ExitCode": 137, "OOMKilled": True})
    if broken:
        with pytest.raises(storage.ModelStorageError) as caught:
            asyncio.run(storage._stream_models(sources, pins, "owned", storage.HELPER_IMAGE))
        assert caught.value.diagnostic["cause"] == "BrokenPipeError"
        assert caught.value.diagnostic["helper_state"]["OOMKilled"]
    else:
        assert asyncio.run(storage._stream_models(sources, pins, "owned", storage.HELPER_IMAGE)) == pins
        assert b''.join(process.stdin.chunks) == b''.join(path.read_bytes() for path in sources.values())
    assert len(removed) == 1 and removed[0].startswith("shapo-model-storage-")
    assert "--network=none" in commands[0] and "--no-healthcheck" in commands[0]
    assert "--memory=512m" in commands[0] and "--rm" not in commands[0]
    assert not any("type=bind" in value for value in commands[0])

@pytest.mark.parametrize("extra", [".part", ".hidden", "symlink"])
def test_readback_helper_rejects_extra_partial_and_symlink_files(files, tmp_path, monkeypatch, extra):
    import signal
    import sys
    sources, pins = files
    root = tmp_path / "volume"
    root.mkdir()
    for name, path in sources.items():
        (root / name).write_bytes(path.read_bytes())
    if extra == "symlink":
        (root / "model.gguf").unlink()
        (root / "model.gguf").symlink_to(sources["model.gguf"])
    else:
        (root / extra).write_bytes(b"preserve; do not delete")
    code = storage.READBACK_CODE.replace("'/models/'", repr(str(root) + "/")).replace("'/models'", repr(str(root)))
    monkeypatch.setattr(signal, "alarm", lambda _: None)
    monkeypatch.setattr(sys, "argv", ["helper", json.dumps(pins), "seal"])
    with pytest.raises(ValueError):
        exec(compile(code, "<fixed-readback-helper>", "exec"), {})
    assert (root / extra).exists() if extra != "symlink" else (root / "model.gguf").is_symlink()


def test_readback_helper_seals_only_after_hashes_pass(files, tmp_path, monkeypatch, capsys):
    import signal
    import sys
    sources, pins = files
    root = tmp_path / "volume"
    root.mkdir()
    for name, path in sources.items():
        (root / name).write_bytes(path.read_bytes())
    code = storage.READBACK_CODE.replace("'/models/'", repr(str(root) + "/")).replace("'/models'", repr(str(root)))
    monkeypatch.setattr(signal, "alarm", lambda _: None)
    monkeypatch.setattr(sys, "argv", ["helper", json.dumps(pins), "seal"])
    try:
        exec(compile(code, "<fixed-readback-helper>", "exec"), {})
        proof = json.loads(capsys.readouterr().out)
        assert proof["directory_mode"] == 0o555
        assert all(row["mode"] == 0o444 for row in proof["artifacts"].values())
        assert {name: row["sha256"] for name, row in proof["artifacts"].items()} == pins
    finally:
        root.chmod(0o755)

def test_copy_helper_actual_stdin_hash_fsync_and_cache_drop(files, tmp_path, monkeypatch, capsys):
    import io
    import signal
    import sys
    sources, pins = files
    sources["model.gguf"].write_bytes(b"x" * (17 * 1048576))
    pins["model.gguf"] = hashlib.sha256(sources["model.gguf"].read_bytes()).hexdigest()
    root = tmp_path / "volume"
    root.mkdir()
    items = {name: {"size_bytes": path.stat().st_size, "sha256": pins[name]} for name, path in sources.items()}
    payload = b"".join(path.read_bytes() for path in sources.values())
    code = storage.COPY_CODE.replace("root='/models'", "root=" + repr(str(root)))
    monkeypatch.setattr(signal, "alarm", lambda _: None)
    monkeypatch.setattr(sys, "argv", ["copy", json.dumps(items)])
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload)))
    drops = []
    monkeypatch.setattr(storage.os, "posix_fadvise", lambda *args: drops.append(args), raising=False)
    monkeypatch.setattr(storage.os, "POSIX_FADV_DONTNEED", 4, raising=False)
    try:
        exec(compile(code, "<fixed-copy-helper>", "exec"), {})
        assert json.loads(capsys.readouterr().out)["copied"]
        assert len(drops) == 2
        for name in pins:
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == pins[name]
            assert (root / name).stat().st_mode & 0o777 == 0o444
        assert root.stat().st_mode & 0o777 == 0o555
        assert set(path.name for path in root.iterdir()) == set(pins)
    finally:
        root.chmod(0o755)


def test_fixed_helper_programs_compile():
    compile(storage.COPY_CODE, "<copy>", "exec")
    compile(storage.READBACK_CODE, "<readback>", "exec")



