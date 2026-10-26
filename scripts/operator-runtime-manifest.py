#!/usr/bin/env python3
"""Verify pinned local runtime inputs and emit a small startup integrity record."""
from datetime import UTC, datetime
import argparse
import asyncio
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
MODEL = "Qwen3.5-9B-Q4_K_M"
RUNTIME = "ghcr.io/ggml-org/llama.cpp:server@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44"
REVISION = "8e5a58df87ab59dfceb5b961ae26691e39f30c24"
PINS = {
    "Qwen3.5-9B-Q4_K_M.gguf": "03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8",
    "Qwen3-Embedding-0.6B-Q8_0.gguf": "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
}
HELPER_IMAGE = "sha256:d0c3811794d5e8ba0ab27e32705c34410ca7e6208c6a34d32a57a9ef6af387bf"
TARGETS = {"model.gguf": "Qwen3.5-9B-Q4_K_M.gguf", "embedding.gguf": "Qwen3-Embedding-0.6B-Q8_0.gguf"}
OWNER_LABEL = "shapo.operator.owner"
NONCE_LABEL = "shapo.operator.nonce"

# Fixed helper code, no model text or shell evaluation. All GGUF IO is bounded
# to 1MiB chunks; source bytes enter the guest through Docker stdin, not VirtioFS.
COPY_CODE = '''import hashlib,json,os,signal,sys
signal.alarm(600)
items=json.loads(sys.argv[1]);root='/models'
for name,item in items.items():
 path=root+'/'+name;temporary=path+'.part'
 descriptor=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 digest=hashlib.sha256();remaining=item['size_bytes'];dirty=0
 with os.fdopen(descriptor,'wb') as handle:
  while remaining:
   chunk=sys.stdin.buffer.read(min(1048576,remaining))
   if not chunk:raise ValueError('Truncated model stream')
   remaining-=len(chunk);digest.update(chunk);handle.write(chunk);dirty+=len(chunk)
   if dirty>=8388608:
    handle.flush();os.fsync(handle.fileno())
    if hasattr(os,'posix_fadvise'):os.posix_fadvise(handle.fileno(),0,0,os.POSIX_FADV_DONTNEED)
    dirty=0
  handle.flush();os.fsync(handle.fileno())
 if digest.hexdigest()!=item['sha256']:raise ValueError('Model stream checksum mismatch')
 if os.path.lexists(path):raise ValueError('Refusing existing model destination')
 os.chmod(temporary,0o444);os.rename(temporary,path)
if sys.stdin.buffer.read(1):raise ValueError('Trailing model stream')
os.chmod(root,0o555)
fd=os.open(root,os.O_RDONLY);os.fsync(fd);os.close(fd)
print(json.dumps({'copied':True}),flush=True)
'''
READBACK_CODE = '''import hashlib,json,os,resource,signal,stat,sys
signal.alarm(600)
pins=json.loads(sys.argv[1]);seal=sys.argv[2]=='seal';result={}
if set(os.listdir('/models'))!=set(pins):raise ValueError('Unexpected model volume files')
for name,expected in pins.items():
 path='/models/'+name;info=os.lstat(path)
 if not stat.S_ISREG(info.st_mode):raise ValueError('Model is not a regular file')
 with open(path,'rb') as handle:actual=hashlib.file_digest(handle,'sha256').hexdigest()
 if actual!=expected:raise ValueError('Volume model checksum mismatch')
 result[name]={'sha256':actual,'size_bytes':info.st_size,'mode':stat.S_IMODE(info.st_mode)}
if seal:
 for name in pins:os.chmod('/models/'+name,0o444);result[name]['mode']=0o444
 os.chmod('/models',0o555)
 fd=os.open('/models',os.O_RDONLY);os.fsync(fd);os.close(fd)
print(json.dumps({'artifacts':result,'directory_mode':stat.S_IMODE(os.stat('/models').st_mode),'helper_peak_rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024}),flush=True)
'''


def inspect(kind, name):
    return json.loads(subprocess.check_output(["docker", kind, "inspect", name], timeout=15))[0]


class ModelStorageError(ValueError):
    """Bounded fixed-helper diagnostics, never stdin/model bytes."""
    def __init__(self, message, diagnostic):
        super().__init__(message)
        self.diagnostic = diagnostic


def _helper_state(name):
    try:
        value = inspect("container", name)["State"]
        return {key: value.get(key) for key in ("Status", "ExitCode", "OOMKilled")}
    except Exception as exc:
        return {"unavailable": type(exc).__name__}


def _docker(arguments, *, timeout=30):
    result = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise ModelStorageError("Model storage Docker operation failed",
            {"exit_code": result.returncode, "stderr": result.stderr[-2000:]})
    return result.stdout


def _pins(expected):
    if set(expected) != set(TARGETS) or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value) for value in expected.values()):
        raise ValueError("Invalid canonical model pins")
    return dict(expected)


def _volume_identity(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
        raise ValueError("Invalid local model volume name")
    value = inspect("volume", name)
    labels = value.get("Labels") or {}
    if (value.get("Name") != name or value.get("Driver") != "local" or value.get("Scope") != "local"
            or value.get("Options") or labels.get(OWNER_LABEL) not in {"local-operator-models", "ai-operator-completion"}
            or not re.fullmatch(r"[a-f0-9]{12,64}", labels.get(NONCE_LABEL, ""))):
        raise ValueError("Model volume identity/ownership mismatch")
    return {"name": name, "driver": value["Driver"], "scope": value["Scope"],
            "created_at": value["CreatedAt"], "labels": labels}


def _no_writers(name):
    ids = _docker(["ps", "--all", "--filter", "volume=" + name, "--format", "{{.ID}}"]).splitlines()
    for cid in ids:
        if not re.fullmatch(r"[a-f0-9]{12,64}", cid):
            raise ValueError("Invalid attached container identity")
        value = inspect("container", cid)
        if any(item.get("Type") == "volume" and item.get("Name") == name and item.get("RW") for item in value.get("Mounts", [])):
            raise ValueError("Model volume has a writable attachment")


def _helper_arguments(volume, image, code, parameters, *, writable=False):
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise ValueError("An immutable local helper image ID is required")
    return ["run", "--pull=never", "--no-healthcheck", "--name", "shapo-model-storage-" + uuid4().hex,
            "--network=none", "--read-only", "--user=0:0", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory=" + ("512m" if writable else "128m"), "--cpus=1", "--pids-limit=32", "--mount",
            "type=volume,source=" + volume + ",target=/models,volume-nocopy" + ("" if writable else ",readonly"),
            "--entrypoint", "python", image, "-c", code, *parameters]


def _readback(volume, expected, helper_image, *, seal=False):
    args = _helper_arguments(volume, helper_image, READBACK_CODE, [json.dumps(expected), "seal" if seal else "read"], writable=seal)
    try:
        return json.loads(_docker(args, timeout=630))
    except ModelStorageError as exc:
        exc.diagnostic["helper_state"] = _helper_state(args[args.index("--name") + 1])
        raise
    finally:
        _remove_helper(args[args.index("--name") + 1])


def _remove_helper(name):
    result = subprocess.run(["docker", "rm", "--force", name], capture_output=True, text=True, timeout=15)
    if result.returncode and "No such container" not in result.stderr:
        raise ValueError("Owned model-storage helper cleanup failed")


def _open_source(path):
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("Regular model source required")
    return os.fdopen(descriptor, "rb")


def verify_volume(volume, expected_sha256, *, helper_image=HELPER_IMAGE):
    expected = _pins(expected_sha256)
    identity = _volume_identity(volume)
    _no_writers(volume)
    result = _readback(volume, expected, helper_image)
    if (set(result.get("artifacts", {})) != set(expected) or result.get("directory_mode") != 0o555
            or any(item.get("sha256") != expected[name] or item.get("mode") != 0o444
                   for name, item in result["artifacts"].items())):
        raise ValueError("Model volume is not checksum verified and read-only sealed")
    _no_writers(volume)
    if _volume_identity(volume) != identity:
        raise ValueError("Model volume identity changed during readback")
    return {"schema_version": 1, "storage": "docker_local_volume", "volume": identity,
            "artifacts": result["artifacts"], "readback_verified": True, "sealed_read_only": True,
            "readback_helper_peak_rss_bytes": result.get("helper_peak_rss_bytes"),
            "helper_image": helper_image, "verified_at": datetime.now(UTC).isoformat()}


async def _stream_models(source_files, expected, volume, helper_image):
    with ExitStack() as stack:
        sources = {name: stack.enter_context(_open_source(path)) for name, path in source_files.items()}
        return await _stream_open_models(sources, expected, volume, helper_image)


async def _stream_open_models(sources, expected, volume, helper_image):
    items = {name: {"size_bytes": os.fstat(handle.fileno()).st_size, "sha256": expected[name]} for name, handle in sources.items()}
    args = _helper_arguments(volume, helper_image, COPY_CODE, [json.dumps(items)], writable=True)
    args.insert(1, "-i")
    process = await asyncio.create_subprocess_exec("docker", *args, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    hashes = {}
    output, error = b"", b""
    try:
        async with asyncio.timeout(630):
            for name, handle in sources.items():
                digest = hashlib.sha256()
                while chunk := handle.read(1048576):
                    digest.update(chunk)
                    process.stdin.write(chunk)
                    await process.stdin.drain()
                hashes[name] = digest.hexdigest()
                if hashes[name] != expected[name]:
                    raise ValueError("Source model checksum mismatch")
            process.stdin.close()
            await process.stdin.wait_closed()
            output, error = await process.communicate()
            if process.returncode:
                raise ValueError("Native model staging failed")
    except BaseException as exc:
        try:
            if process.returncode is None:
                process.stdin.close()
                output, error = await asyncio.wait_for(process.communicate(), 5)
            diagnostic = {"helper_exit_code": process.returncode, "stderr": error.decode(errors="replace")[-2000:],
                          "stdout": output.decode(errors="replace")[-500:]}
        except BaseException as diagnostic_error:
            diagnostic = {"helper_exit_code": process.returncode, "diagnostic_unavailable": type(diagnostic_error).__name__}
        diagnostic.update(cause=type(exc).__name__, helper_name=args[args.index("--name") + 1],
                          helper_state=_helper_state(args[args.index("--name") + 1]))
        raise ModelStorageError("Native model staging failed", diagnostic) from exc
    finally:
        if process.returncode is None:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), 5)
            except TimeoutError:
                pass
        _remove_helper(args[args.index("--name") + 1])
    return hashes


def _atomic_receipt(path, value):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError("Refusing symlink storage receipt")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".model-storage-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            json.dump(value, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage_models(source_files, expected_sha256, *, helper_image=HELPER_IMAGE, volume=None, receipt_path=None):
    expected = _pins(expected_sha256)
    if set(source_files) != set(expected):
        raise ValueError("Invalid canonical source model names")
    sources = {name: Path(path) for name, path in source_files.items()}
    if any(path.is_symlink() or path.parent.is_symlink() or not path.is_file() for path in sources.values()):
        raise ValueError("Regular non-symlink source models required")
    # An explicit existing owned volume is never overwritten, only freshly
    # hashed and metadata sealed. New volumes are never deleted on failure.
    existing = None
    if volume is not None:
        try:
            existing = _volume_identity(volume)
        except subprocess.CalledProcessError:
            pass
    if existing is None:
        volume = volume or "shapo-operator-models-" + uuid4().hex[:12]
        nonce = uuid4().hex
        _docker(["volume", "create", "--driver", "local", "--label", OWNER_LABEL + "=local-operator-models",
                 "--label", NONCE_LABEL + "=" + nonce, volume])
        identity = _volume_identity(volume)
        if identity["labels"].get(NONCE_LABEL) != nonce:
            raise ValueError("New volume ownership mismatch")
        _no_writers(volume)
        source_hashes = asyncio.run(_stream_models(sources, expected, volume, helper_image))
    else:
        _no_writers(volume)
        source_hashes = {}
        for name, path in sources.items():
            with _open_source(path) as handle:
                source_hashes[name] = hashlib.file_digest(handle, "sha256").hexdigest()
        if source_hashes != expected:
            raise ValueError("Source model checksum mismatch")
        _readback(volume, expected, helper_image, seal=True)
    proof = verify_volume(volume, expected, helper_image=helper_image)
    proof["status"] = "verified"
    proof["source_sha256"] = source_hashes
    if receipt_path is not None:
        _atomic_receipt(receipt_path, proof)
    return proof


def build(model_dir, *, storage="bind", volume=None, helper_image=HELPER_IMAGE):
    model_dir = Path(model_dir)
    if model_dir.is_symlink():
        raise ValueError("Refusing symlink model directory")
    if storage not in {"bind", "native"}:
        raise ValueError("Unknown model storage profile")
    storage_proof = verify_volume(volume, {target: PINS[source] for target, source in TARGETS.items()}, helper_image=helper_image) if storage == "native" else None
    for name, expected in (PINS.items() if storage == "bind" else []):
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
        ipv6 = value["HostConfig"].get("Sysctls", {})
        if any(ipv6.get(key) != "1" for key in (
                "net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6")):
            raise ValueError("Runtime IPv4-only namespace mismatch")
        image = inspect("image", value["Image"])
        if image["Config"]["Labels"].get("org.opencontainers.image.revision") != REVISION:
            raise ValueError("Runtime revision mismatch")
        arguments = value["Config"]["Cmd"]
        artifact = "Qwen3.5-9B-Q4_K_M.gguf" if role == "inference" else "Qwen3-Embedding-0.6B-Q8_0.gguf"
        mounted_path = "/models/model.gguf" if role == "inference" else "/models/embedding.gguf"
        model_mounts = [item for item in value["Mounts"] if item["Destination"] == "/models"
                        or item["Destination"].startswith("/models/")]
        valid_mount = len(model_mounts) == 1 and not model_mounts[0]["RW"]
        if storage == "native":
            valid_mount = valid_mount and model_mounts[0].get("Type") == "volume" and model_mounts[0].get("Name") == volume and model_mounts[0].get("Destination") == "/models"
        else:
            valid_mount = valid_mount and model_mounts[0].get("Type") == "bind" and model_mounts[0].get("Destination") == mounted_path and Path(model_mounts[0]["Source"]).resolve() == (model_dir / artifact).resolve()
        if not valid_mount:
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
            if storage == "native":
                required["--threads"] = "4"
        for flag, expected in required.items():
            if arguments.count(flag) != 1 or arguments[arguments.index(flag) + 1] != expected:
                raise ValueError("Runtime argument mismatch")
        if "--offline" not in arguments or "--no-agent" not in arguments:
            raise ValueError("Runtime offline/tool boundary missing")
        containers[role] = {"image_id": value["Image"], "arguments": arguments, "sysctls": ipv6,
                            "model_mount": {key: model_mounts[0].get(key) for key in ("Type", "Name", "Destination", "RW")}}
    return {"schema_version": 1, "profile": "mac-arm64-cpu", "model": MODEL,
            "model_sha256": PINS["Qwen3.5-9B-Q4_K_M.gguf"], "runtime_image": RUNTIME,
            "runtime_revision": REVISION, "context_tokens": 8192, "parallel": 1,
            "embedding_sha256": PINS["Qwen3-Embedding-0.6B-Q8_0.gguf"],
            "embedding_revision": "370f27d7550e0def9b39c1f16d3fbaa13aa67728",
            "embedding_dimensions": 1024, "verified_at": datetime.now(UTC).isoformat(),
            "containers": containers, "model_storage": storage_proof or {"storage": "host_bind_diagnostic"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("attest", "stage-volume", "verify-volume"), default="attest")
    parser.add_argument("--volume", default=os.environ.get("OPERATOR_MODELS_VOLUME"))
    parser.add_argument("--receipt", type=Path, default=ROOT / ".operator-local/runtime/model-storage.json")
    args = parser.parse_args()
    source_dir = Path(os.environ.get("OPERATOR_MODELS_DIR", ROOT / ".operator-models"))
    pins = {target: PINS[source] for target, source in TARGETS.items()}
    if args.command == "stage-volume":
        volume = args.volume
        if volume is None and args.receipt.is_file() and not args.receipt.is_symlink():
            previous = json.loads(args.receipt.read_text())
            volume = previous.get("volume", {}).get("name")
        proof = stage_models({target: source_dir / source for target, source in TARGETS.items()}, pins,
                             volume=volume, receipt_path=args.receipt)
        print(json.dumps({"volume_name": proof["volume"]["name"], "receipt": str(args.receipt), "verified": True}))
        return
    if args.command == "verify-volume":
        print(json.dumps(verify_volume(args.volume, pins)))
        return
    target = ROOT / ".operator-local/runtime/verification.json"
    if target.parent.is_symlink() or target.parent.parent.is_symlink():
        raise SystemExit("Refusing symlink runtime metadata directory")
    target.parent.mkdir(mode=0o700, exist_ok=True)
    target.parent.chmod(0o755)
    if target.is_symlink():
        raise SystemExit("Refusing symlink manifest")
    value = build(source_dir, storage=os.environ.get("OPERATOR_MODEL_STORAGE", "bind"), volume=args.volume)
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
