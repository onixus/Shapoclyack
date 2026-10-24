# Separate inference container on Mac

The owner requested this workstation profile on 2026-10-25. It uses a separate
Linux ARM64 CPU container on Docker Desktop. It retains Qwen3.5-9B Q4_K_M,
8192 total context tokens and one inference slot. This is an additional
deployment profile; it does not establish the Linux/NVIDIA 8-GiB guarantee.

Pinned inputs:

| Input | Immutable value |
|---|---|
| llama.cpp image index | `ghcr.io/ggml-org/llama.cpp@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44` |
| Runtime source revision | `8e5a58df87ab59dfceb5b961ae26691e39f30c24` (b11854) |
| Model repository | `unsloth/Qwen3.5-9B-GGUF` |
| Model revision | `3885219b6810b007914f3a7950a8d1b469d598a5` |
| Artifact | `Qwen3.5-9B-Q4_K_M.gguf`, 5680522464 bytes |
| Artifact SHA-256 | `03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8` |

The model digest and size were taken from the upstream repository's HTTPS
LFS metadata at that revision, rather than calculated from an untrusted
download and treated as its own trust anchor. Upstream advertises Apache-2.0;
retain applicable license metadata with offline transfers. The GGUF's embedded
tokenizer/chat template are covered by the model file hash. No image projector
is loaded. See [model metadata](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/tree/3885219b6810b007914f3a7950a8d1b469d598a5)
and [runtime source](https://github.com/ggml-org/llama.cpp/tree/8e5a58df87ab59dfceb5b961ae26691e39f30c24).

```sh
# Connected staging only: downloads about 5.68 GB plus the runtime image.
bash scripts/operator-mac.sh download
# Offline startup verifies weights again and refuses image auto-pull.
bash scripts/operator-mac.sh up
bash scripts/operator-mac.sh ps
curl --fail http://127.0.0.1:8082/health
curl --fail http://127.0.0.1:8082/v1/models
```

`OPERATOR_MODELS_DIR` can point to a prepared directory instead. `up` does not
download weights or an image; damaged or missing files fail before startup.
Only localhost port 8082 is published. The service has a dedicated Docker
internal network, read-only root/weights, unprivileged UID, no capabilities,
no privilege escalation and bounded PID/CPU/RAM. It has no Docker socket,
host filesystem tools, external MCP or provider credentials. Offline mode is
also passed to llama-server. It runs four CPU threads, zero GPU layers and a
7-GiB memory ceiling; Docker Desktop needs adequate free memory in addition
to existing containers. This ceiling is not a measured model peak or promise
of latency. A failure must be reported, without changing quantization/context
or silently switching to hosted inference.

On this Docker Desktop version, internal-only networks do not publish host
ports. A credential-free fixed-target gateway therefore publishes localhost
8082 while the model stays on its internal network. The gateway uses an exact
already-present local Python/API image ID; this workstation profile is not a
portable release image. Its script denies foreign browser origins and open
proxy/CONNECT requests. The gateway alone has an ingress bridge; the model
has no default route. The console stack uses the same ingress pattern.

For a host API/worker use:

```sh
export OCTO_OPERATOR_ENABLED=1
export OCTO_OPERATOR_WORKER_ENABLED=1
export OCTO_OPERATOR_PROVIDER=local
export OCTO_OPERATOR_MODEL=Qwen3.5-9B-Q4_K_M
export OCTO_OPERATOR_BASE_URL=http://127.0.0.1:8082/v1
python -m api.services.local_operator.worker
```

These settings must also be applied to the API process, with its normal
PostgreSQL/session/artifact configuration. Starting inference alone does not
start or migrate the API or worker and does not enable another running
installation. For a containerized API/worker, explicitly provision a trusted
private IP endpoint and networking; the adapter deliberately rejects arbitrary
hostnames and public local-mode endpoints. Do not publish inference publicly.
The `/operator` console uses the authenticated API and separate durable worker;
it never calls llama-server directly. The status endpoint continues to report
`not_checked` until runtime readiness is actually checked by that installation.

Stop only this deployment with `bash scripts/operator-mac.sh down`. The model
directory is retained. For upgrades, prepare separately verified versioned
weights and image, stop inference after draining its worker, then change the
pinned deployment and restart; rollback uses the previous pair. The general
[bundle verifier](local-operator-bundle.md) supports stricter multi-artifact
trust manifests for the later full runtime/embedding distribution.
