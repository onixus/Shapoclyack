# Separate inference container on Mac

The owner requested this workstation profile on 2026-10-25. It uses a separate
Linux ARM64 CPU container on Docker Desktop. It retains Qwen3.5-9B Q4_K_M,
8192 total context tokens and one inference slot. This is the primary acceptance
profile under [ADR 0005](adr/0005-local-operator-mac-acceptance.md).
Linux/NVIDIA 8-GiB acceptance is separate [#609](https://github.com/onixus/Shapoclyack/issues/609).

Pinned inputs:

| Input | Immutable value |
|---|---|
| llama.cpp image index | `ghcr.io/ggml-org/llama.cpp:server@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44` |
| Runtime source revision | `8e5a58df87ab59dfceb5b961ae26691e39f30c24` (b11854) |
| Model repository | `unsloth/Qwen3.5-9B-GGUF` |
| Model revision | `3885219b6810b007914f3a7950a8d1b469d598a5` |
| Artifact | `Qwen3.5-9B-Q4_K_M.gguf`, 5680522464 bytes |
| Artifact SHA-256 | `03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8` |
| CPU embedding model | `Qwen/Qwen3-Embedding-0.6B-GGUF` at `370f27d7550e0def9b39c1f16d3fbaa13aa67728`, Q8_0 |
| Embedding SHA-256 | `06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439` |

The model digest and size were taken from the upstream repository's HTTPS
LFS metadata at that revision, rather than calculated from an untrusted
download and treated as its own trust anchor. Upstream advertises Apache-2.0;
retain applicable license metadata with offline transfers. The GGUF's embedded
tokenizer/chat template are covered by the model file hash. No image projector
is loaded. See [model metadata](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/tree/3885219b6810b007914f3a7950a8d1b469d598a5)
and [runtime source](https://github.com/ggml-org/llama.cpp/tree/8e5a58df87ab59dfceb5b961ae26691e39f30c24).

```sh
# Connected staging only: downloads about 6.32 GB plus the runtime image.
bash scripts/operator-mac.sh download
# Stage sealed GGUF bytes into a Docker-local volume without starting models.
bash scripts/operator-mac.sh stage
# Offline startup freshly verifies the native volume and refuses image auto-pull.
bash scripts/operator-mac.sh up
bash scripts/operator-mac.sh ps
curl --fail http://127.0.0.1:8082/health
curl --fail http://127.0.0.1:8082/v1/models
```

`OPERATOR_MODELS_DIR` can point to a prepared directory instead. `up` does not
download weights or an image; damaged or missing files fail before startup.
The default `OPERATOR_MODEL_STORAGE=native` uses
`compose.operator-mac.native.yml` (Docker Compose >=2.24.4). Both model processes
mount the same Docker **local** volume at `/models:ro`; their model paths,
quantizations, 8192-token context and four inference threads stay unchanged.
GGUF source bytes are streamed through Docker stdin in 1-MiB chunks, with a
source SHA-256 and an independent read-only destination readback. No GGUF host
file is mounted through VirtioFS in this profile. This is a storage hypothesis
under evaluation, not evidence that latency or model quality passed.

`OPERATOR_MODELS_VOLUME` may explicitly select an existing product-owned local
volume. Reuse freshly checks both host source hashes and destination hashes;
it never overwrites existing GGUF bytes. Driver options, foreign ownership,
writable attachments (including stopped containers), symlinks, extra/partial
files or a checksum mismatch refuse startup. Two canonical destination files,
`model.gguf` and `embedding.gguf`, are sealed mode `0444` under a `0555`
directory. A network-none, capability-free helper performs staging/readback;
no Docker socket or source host directory is mounted into it. Helpers are
removed before the final read-only readback and atomic fsynced receipt is
published at `.operator-local/runtime/model-storage.json`.
The copy helper has a 512-MiB ceiling and flushes/fsyncs in 8-MiB batches,
dropping clean Linux page-cache ranges after each batch. Readback uses a
128-MiB helper. Fixed helper stderr/exit/OOM state is captured before owned
cleanup on failure; no receipt is published. These staging budgets and the
readback helper's measured process RSS are not model inference memory peaks.

`operator-runtime-manifest.py` then verifies the actual container mount type,
volume identity, read-only flag and `/models` destination against a fresh
readback. A volume name or old receipt alone provides no integrity claim.
Docker administrators can still mutate volumes; this is not protection from a
concurrent privileged Docker operator. Failed/new or reused volumes are never
automatically deleted, and `down` preserves the external weight volume.
Explicit `OPERATOR_MODEL_STORAGE=bind` retains the host-bind diagnostic profile;
its results do not establish native-volume acceptance. No global Docker or
host settings are changed.

Only localhost ports 8082 (language) and 8084 (embeddings) are published through
fixed-target gateways. The services have a dedicated Docker
internal network, read-only root/weights, unprivileged UID, no capabilities,
no privilege escalation and bounded PID/CPU/RAM. It has no Docker socket,
host filesystem tools, external MCP or provider credentials. Offline mode is
also passed to llama-server.

The two model namespaces disable IPv6 through `all` and `default` sysctls;
the fixed endpoints use IPv4. Startup attestation checks this policy. This
prevents unsolicited IPv6 neighbor/multicast traffic rather than exempting
unclassified packets from the offline observation gate.

It runs four CPU threads, zero GPU layers and a
7-GiB memory ceiling; Docker Desktop needs adequate free memory in addition
to existing containers. This ceiling is not a measured model peak or promise
of latency. A failure must be reported, without changing quantization/context
or silently switching to hosted inference.

Inference explicitly sets `--cache-ram 0`; startup attestation requires exactly
this value, including for the offline package. The pinned runtime otherwise
defaults to an 8192-MiB RAM prompt-cache budget (with a decision-model exception).
The 2026-10-26 attempt under a 16-GiB Docker VM hit the model's 7-GiB memory
cgroup and restarted. Disabling that cache is a single-variable diagnostic
change; its contribution to anonymous-memory growth and the revised profile's
quality, latency and hour-long stability remain unverified. Context, weights,
parallelism, threads and the container memory ceiling remain unchanged.
The observer now retains selected `memory.stat` bytes (including anonymous,
file and slab memory), `memory.current`, peak and events in each sample.
PID1 start ticks bracket each read to reject mixed restart epochs; counter
files are sequential rather than an atomic snapshot. Reads have a five-second
timeout and failures stay visible. Earlier samples are not replaced by the
new process's counters after a restart.

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
it never calls llama-server directly. Successful `up` waits for both model health
checks and emits `.operator-local/runtime/verification.json`, binding verified
weight digests to inspected runtime configuration. `operator-console.py init`
pins that record's SHA and mounts it read-only; status then checks live health,
model alias and context. A host deployment can set
`OCTO_OPERATOR_RUNTIME_MANIFEST_PATH` and `OCTO_OPERATOR_RUNTIME_MANIFEST_SHA256`
explicitly. Missing records report `not_checked`; mismatches or health failures
report `unavailable`. Runtime readiness does not change domain-quality status.

Stop only this deployment with `bash scripts/operator-mac.sh down`. The model
directory is retained. For upgrades, prepare separately verified versioned
weights and image, stop inference after draining its worker, then change the
pinned deployment and restart; rollback uses the previous pair. The general
[bundle verifier](local-operator-bundle.md) supports stricter multi-artifact
trust manifests for the later full runtime/embedding distribution.
