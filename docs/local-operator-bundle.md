# Offline operator bundle integrity and launch

## Complete Mac workstation package

`scripts/operator-offline-bundle.py` packages the primary Mac profile as a
directory: exact Git source, compiled UI, Qwen3.5-9B Q4_K_M and CPU embedding
GGUF weights, cached arm64 runtime/application/PostgreSQL images, licenses,
required image SBOM and an additional SPDX file inventory. This is distinct
from the native executable manifest below. The script does not download inputs.

Prepare inputs on a connected staging workstation. Compile the UI from the
same exact commit as `--source-ref`; the exporter checks the supplied revision
binding, while the administrator attests the build provenance. Generate the
image SBOM against all three exact cached image IDs, using an approved scanner
such as Syft; include each image ID and transitive package inventory in the
JSON document. The required wrapper is `{"schema_version":1,"images":{` followed
by each exact `sha256:...` image ID mapped to its complete SPDX 2.2/2.3 document
with nonempty `packages`, or CycloneDX document with nonempty `components`.
Close both objects with `}}`. Verification requires all three exact image IDs;
inventory completeness and scanner provenance still require review. A file
inventory does not replace an image SBOM. Review upstream
runtime, Qwen, embedding and image licenses, and pass every applicable license
using repeated `--license` flags. Apache guidance licensing and provenance are
included in the source catalog. The complete package requires `--feeds` with
the actual local native feed tree and its enrichment manifest. Export snapshots
it privately and regenerates only that copy's metadata; it never refreshes or
rewrites the input directory. The four native core datasets (CVSS4, EPSS, KEV,
exploit) and manifest must exist and contain entries. Available optional vendor,
CPE, geolocation and ASN data are carried too; missing optional data remain
explicitly missing. Unsupported paths, links, empty required datasets and
unbounded/malformed required JSON headers are rejected.

`feed-inventory.json` separately records each payload's byte size/SHA-256 and
dataset-stamped source/date. Import checks these hashes against `feeds.tar`
before Docker load, verifies native metadata against bounded actual headers,
and cross-checks the regenerated enrichment manifest. Up to 32 MiB per JSON
dataset is fully parsed for entry counts; larger optional files carry unknown
counts/coverage. Snapshot time never substitutes for an absent feed date.
Age over thirty days is stale; missing/future/invalid dates are unknown.
Seed or insufficient coverage stays unknown even with a recent date. A carried
`source_origin=stale` remains stale across another offline snapshot. Native
writer locks and installation history are not distributed as knowledge data;
an unfinished installation journal or other unsupported files must be resolved
before export. These
package inventory labels do not replace each runtime consumer's own freshness
and applicability policy. `coverage_complete` is always false: having all
available bytes offline does not establish a fresh or complete knowledge base.

```sh
python scripts/operator-offline-bundle.py export \
  --destination .operator-local/bundle/release --source-ref "$REVISION" \
  --ui-source-revision "$REVISION" --ui ui/out \
  --model "$MODEL_GGUF" --model-revision "$MODEL_REVISION" \
  --model-sha256 "$MODEL_SHA256" --embedding "$EMBEDDING_GGUF" \
  --embedding-revision "$EMBEDDING_REVISION" --embedding-sha256 "$EMBEDDING_SHA256" \
  --runtime-image "$PINNED_RUNTIME" --app-image "$PINNED_APPLICATION" \
  --postgres-image "$PINNED_POSTGRES" --image-sbom "$IMAGE_SBOM" \
  --feeds "$LOCAL_NATIVE_FEED_DIRECTORY" \
  --license "$RUNTIME_LICENSE" --license "$MODEL_LICENSE" --license "$EMBEDDING_LICENSE"
python scripts/operator-offline-bundle.py verify .operator-local/bundle/release \
  --manifest-sha256 "$INDEPENDENTLY_TRUSTED_MANIFEST_SHA256"
python scripts/operator-offline-bundle.py import .operator-local/bundle/release \
  --manifest-sha256 "$INDEPENDENTLY_TRUSTED_MANIFEST_SHA256" \
  --destination .operator-local/restored-workstation --start
```

Transfer the printed manifest SHA through a separately authenticated channel.
Do not treat a digest next to an untrusted download as provenance. Verification
hashes every payload before tar parsing, Docker load or startup. It rejects
unlisted files, symlinks, hard links, traversal, devices, duplicate paths and
oversized payloads. Only a new destination is accepted. Import copies and
rechecks the payloads before loading images and verifies their IDs and arm64
architecture. `--without-docker-load` performs materialization only and cannot
start services. Bounds are 32 GiB total payload, 16 GiB per file, and 1 GiB
expanded source/UI archive, 4 GiB for the native feed tree (matching its
existing enrichment-bundle bound), and 30,000 members per archive.

Fresh startup creates a random private Compose project, internal network and
new private credentials, migrates PostgreSQL, starts the bounded model and CPU
embedding services, API/worker and compiled UI gateway on loopback port 8085.
Models have no published ports or external network. The fresh instance enables
operator reads and embeddings; scan start remains disabled. Startup checks
authenticated operator status and UI delivery. After both model containers
start, the importer inspects their exact image IDs/revision, complete command
lines, nonroot identity, read-only filesystem and model volume, absence of
published ports, and ownership of their single internal network. It binds this
record to the already hashed immutable imported model payloads and mounts the
atomic integrity record read-only into recreated API/worker containers.
Before startup, both GGUF payloads are streamed into a new project-owned local
Docker volume, with source and destination SHA-256 checks. A second read-only
helper rehashes the destination files and verifies their sealed modes and local
volume identity. Models mount that volume read-only at `/models`; startup
attestation checks both actual mounts and repeats the destination verification.
The helper uses no network, Docker socket or host model bind. This moves model
I/O off the Mac shared filesystem without changing weights, context or sampling;
it is not by itself proof of performance. IPv6 is disabled in both model
namespaces and the importer verifies those sysctls.
The startup check requires `runtime_status=ready` and `analysis_available=true`,
including live model and embedding health. It does not rehash models during
inference. Model quality, actual traffic
capture and restore correctness require recorded acceptance drills.

### Deployment profile and egress

The imported API and the loopback console stand
(`scripts/operator-console.py`) run with `OCTO_ENV=prod`: fresh JWT, master-key
and database secrets are generated per installation (chmod 600), and the API's
production validator accepts the configuration without the development
escape hatch. `OCTO_REFRESH_COOKIE_SECURE=true` is kept although the console is
served over plain `http://127.0.0.1`; Chromium and Firefox treat loopback as a
secure context, Safari may drop the refresh cookie (the session then ends with
its first access token, use another browser). `OCTO_HSTS_ENABLED=false`
because browsers ignore the header over http. The state and output directories
are mode 0700 and owned by the image user (uid 1000) when the importer may
chown; otherwise they stay with the invoking user and the control containers
run as that uid:gid. They are never world-writable. A failed export/import
deletes its destination only if it is still the directory that call created.

Before the first `docker compose up` the importer re-reads the written
`app.env` and refuses to start (`bundle_offline_profile_external_provider`,
`bundle_offline_profile_inference_outside_network`) unless the provider is
`local`, `OCTO_OPERATOR_ALLOW_EXTERNAL=false` and both inference URLs are IP
literals inside the isolated subnet. Egress itself is enforced by the compose
`internal` network; this check only stops a misconfigured hosted provider from
being started.

The loopback ingress (`scripts/operator-console-proxy.py`) accepts only a
single `Host` header naming a loopback authority on the stand's ports (a
foreign or missing `Host` gets 421, which blocks DNS rebinding), and the two
model targets forward only `/health`, `/v1/models`, `/v1/chat/completions` and
`/v1/embeddings` with their expected methods; llama.cpp's other routes (`/props`,
`/slots`, `/metrics`, `/tokenize`, ...) answer 404. The API ingress still
serves the console and API paths.

**Kubernetes is not supported for the local operator.** `k8s/` deploys no
inference runtime, operator worker or `OCTO_OPERATOR_*` settings, so there is
no NetworkPolicy to add and none is shipped; LO-09 (no external egress) holds
only for this compose profile. A future k8s deployment must add an egress
NetworkPolicy for the API and worker pods allowing only the inference and
embedding endpoints (plus DNS and Postgres) before the operator is enabled there.

Stop only that imported project, retaining its database, model volume and artifacts:

```sh
python scripts/operator-offline-bundle.py stop .operator-local/restored-workstation \
  --manifest-sha256 "$INDEPENDENTLY_TRUSTED_MANIFEST_SHA256"
```

Keep the previous immutable bundle and backed-up installation for rollback;
never update weights or database files in place. Use the
[recovery drill](local-operator-recovery-drill.md) to validate cancellation,
restart, database/artifact restore, schema rollback and feature disable.

## Native executable manifest

The verifier and launcher are implemented for #585. No runtime binary, model
weights, tokenizer, CUDA library, embedding runner or license is downloaded or
redistributed by this repository. A verified manifest is an integrity result;
it is not a model quality, CUDA compatibility or hardware acceptance result.

An administrator prepares an unpacked, immutable directory on a connected
staging station. Do not import archives through the operator API. Include the
exact runtime executable and its support libraries, Qwen3.5-9B GGUF Q4_K_M,
the matching chat template, Qwen3-Embedding-0.6B CPU weights, tokenizer/support
files and all applicable licenses. The artifact roles `runtime`, `model`,
`template`, `embedding` each occur once; additional files use `support` or
`license`. Split or multi-file embedding weights can use support entries.
Every file must be listed. The verifier checks listed artifacts; the deployer
must ensure the runtime cannot load unlisted libraries or configuration.

`manifest.json` follows the strict `Manifest` model in
`api/services/local_operator/bundle.py`. Its fields are:

| Field | Value |
|---|---|
| schema_version | 1 |
| model | Qwen3.5-9B-Q4_K_M |
| model_revision / runtime_revision / embedding_revision | Immutable 40-character upstream commit IDs |
| embedding_model | Qwen3-Embedding-0.6B |
| context_tokens / parallel | 8192 / 1 |
| Mac inference RAM prompt cache | disabled (`--cache-ram 0`), required by startup attestation |
| artifacts | Each contains path, role, exact positive byte size, lowercase SHA-256 |

Paths must be relative, with no dot segments, symlinks, empty segments, shell
syntax or option-like components. The manifest is limited to 64 KiB and 128
files; each file to 12 GiB and the total to 18 GiB. These are import bounds,
not measured RAM/disk requirements. The template digest is covered by the
same independently trusted manifest digest as the model. A hash supplied
beside an untrusted download does not establish provenance.

Obtain the manifest SHA-256 through separately authenticated release metadata
or an administrator-approved offline trust transfer. Run as a non-root user,
with the bundle read-only and owned by a deployment identity that the runtime
cannot modify:

```sh
python -m api.services.local_operator.bundle /opt/shapoclyack-model \
  --manifest-sha256 "$TRUSTED_MANIFEST_SHA256"
python -m api.services.local_operator.bundle /opt/shapoclyack-model \
  --manifest-sha256 "$TRUSTED_MANIFEST_SHA256" --launch
```

Verification streams and hashes all files before any executable is invoked.
The bundle must remain immutable during verification and execution; this is
not a sandbox against a concurrent privileged writer. On a missing file,
hash mismatch, invalid baseline or malformed manifest, launch fails closed.
The launcher uses `execve`, retains signal delivery, clears inherited provider
credentials, proxies, preload hooks and `LLAMA_ARG_*` overrides, fixes loopback
port 8082 (configurable unprivileged port), one inference slot, 8192 context,
1024 output tokens, all available GPU layers, offline mode and disabled Web UI.
It does not enable tools, remote MCP servers or model auto-download.
Set `OCTO_OPERATOR_BASE_URL=http://127.0.0.1:8082/v1` for the API/worker on
the same network namespace. No hosted fallback is introduced. This executable
launcher is distinct from the primary Mac container profile; physical NVIDIA
acceptance is tracked in #609.

Flags follow the [upstream llama-server interface](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).
The pinned runtime must support these flags; its actual model/template
compatibility must be recorded in the acceptance report. Asking for all GPU
layers is not proof they fit. The launcher does not execute CPU embeddings;
the Mac profile measures semantic retrieval with a separate CPU embedding
container. That evidence does not establish this executable launcher's GPU
acceptance.

The deployment must enforce an OS/container egress deny policy around runtime
and index, while allowing only the authenticated local worker to reach
inference. Loopback binding and `--offline` do not replace network evidence.
For physical acceptance record GPU SKU, driver/CUDA, exact revisions/digests,
actual loaded layer count and total device VRAM, 30 sequential requests and a
60-minute run, full 8192-token usage, failures/TTFT/throughput/latency, CPU
embedding memory and offline cold-start packet/deny counters. A passing tiny
fixture verifier test supplies none of these measurements.

Upgrade by staging and verifying a separate versioned immutable directory,
draining the worker, stopping runtime, switching the deployment path and
restarting. Roll back to the previous trusted manifest/directory using the
same sequence. Do not update weights in place. Disable operator flags and stop
its worker/runtime to remove inference; ordinary scanner service remains
independent. Backup/restore and version switches need deployment drill evidence
before #585 or #593 can close.
