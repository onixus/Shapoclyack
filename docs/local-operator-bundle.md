# Offline operator bundle integrity and launch

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
the same network namespace. No hosted fallback is introduced.

Flags follow the [upstream llama-server interface](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).
The pinned runtime must support these flags; its actual model/template
compatibility must be recorded in the acceptance report. Asking for all GPU
layers is not proof they fit. The launcher does not execute CPU embeddings;
semantic retrieval remains a separate unaccepted component.

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
