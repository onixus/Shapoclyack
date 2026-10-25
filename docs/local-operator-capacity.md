# Exact 8K runtime capacity measurement

`scripts/operator-capacity.py` sends a real full-budget request to the pinned
local runtime: **8064 input tokens plus 128 generated tokens = 8192 tokens**.
The `/tokenize` endpoint produces valid vocabulary IDs from benign synthetic
text; repeating those IDs fills the input exactly. A numeric token prompt does
not insert an additional BOS token. The native request disables prompt-cache
reuse, ignores EOS for the bounded 128-token output and streams token IDs.
No request is retried, no source context is shortened and runtime context stays
8192. The stress deadline is separate from the ordinary 120-second task budget.

The primary Mac CPU measurement retained under
`.operator-local/evaluation/capacity-8k-001` processed all **8064** input tokens
without cache reuse and produced exactly **128** streaming/native output
tokens. Native prefill took **258.90 seconds** (31.15 tokens/s), first actual
generated token arrived at **258.91 seconds**, and total time was **272.24
seconds** (native decode 9.56 tokens/s). These are full-capacity stress timings,
not the typical-task p95 or a language-quality score. Both inference and CPU
embedding services were loaded for the accompanying resource observation.

## Pinned native boundary semantics

The native response reports `truncated: true` at this exact boundary. This is
retained explicitly, not rewritten to false. In runtime revision
`8e5a58df87ab59dfceb5b961ae26691e39f30c24`, the
[context guard](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-context.cpp#L2142)
checks `prompt.n_tokens()+1 >= n_ctx` **after sending the sampled token and
before checking the exhausted generation budget**. For the last token in this
request it sees `8191+1 >= 8192`; it therefore marks a boundary stop even though
all 128 requested outputs have already been produced.

The proof does not rely on the requested input count alone:

- Native `timings.prompt_n=8064` maps directly to the
  [actual processed counter](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-common.cpp#L139).
  The counter increments for real prompt tokens in
  [post-decode batches](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-context.cpp#L5024).
- `cache_n=0` confirms the complete cold prefill. Every generated token is
  independently counted in SSE; native `tokens_predicted=128` agrees.
- Final `tokens_cached=8191` equals `8064+127`: the final sampled output needs
  no subsequent input decode. A real discard/shift would reduce this intact
  cache. The separate
  [context-shift branch](https://github.com/ggml-org/llama.cpp/blob/8e5a58df87ab59dfceb5b961ae26691e39f30c24/tools/server/server-context.cpp#L3660)
  is not what produced this result.

The scorer therefore classifies this exact, independently verified condition
as **`capacity_boundary_stop`**, preserving `native_truncated: true`. It still
fails on one missing processed input, any cached input in this cold test,
short output, an insufficient/shifted cache, different context/model profile or
an unrecognized runtime's boundary flag. The special interpretation is pinned
to the exact audited runtime image; it is not a blanket exception for a
truncation flag.

Native prompt-progress SSE frames also contain a dummy token. They are not
generated output and must not count as first-token latency. The corrected
parser requires a positive decoded-token counter and excludes progress frames.
The original report and first strict-flag failure remain preserved. Corrected
reports were recomputed from the **same captured request/stream**, with zero
additional model calls. Producer-source and analysis-source hashes, raw-event
hashes, exact upstream source copies and the original-report hash accompany
the evidence under `boundary-verified`, `boundary-evidence.json` and
`upstream-source`.

## Reproduction

Run serially after runtime readiness and with external resource/network
observation enabled. Inside the internal network:

```console
python scripts/operator-capacity.py --base-url http://172.30.83.2:8082 \
  --provenance-json /artifacts/verification.json \
  --output /artifacts/capacity-unique --timeout-seconds 780
```

The provenance file must attest the pinned model and context8192/parallel1/
temperature0/seed42 profile. Native stress evidence alone does not establish
authorization, model-domain quality, no-OOM across an hour, network isolation
or a NVIDIA result. Those require the separate exact-build reports.
