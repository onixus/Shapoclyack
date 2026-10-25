# Operator evidence index (#587)

The tenant-owned PostgreSQL index retains only bounded observations from a
completed, published run: whitelisted integer summary counts and scalar fields
from `vulnerabilities.json`. CVE, CWE, host, numeric port, service, severity,
asset_id, package and version are retained only when explicitly supplied with a
restricted token syntax. No title, raw banner, credentials, markdown, raw evidence,
arbitrary file or remote URL enters this index. Source time is artifact storage
modification time; it does not establish observation freshness.

Refresh atomically replaces the tenant/run snapshot and all documents within one
transaction. Tenant locking serializes refresh; legal holds forbid replacement.
Each document records source hash, document hash, source time, snapshot and index
time. Search and citation opening recheck publication eligibility and both source
fingerprints. Changed or deleted artifacts are refused until a new refresh.
Previously indexed chunks cannot be used after source deletion. Maintenance can
prune stale snapshots; legal holds preserve stored data while reads still fail.
Tenant deletion and run retention must also remove these derived tables.

CVE and package equality preserves the supplied identifier without guessing
numeric versions. PostgreSQL `simple` full-text search supplements exact matches.
An optional pinned local CPU embedding index now supplements these operations;
it remains disabled by default. An exact CVE query uses equality only, so a
nearby vector cannot replace a missing identifier. Explicit CVE/package filters
apply before ranking, and exact package matches precede semantic neighbors.
All results remain partial observations rather than assertions of scan coverage.
Missing findings are marked `missing`; oversized files and row/context caps are
marked `truncated`. Invalid findings remain partial; zero indexed findings never
means a clean scan. Limits: 2 MiB findings file, 1000 finding rows, 50 results,
512 query characters and 24000 output context characters.

Every API/worker call must additionally perform current actor authorization.
Tenant ownership of evidence does not grant personal conversation access.
Tests with fixed vectors establish storage, ranking and authority behavior, not
model retrieval quality. The explicit real-runtime gate below records its own
measurements independently of these tests.

## Pinned local CPU embeddings

`EmbeddingConfig` accepts only a configured loopback or private IP-literal
endpoint. No DNS hostname, credentials, redirect, environment proxy, external
provider, automatic model download or fallback is supported. The deployment
owns CPU placement and verifies its model/runtime artifacts before startup;
an OpenAI-compatible response cannot attest the installed weights.

| Setting / `OCTO_` environment suffix | Default / requirement |
|---|---|
| `OPERATOR_EMBEDDINGS_ENABLED` | `false` |
| `OPERATOR_EMBEDDINGS_BASE_URL` | `http://127.0.0.1:8084/v1` |
| `OPERATOR_EMBEDDINGS_MODEL` | `Qwen3-Embedding-0.6B`, fixed alias |
| `OPERATOR_EMBEDDINGS_REVISION` | Required 40-digit lowercase revision when enabled |
| `OPERATOR_EMBEDDINGS_MODEL_SHA256` | Required 64-digit lowercase artifact digest when enabled |
| `OPERATOR_EMBEDDINGS_DIMENSIONS` | `1024`; every returned/stored vector is checked |
| `OPERATOR_EMBEDDINGS_TIMEOUT_SECONDS` | `30`, at most 60 per call |
| `OPERATOR_EMBEDDINGS_MAX_RESPONSE_BYTES` | `2097152` per batch |

The Mac bundle pins official Qwen GGUF revision
`370f27d7550e0def9b39c1f16d3fbaa13aa67728`,
`Qwen3-Embedding-0.6B-Q8_0.gguf`, SHA-256
`06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439`.
See [Mac runtime configuration](local-operator-mac.md).

Only normalized CVE/CWE/package/version/service/severity/port/count fields reach
embedding inference. Inventory/advisory documents additionally carry bounded
distribution/release/architecture/vendor-advisory identifiers. Hostnames, IPs,
asset/console identities, titles, banners, commands, arbitrary descriptions,
source URLs and nested raw evidence are excluded. A fixed source-kind label and
query instruction are versioned through the encoder fingerprint. Query text is
bounded and sent only to the configured local runtime. Audit receipts commit
source-corpus/query digests and model identity before inference; they contain no
prompt text or vectors.

Requests use batches of at most **4**, at most 2048 characters per document,
and a **60-second whole-build deadline**, including slow response bodies. There
is no partial vector publication: timeout, OOM, wrong model/dimension, nonfinite
or zero vectors and provider failure leave the new index unavailable. Existing
exact source records remain separate. Explicit exact-filter reads report their
mode and `semantic_status`; a requested hybrid search fails with `503` when its
enabled model/index is unavailable instead of silently claiming semantic success.

## Durable source-scoped index

Migration `0102_operator_semantic` adds `operator_embedding_indexes` and
`operator_evidence_embeddings`. A corpus is keyed by tenant, typed source scope,
source snapshot, model artifact/revision, vector dimension and encoder version.
Completed vector sets replace predecessors atomically under the tenant lock.
Vectors and minimized full-text content are PostgreSQL JSON/text data; no
external vector service or optional database extension is required. With the
existing 1000-finding cap, a run has at most 1001 documents including its summary.

Hybrid search combines PostgreSQL full-text rank and bounded cosine rank by
reciprocal rank fusion; exact identifiers retain precedence. Candidate reads,
vector lookups and result contexts remain in the current tenant/source scope.
Source hashes and the current corpus are checked again after embedding calls.
The model never compares software versions or determines fixed-version truth.

`run` scope indexes completed published run observations. `device_remediation`
scope indexes separate **inventory** and **advisory** documents derived from the
existing current vendor-backed remediation cards. It covers assessed package
matches, not every installed package or every advisory in a feed. Missing,
unsupported, stale or unverified cards are excluded before inference; no eligible
source returns explicit `unknown`/`stale` with `semantic_status=no_eligible_sources`.
Device corpus snapshots hash both accepted inventory identity and current feed
provenance. Opening a citation re-resolves the current card and original
remediation-source bindings; it cannot turn an old feed or inventory snapshot
into current evidence.

Composite tenant foreign keys and RLS protect the new tables. Run/inventory
snapshot deletion cascades to their vectors. Rotating maintenance prunes changed
source corpora; legal hold retains inaccessible old indexes. Tenant purge lists
these tables before their parents. Disabling embeddings does not expose cached
vectors or perform inference.

## Real-model retrieval measurement

`tests/fixtures/operator_retrieval_eval.json` is frozen at SHA-256
`d18074d87edc89d9e646c8cfe9d46ab4dc4dc6076ba3cc5bb153b1c0b3790092`:
120 synthetic run observations and 180 cases: 60 natural-language run queries,
60 exact CVE/package lookups, and 60 inventory/advisory queries in Russian/English.
The vendor-card fixtures are synthetic; this benchmark measures retrieval, not
vendor-feed coverage, model category accuracy or remediation correctness.

On an isolated migrated PostgreSQL database, explicitly set
`OCTO_OPERATOR_EMBEDDING_ACCEPTANCE=1` and run
`tests/test_operator_retrieval_live.py`. The local runtime URL may be supplied as
`OCTO_EMBEDDING_ACCEPTANCE_URL`; `OCTO_OPERATOR_RETRIEVAL_REPORT` selects the JSON
report path. Ordinary CI skips this test without the explicit runtime flag.
The frozen gates are recall@10 **>=0.90** on natural queries and **100%** exact-ID
hits. Failures remain in the denominators and raw records. The report includes
RU/EN splits, returned source bindings, index/query timings, PostgreSQL index
bytes, client-harness peak RSS, model pins and source-code hashes. Runtime peak
RAM/CPU placement and offline network evidence come from the separate deployment
report. A fixture-only pass does not satisfy this real-runtime gate.
