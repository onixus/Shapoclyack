# Operator evidence API

The evidence API is available when `operator_enabled` is enabled. Every request
requires a current console session and an explicit nonblank `tenant_id`. Tenant
viewer roles may search and open citations; operator roles may refresh the derived
index. Ordinary service tokens are rejected, including tokens with wildcard scope.

- `GET /api/operator/evidence/search?tenant_id=default&run_id=RUN` searches the
  tenant's derived index. Optional `query` is limited to 256 characters, `cve`
  matches `CVE-YYYY-NNNN…`, `package` is a bounded exact package token, and `limit`
  is 1–10. Unknown and repeated query arguments are rejected.
- `POST /api/operator/evidence/runs/RUN/refresh?tenant_id=default` requires the
  empty JSON object `{}`. It refreshes derived local evidence. With explicitly
  enabled embeddings it also builds the pinned local CPU vector index; it never
  fetches a client-supplied URL or changes scan/finding state.
- `GET /api/operator/evidence/SOURCE?tenant_id=default&snapshot_id=SNAPSHOT&source_hash=HASH`
  opens a citation only when its current source still matches the supplied
  snapshot and lowercase SHA-256 digest. Both arguments are required.
- `GET /api/operator/evidence/runs/RUN/summary` opens a direct run-summary
  citation with the same required tenant/snapshot/hash bindings.
- `POST /api/operator/evidence/devices/DEVICE/refresh` builds a typed current
  inventory/advisory corpus from the existing remediation cards. The body is
  `{}` and `tenant_id` remains required.
- `GET /api/operator/evidence/devices/DEVICE/search` accepts `query`, exact `cve`
  and `package`, `source_kind=inventory|advisory`, and `limit=1..10`. It returns
  separate document references, never a claim that the complete device is safe.
- `GET /api/operator/evidence/devices/DEVICE/sources/SOURCE` requires
  `snapshot_id`, `source_hash` and `tenant_id`; source/feed/inventory bindings are
  revalidated through the existing deterministic remediation resolver.

Indexes belong to a tenant, so readers in the same tenant share evidence rather
than inheriting somebody else's personal conversation. Responses expose bounded
structured context, source digests, timestamps, citation identifiers, and index
state. They do not expose arbitrary source URLs, banner text, source titles, or
raw artifact metadata. Retrieval state and semantic status describe the available
index; they do not assert model quality or successful inference.

Each operation rechecks the console session family, account, active tenant and
current role before retrieval and again before returning the result. A held
request cannot return evidence after its session family is revoked or its account
is deleted and recreated. Citation retrieval also revalidates live source
eligibility and content hashes, so mutation, deletion or ownership changes cannot
turn an old snapshot into current evidence. Source changes return `409`, missing
or ineligible sources return `404`, invalid arguments return `422`, and revoked
console authority returns `403`.
Enabled but unavailable embedding runtime/index returns `503` for hybrid search.
Exact identifier/filter reads remain explicit `mode=exact_fulltext` and report
their actual semantic index status. Vector readiness is not model-quality or
coverage acceptance; see the [retrieval guide](local-operator-retrieval.md).

`tests/test_operator_evidence_api.py` exercises these authorization and source
integrity boundaries against PostgreSQL. The tests require a migrated, isolated
database supplied through `OCTO_POSTGRES_URL`.
