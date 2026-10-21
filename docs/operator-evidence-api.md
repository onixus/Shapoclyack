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
  empty JSON object `{}`. It refreshes only derived local evidence and does not
  invoke a model or fetch a client-supplied URL.
- `GET /api/operator/evidence/SOURCE?tenant_id=default&snapshot_id=SNAPSHOT&source_hash=HASH`
  opens a citation only when its current source still matches the supplied
  snapshot and lowercase SHA-256 digest. Both arguments are required.

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

`tests/test_operator_evidence_api.py` exercises these authorization and source
integrity boundaries against PostgreSQL. The tests require a migrated, isolated
database supplied through `OCTO_POSTGRES_URL`.
