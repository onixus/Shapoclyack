# Finding evidence: production integration (#449)

Production reports now retain observations in additive `finding_evidence` fields
inside each legacy remediation container. `finding_key` remains unchanged:
asset/CVE-or-script/port. A container may contain multiple **distinct** precise
subjects; they are not a claim that TCP/UDP, vhosts/SNI or HTTP objects are the
same confirmed object. Counts in reports, run API, tracker and ClickHouse remain
container counts. Evidence counts and subject counts are separate.

The offline sidecar command below remains available for historical artifacts.

## Production compatibility, enablement and rollback

Deploy migration `0087_finding_evidence` before the new API. New reports enable
the additive contract by default; there is no bulk identity migration/backfill
and old `vulnerabilities.json` files remain readable. Existing keys, owners,
SLA deadlines, exceptions and events are preserved. Observations are rebound to
authenticated tenant/run ownership at run API, tracker and analytics boundaries;
uploader group IDs and context cannot assert ownership. A self-consistent hash
is not an authorization or sanitization check: ingestion enforces the exact
observation field allowlist, bounded/redacted text, scalar semantics, canonical
time and subject fields, and at most eight incoming artifact references before
aggregation. Unknown extra fields and unsafe supplied values make evidence
incomplete rather than copying attacker-controlled bodies into API/analytics.

`report_sources.json` preserves the exact input rows and its actual file SHA-256
and JSON pointers are referenced by fallback observations. Available bounded raw
readers add original Pulse/NSE/Nuclei artifact references, matcher, object and
engine evidence. A matching coarse report representation is replaced by its
authoritative raw observation, retaining both exact raw and report-source
references without increasing observation counts. Unmatched rules and conflicting
known transport/SNI/object/time observations remain separate. New source snapshots and sidecars require operator permissions;
raw downloads use the existing run-scoped artifact endpoint and its access rules.
The UI shows observations in run findings and tracker detectors. ClickHouse keeps
one row per container, adding evidence to the existing JSON assessment envelope;
all captured risk receipt fields remain unchanged.

The report chooses a deterministic representative from the latest dated cohort
(or a deterministic undated representative), without source ranking or a
strongest-forever rule. All conflicting/undated observations remain available.
The tracker treats CVE and non-CVE replay identically: replaying already stored
observation IDs unions raw references without incrementing publication counts,
appending duplicate events, reopening a closed task or resetting its SLA. A
strictly older publication for already known precise subjects is stored and
audited as historical; it does not overwrite the current assessment or lifecycle.
Unknown timestamps and newly observed precise subjects are never classified as
historical. A later weaker positive remains actionable.

The tracker unions evidence across runs, idempotently by observation ID, up to
10,000 observations. Invalid supplied evidence and exhausted history bounds set
an explicit incomplete marker; they do not fall back to legacy absence.

Precise HTTP object/SNI/authority, multiple distinct endpoints, or incomplete
evidence blocks negative closure through legacy endpoint coverage. These
containers require operator triage until verification can prove every precise
subject was checked. A new positive observation remains positive even when
another source is partial. Nuclei never implies machine verification.

Rollback: deploy the older report/API code; existing workflow keys and history
are unchanged. Leaving the additive nullable column is safe. Downgrading 0087
drops only evidence history; export it first if required. Historical artifacts
are not automatically regenerated. The real local Nuclei v3.11.1 capture under
`tests/fixtures/finding_evidence` exercises output shape with a fabricated local
CVE template, not real-world detection acceptance. Full release/device/runtime
acceptance and precise-subject negative verification remain separate gates.

## Run against existing artifacts

From a checkout with the repository's Python dependencies installed:

```bash
python scripts/build-finding-evidence.py scanner/output/runs/example \
  --tenant-id example-tenant --run-id example
python -m pytest -q tests/test_finding_evidence.py tests/test_finding_evidence_regressions.py
```

The directory must already exist. The command reads `pulse/raw.json`,
`nuclei_raw.jsonl`, and up to 128 XML files under `nmap/`. It writes only
`finding_evidence.json`, using an atomic replacement and a private temporary
file. It never starts Pulse, Nuclei, Nmap, a network request, or an import into
PostgreSQL/ClickHouse. It does not edit raw artifacts, `vulnerabilities.json`,
`finding_key`, assignments, SLA, exceptions, or remediation history.

Supply the original run's stable ID, not the date of regeneration. Explicit
context overrides row-supplied tenant/run fields. These arguments are **not an
authorization check**: a future API consumer must get tenant/run ownership from
its authenticated, tenant-scoped publication boundary, not from an uploaded
artifact or a caller-provided CLI string.

Exit 0 means available inputs were projected without parse/limit errors, not
that the scan completed. Missing optional engines are listed in diagnostics;
missing *all* inputs, malformed input, unsafe paths or exhausted limits produce
exit 1 and `projection_incomplete: true`. Directory/write errors produce exit 2.
Every result has `coverage: "unknown"`. Neither absence of a source nor an empty
finding list is evidence of remediation.

## Contract and identity

Each `octo.finding_observation.v1` observation records source, nullable engine
and ruleset versions, rule/template and matcher, nullable UTC observation time,
run and tenant, normalized subject, evidence kind, nullable confidence, severity,
a bounded preview and an evidence digest. References carry a relative artifact
path, its content SHA-256, and a JSON pointer, JSONL line or XML element locator.
Raw artifacts must remain available under their original access restrictions;
this projection does not create public download links. Hashes identify content,
not authorship or authenticity.

`octo.finding_evidence.v1` groups observations deterministically by tenant,
subject and CVE. Non-CVE groups additionally retain the source/rule namespace;
this **does not** create remediation tasks from inventory detections (#451).
Group IDs use `evidence:` and observation IDs use `obs:`. Neither ID replaces a
persisted tracker `finding_key`. Run is part of observation identity, not group
identity. Identical observations merge their references without increasing the
observation count. Different evidence, versions or observation times remain
separate. Sorting and duplicates do not change the union.

Subjects retain transport, optional HTTP scheme/authority, explicit SNI and an
object digest. Literal IP spelling, host case and numeric ports normalize.
HTTP default ports normalize, but conflicting explicit ports are rejected.
Directed Nuclei invocations may carry an adapter-owned `shapoclyack_input`
(`octo.nuclei_input.v1`) note because the pinned engine's IP-URL JSONL does not
record per-process Host/SNI flags. The reader requires its literal IP and port to
match the raw observed endpoint; canonical HTTP authority and explicit SNI are
retained separately from transport IP. Authority changes also change the HTTP
object digest, so two virtual hosts on one IP/path remain distinct. Credentials,
URLs/control characters, mismatched endpoints/ports/SNI, and unknown note fields
make the projection incomplete instead of silently falling back to one IP object.
The per-process original raw file remains unchanged; enriched merged JSONL records
contain the adapter assertion. Neither the note nor its hash authenticates an
upload: the existing authenticated publication boundary still owns tenant/run
scope, and archive authenticity validation remains a separate gate.
DNS names are never mapped to IPs from an unverified `ip` field or reverse lookup.
Unknown transport/authority/object is **not** a wildcard: a service-level Pulse
finding cannot automatically absorb a path-specific Nuclei match. Both may be
related later, but only under an explicit, sufficiently precise binding.

URL userinfo and fragments are not included. Path and query are represented by
a digest rather than displayed: they can themselves contain secrets. Exact
path case, percent escapes, query order and duplicate query parameters remain
significant; query-value changes may therefore create different shadow groups.
Do not silently copy that policy into long-lived tracker identity.

An explicit non-empty `affected_object` is also part of HTTP identity: its
opaque digest is combined with the normalized URL-derived object ID, rather
than replacing the URL or being ignored. Two qualifiers on one URL and one
qualifier on two URLs remain distinct. Missing/empty qualifiers keep the
existing URL-only hashes; non-HTTP object hashes are unchanged. No object text
is copied into the projection.

## Evidence and temporal interpretation

Pulse classes map to version match, keyword hypothesis, exposure and TLS
observation. Nuclei produces a template-match observation with its template,
matcher, timestamp and source line. Arbitrary `request`, `response` and extracted
values are not copied. Extracted values affect a digest so distinct evidence is
not erased. NSE CVE mentions remain unverified script reports; raw output is
hashed/referenced but its free-text preview is omitted. This module is not a new
NSE vulnerability detector and does not interpret prose as a verification result.

JSONL records are delimited by LF; CRLF and a final record without a newline
are supported. Blank physical lines still count toward `line:N` references.
Literal U+0085/U+2028/U+2029 inside JSON strings are data, not record boundaries,
including in response bodies which are not projected. Malformed physical
records remain explicit errors without shifting later locators.

No source-name ranking is used. The projection keeps older and newer evidence,
reports differing fields, identifies the latest dated cohort and separately
lists undated observations. It does not choose a risk-score winner, infer the
time of undated observations from filesystem timestamps, or use "strongest
forever" as a state machine. `machine_verified` is always false. Actual negative
verification, sufficient coverage and state transitions remain the tracker's job:
since [#451](https://github.com/onixus/Shapoclyack/issues/451) a verification
closes a finding only when the run's own artifacts show every detector of it
re-checked the endpoint (`api/services/verification_coverage.py`,
[vulnerability-lifecycle.md](vulnerability-lifecycle.md#what-the-run-has-to-show)).

Engine/ruleset versions missing from source data stay null. A Docker pin is not
proof of which executable produced an imported file. Likewise, missing
confidence stays null and explicit zero stays zero. The original stage-1 fixtures
are synthetic. The separate `nuclei_v3_11_1/loopback.jsonl` fixture is real local
engine output; its README records the capture boundary and provenance limits.

## Size and privacy limits

Inputs are bounded at 16 MiB per file, 64 MiB total, 10,000 projected observation
rows and 128 Nmap XML files. Limits are reported rather than turned into a clean
empty result. Each observation keeps at most eight sorted artifact references,
with an explicit truncation flag; the referenced original artifact is unchanged.
The flag is monotonic across re-aggregation: any input copy marked truncated
keeps the merged observation truncated, regardless of order or current length.
A missing flag is accepted for fresh observations; an explicit flag must be a
JSON boolean. Replaying a sidecar cannot reconstruct references already lost.
Previews are capped at 512 characters and labels at 256. Full rule digests keep
long labels from collapsing distinct non-CVE rules after display truncation.

Known authorization/cookie headers and password/token/key fields are redacted
before preview truncation. Quoted values are scanned with escape-aware quote
and backslash handling. Unterminated quotes, ambiguous trailing value text and
structured secret values suppress the remaining preview instead of exposing a
suffix. URLs in free text are omitted. This is not a general
secret detector: even labels and Pulse evidence may contain arbitrary sensitive
text. Treat the sidecar as a restricted run artifact, not as publishable data.
Nmap XML uses the repository's existing `defusedxml` dependency. Paths escaping
the selected directory and direct input symlinks are refused; these checks do
not replace the archive validation/publication boundary in #366 or provide a
transactional snapshot against concurrent filesystem mutation.

## Pre-release shadow compatibility

Regenerate sidecars made with the initial PR #493 revision from their original
raw artifacts. They may contain partially redacted credential values, collapsed
explicit HTTP objects or missing Unicode-containing JSONL observations. Existing
copies are not automatically rewritten by a code update. Corrected previews and
HTTP object identities can change shadow IDs; they never change persisted tracker
keys. The schema is still the unreleased stage-1 v1 contract, not a migration of
production findings. Re-aggregation alone cannot recover already discarded
objects, records or references.

## Acceptance and validation boundaries

`tests/test_production_evidence.py` covers report aggregation, temporal conflicts,
transport/SNI/object separation, authenticated tenant/run rebinding, replay,
conservative closure, raw access restrictions and bounded history. Its captured
Nuclei consumer test carries the actual local v3.11.1 JSONL through report export,
a migrated PostgreSQL tracker, run API projection and ClickHouse row transform.
It checks one container/observation across consumers, preserves a pre-existing
legacy finding key and approved exception/SLA, and rejects another tenant's run
read. The separate tracker test preserves assignee and owner team.
`web-next/src/components/finding-evidence.test.tsx` verifies distinct subject
rendering and original-run authenticated downloads with permission failures.
The optional `test_live_clickhouse_evidence_roundtrip_replay_and_tenant_counts`
also inserts through the production client into a temporary table using the
production `ReplacingMergeTree` schema. A `FINAL` read verifies replay does not
increase the host/CVE inventory count, all four observations across ports 80/443
survive, and tenant inventory counts remain separate. The receipt also records
`inventory_projection.container_count: 2`: legacy ClickHouse host/CVE inventory
rows and port-scoped remediation tasks have different declared identities.
Before insert, all ports of one host/CVE are folded into one bounded evidence
projection; the scalar risk receipt uses the highest contextual score with a
deterministic tie break. ClickHouse merges therefore cannot discard an arbitrary
port within a publication. Existing CVE inventory consumers keep their contract;
canonical task counts and workflow history remain in PostgreSQL. It runs when `OCTO_CLICKHOUSE_URL` is configured, including
the Jenkins integration matrix. Service projections, database consumers and UI
are tested independently; this is not a browser E2E session.

A local Python 3.12.15 microbenchmark on 2026-10-20 used 1,000 input rows: 500
TCP/443 IP/CVE containers with one Pulse and one Nuclei observation each, identical
2026-10-01 timestamps. Five `combine()` calls with an explicit artifact SHA took
0.0498–0.0551 seconds (median 0.0504); the serialized output was 1,631,026 bytes.
The fallback digest is computed once for the input snapshot, rather than once
per observation. Five calls without an explicit SHA took 0.0504–0.0525 seconds
(median 0.0515). This measures projection time and payload size on a synthetic
local workload, not scanning, DB ingestion or end-to-end performance; no overall
speedup or production latency claim follows from it.
