# Finding evidence: shadow contract (#449, stage 1)

This is an **offline, explicitly invoked projection**, not a change to the
production tracker. `build_reports()` and the existing first-wins
`vulnerabilities.json` path are unchanged. Do not mark #449 complete on the
strength of this stage: API/tracker/UI integration and identity compatibility
are still required. This implementation can be reviewed and exercised without
merging #491 or waiting for a live-engine benchmark.

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
verification, sufficient coverage and state transitions remain the tracker's job.

Engine/ruleset versions missing from source data stay null. A Docker pin is not
proof of which executable produced an imported file. Likewise, missing
confidence stays null and explicit zero stays zero. The fixtures are synthetic
and use the JSONL fields already exercised by `tests/test_nuclei_scan.py`; they
are **not** advertised as captures from a live pinned Nuclei execution.

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

## Remaining stages of #449

Before switching the default result, agree on a compatibility/migration policy
for protocol/vhost/object distinctions currently absent from `finding_key`.
Then replace first-wins in the report and propagate observations through the
run API, tracker, UI and analytics without multiplying unique finding counters.
The consumer work must cover idempotent re-publication, old artifacts,
assignments/SLA/exceptions, temporal conflict handling and incomplete coverage.
Add actual pinned-engine captures and full consumer integration tests. This
shadow artifact is deliberately not ingested by existing consumers.

Rollback of this stage is stopping the explicit command or removing its sidecar;
no stored finding identity or database migration has been applied.
