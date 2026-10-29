# ADR 0006: Native informational perimeter observations

| | |
|---|---|
| **Status** | **Accepted** — user, 2026-10-29 (API/receipts and one constrained RDP inventory probe) |
| **Date** | 2026-10-29 |
| **Related** | [ADR 0002](0002-replacing-nmap-functions.md), [Pulse plugins](../pulse-plugins.md), [Finding evidence](../finding-evidence.md) |

## Context

At the time of this decision, the perimeter monitor had 16 shipped Rhai scripts and 16 applicability
entries in `scanner/pipeline/pulse_plugins.py`. Every Rhai map returned as a
plugin result is finding-shaped, not a neutral inventory message: the scanner
adapter converts it to a `pulse-plugin` report row
(`scanner/pipeline/service_schema.py`), and INFO or unrecognized severity is
normalized to `unknown`. The offline evidence
projector may represent that same row as `plugin_report`; this projection does
not change its report or tracker semantics.

This is a poor output contract for a protocol inventory observation that must
not create a vulnerability/tracker row. In particular, the proposed RDP
protocol-negotiation matrix is distinct from the existing standard-security
finding and NTLM inventory, but cannot be expressed safely as a Rhai map under
the current adapter contract. Exact pinned Nuclei template sources are also not
present in the local corpus, so this decision is not about Nuclei coverage.

## Decision drivers

- A fact-only protocol observation must remain separate from findings and must
  never create, update, close, or verify a remediation task.
- Scans, runs and assets must remain correctly bound at authenticated tenant
  boundaries; self-reported IDs or hashes are not authorization.
- Ran, responded, failed, skipped and unknown are distinct states. A timeout,
  refusal, partial response or absent record cannot imply a negative result or
  successful assessment.
- Wire probes remain bounded and read-only; enabling observations must not widen
  target scope, transport privileges, request budgets or policy bypasses.
- The output needs reproducible provenance and parser tests, while raw protocol
  payloads remain subject to existing run-artifact access controls.

## Options

1. **Encode inventory in Rhai findings.** Rejected for this use: the scanner
   adapter produces a `pulse-plugin` report row and INFO becomes `unknown`.
2. **Use the existing offline finding-evidence sidecar as a second identity
   system.** Not selected: it projects existing positive report/raw evidence,
   is explicitly not a scan-completion or coverage reporter, and is not a live
   informational-observation ingestion API.
3. **Add a versioned native observation artifact/API and a constrained RDP
   inventory probe.** Accepted for implementation, with no changes to the existing
   finding adapter or tracker path. The user approved one bounded X.224
   negotiation inventory slice; this does not authorize additional probe families.

## Recommendation

Implement a versioned, additive `observation_receipt.json` sidecar with schema
`octo.perimeter_observation.v1`, separate from `vulnerabilities.json`,
`report_sources.json`, and tracker ingestion. Existing finding evidence is
finding-oriented, so the receipt must be a distinct top-level document, not a new
kind in `finding_evidence.json`. Readers that do not know this filename must
continue to ignore it; existing artifact schemas remain unchanged. The receipt contains explicit tenant/run binding supplied by the run controller,
bounded check-family identity/provenance, endpoint subject, protocol/request
variant, decoded outcome and state, timestamp, and optional evidence digest. The
scanner writes it as a restricted additive artifact; this first implementation
has no authenticated ingestion API or production consumer. Remaining validation
and follow-up requirements are:

- canonical endpoint subject and transport; the current scanner context is passed from the approved scan scope and run paths, while control-plane authentication/ingestion remains future work;
- stable check-family ID and implementation digest, protocol/request variant,
  bounded decoded outcome and observation timestamp;
- an explicit lifecycle such as `planned`, `submitted`, `responded`, `failed`,
  `skipped` or `unknown`, with completion receipts distinguishable from a
  positive observation;
- safe bounded evidence allowlists, artifact references, retention and operator
  access policy;
- identity and deduplication relative to findings, and an invariant that this
  channel cannot publish a vulnerability, affect severity, or change tracker
  lifecycle;
- release/version compatibility and how older consumers ignore the additive
  artifact without losing other scan results.

Add a scanner-native RDP inventory check that runs only for an already-approved
open TCP endpoint on port 3389. It sends one request-specific X.224 negotiation
offer, validates the single RDP_NEG_RSP, records the negotiated protocol or an
explicit inconclusive/failure state in the separate typed observation receipt,
and stops. Do not proceed to TLS, CredSSP, NTLM, authentication, or desktop
session; do not report NLA, cipher strength, or security-policy conclusions. The
request variant and applicability must be explicit; output is exclusively a
neutral observation, never a Rhai finding or vulnerability input. No further
probe families are authorized by this acceptance.

The probe connects only to the already-scoped numeric IP (hostnames remain
`unknown`), avoiding a new DNS resolution after scope admission. It has a single
1.5-second connection/write/read deadline. When a
per-host packet-rate ceiling is configured, this unpaced request is not sent;
the receipt records `skipped` rather than a negative result. Resume schedules
the observation independently of Pulse's host checkpoint.
The serial network probes have a 30-second total budget (or the configured
stage timeout, if smaller); remaining recorded targets are `skipped`. Receipt
construction and persistence have additional processing time. The
receipt holds at most 10,000 targets and explicitly counts any omitted targets.

## Consequences

- The scanner-native, bounded X.224 check writes decoded protocol facts only to
  the separate typed receipt; it is independent of the Rhai finding adapter.
  No authenticated ingestion API or production consumer exists yet.
- This single probe is a scoped increment, not a demonstrated threefold increase
  in perimeter coverage.
- A future coverage target must be a frozen, curated registry of independent
  check families and applicable endpoint scope, with completion receipts and
  baseline numerator/denominator. Plugin-file count, finding count and three
  request variants alone are not valid evidence of a threefold coverage increase.
- The accepted RDP inventory slice is an additive scoped implementation, not an
  agreed coverage metric or proof of threefold expansion; baseline/target remain
  undecided pending a curated family registry.
- Offline parsing tests may validate existing artifacts, but cannot demonstrate
  production observation emission or endpoint completion.

## Not decided here

- Exact schema field names, storage, ingestion API or UI for native observations.
- Whether RDP negotiation inventory is independently useful or sufficiently
  distinct from existing RDP checks.
- The baseline and product target for a threefold coverage increase.
- Any additional Nuclei templates, network probes, credentials, or production policy.
