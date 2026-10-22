# Finding analysis contract and evaluation boundary

`analyze_run` uses a selection-only model contract, exported as
`docs/schemas/operator-analysis-v1.json`. The model selects a summary label,
registered source ID/hash/snapshot tuples, proposed priority (`low`, `medium`,
`high`, `unknown`), category (`vulnerability`, `exposure`, `configuration`,
`unknown`), and up to four fixed next-step labels. Server code renders the
summary and next steps in Russian or English and attaches citations from the
registered evidence. Free-form prose, URLs, commands, tenant/actor/ownership,
version, risk and other extra fields are rejected. These are proposals for
human review, never writes to finding priority, risk, ownership or configuration.
No comparison or remediation claims are supported.

The caller must authorize retrieval and revalidate every selected source after
inference. This validator does not establish tenant authorization. Every
selection must match the exact registered ID, hash and snapshot. Duplicate
registrations, duplicate selections, foreign references and stale selections
are rejected. Missing, unknown, stale or empty retrieval requires abstention.
Partial and truncated retrieval may produce bounded proposals, but the result
always remains `incomplete` and `quality_unverified` with an explicit reason.

Prompts contain only opaque source references, normalized CVE/CWE identifiers,
known service labels and severity values, and numeric ports. IP addresses,
hostnames, owners, titles, run metadata, arbitrary descriptions and raw evidence
text are excluded even when present in retrieval context. These values are
observations, not authority. The model output cannot introduce or copy factual
identifiers because all generated prose is a closed vocabulary. Identifiers in
rendered citations come from the registered server records. JSON is parsed once
with duplicate-key rejection; invalid output fails without tools or repair.

## Frozen contract fixture

`tests/fixtures/operator_analysis_eval.json` contains **72 frozen cases**: 36
Russian and 36 English. Each contains a retrieval result, proposed model JSON,
accept/reject classification, gold reference tuples and expected abstention.
Cases include missing/stale/partial/truncated data, multiple IP observations,
unknown classifications, duplicates, altered hashes/snapshots, foreign sources,
fabricated CVE/IP claims, malformed labels and malicious authority/URL fields.

SHA-256 of the fixture bytes:

`e4cdf0d2b4507dd5b956d1b7af57a3a35b8d20df66039fcfd65f76ad5c6c26a0`

`tests/test_operator_analysis.py` pins this digest and checks all cases against
the actual validator, along with prompt privacy, malformed JSON, stale-item and
schema-export checks. Run:

```console
.venv/bin/python -m pytest -q tests/test_operator_analysis.py
```

These are **contract and harness tests using supplied outputs**. No language
model is invoked; acceptance rates are not model F1, citation precision,
relevance, threat analysis accuracy or remediation quality. An accepted output
only demonstrates bounded shape and reference consistency. In particular, the
validator cannot establish that a suggested category or priority is correct.

Before claiming model quality, freeze an independently reviewed domain dataset
with expected labels and abstentions, run the exact provider/model and prompt
version against it, record immutable input/output artifacts and provenance, and
report RU/EN accuracy, reference validity, unsupported-claim and abstention
metrics separately. Report partial/stale/unknown subsets and confidence intervals.
Any cloud run also requires the configured opt-in and data-boundary checks.
Until those measurements exist, user-visible results retain the unverified
quality status; this fixture is not a substitute for GPU/offline acceptance.
