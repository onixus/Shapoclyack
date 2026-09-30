# D3: review stand calibration artifacts without inventing measurements

This is a read-only preparation/checking step for [D3](https://github.com/onixus/Shapoclyack/issues/337),
not its completion. The sizing model and measurement commands remain those in
[the sizing guide](sizing.md). No kind/Arch result, new coefficient, validated
capacity or RPO/RTO is supplied by this change.

## Keep raw inputs and repeat the measurements

Use a **dedicated** stand/database and the ownership safeguards documented in
`sizing.md`; do not point synthetic seeding/profiling at production. Run the
existing Postgres, ClickHouse, API and real `runs-dir --archive` measurement
commands independently at least three times. For each repetition, keep every
raw JSON and its own `scale_measure derive ... --out derived-N.json` result.

Do not use the same raw file three times. Keep at least two distinct host counts
of real sensor runs with resource accounting **and archive bytes** per repetition
for the CPU/RSS and archive-size fits; collect them with `runs-dir --archive`.
Synthetic report-stage and checkpoint-resumed runs are excluded by the existing
collector, not relabelled as real scans. Copy the complete raw artifacts to the
campaign directory before review; do not discard failures from the scan log.

Create a manifest in that directory, using paths relative to it:

```json
{
  "schema_version": 1,
  "deployment": "kind",
  "scanner_mode": "scanner-executor",
  "samples": [
    {"id": "repeat-1", "result": "derived-1.json", "raw_results": ["pg-1.json", "ch-1.json", "api-1.json", "runs-1.json"]},
    {"id": "repeat-2", "result": "derived-2.json", "raw_results": ["pg-2.json", "ch-2.json", "api-2.json", "runs-2.json"]},
    {"id": "repeat-3", "result": "derived-3.json", "raw_results": ["pg-3.json", "ch-3.json", "api-3.json", "runs-3.json"]}
  ]
}
```

This is a **manifest example, not measurement data**. Its files must be obtained
on the actual stand. Create separate campaigns for `kind` and `arch` and for
`scanner-executor` versus `local`; do not average incompatible process budgets.
Record hardware/storage, image and engine versions/digests, profile, scan scope,
partial failures, retention and headroom rationale with the campaign. Environment
blocks in raw JSON are retained separately rather than overwritten during merge.

```bash
python -m tests.fixtures.scale_calibration campaign.json --out review.json
```

Exit status is **0** when the implemented checks pass, **1** for insufficient or
unsafe evidence (the report is still written), **2** for invalid input or I/O.
Artifact paths cannot escape the campaign directory, including through symlinks;
the output cannot overwrite an input. The helper does not run scans, query
services, execute shell commands, read a URL, or modify any store.

## What is checked

The report binds the manifest, every derived result and every raw input by
SHA-256 and retains **each** raw environment block. It detects reuse of an
identical artifact as another repetition and refuses a repetition whose real
runs do not include archive measurements at two distinct host counts. PostgreSQL `fsync`, `full_page_writes`,
`synchronous_commit` and `autovacuum` must all be explicitly `on` in the raw
metadata; missing settings are not treated as enabled. This intentionally strict
baseline does not silently accept other durability profiles as equivalent.

The coefficient vocabulary comes from the existing `Coefficients` dataclass.
Unknown names, boolean-as-number, negative/non-finite values and invalid shapes
are refused. The comparison reports min/median/max, relative range and the
number of measured repetitions **for each coefficient**. Missing values remain
missing: a median of available samples is only diagnostic and is marked
`complete: false` when any repetition lacks that coefficient. A zero median has
no relative-range estimate. No defaults or synthetic values fill the gaps.

## What still needs human and stand verification

`checks_passed` is **not** calibration acceptance. `capacity_validated` is always
`false`, and the report deliberately has no top-level `coefficients` field that
could be accidentally fed into the sizing model as an approved calibration.
Hashes bind files; they do not attest the truth of a stand's metadata or prove
that a derived coefficient was calculated from the named inputs. Re-run derive
from those inputs and review the fits before approving a coefficient set.

D3 remains open until kind and Arch (or an explicitly agreed replacement matrix)
have reproducible measurements. In particular, reviewers must inspect actual
engine versions, target/profile equivalence, failed/partial runs, process-tree
RSS under overlap, ClickHouse CPU, and ClickHouse system-log growth over meaningful
idle/ingest windows with retention. The current run-resource peak can be a lower
bound when tools overlap; the quality helper does not upgrade that bound to a
pod peak. Check the aggregate JetStream reservations against `max_file_store`
and PVC, per-run payload against `max_payload`, raw-output disk cost and growth
of jobs, vulnerability events and system logs.

Use reviewed, re-derived coefficient JSON with the existing command to regenerate
tables, and explain the chosen headroom/variability rather than blindly taking
a median:

```bash
python -m tests.fixtures.scale_sizing --tiers --coefficients approved-stand.json --markdown
```

The >=10k-asset disaster-recovery measurement and measured RPO/RTO remain the
separate acceptance in #333; neither a configuration target nor this report
establishes recovery performance.
