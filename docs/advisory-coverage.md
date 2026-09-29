# Advisory coverage and unknown assessments

This is the first correctness stage of #358. It does not add RHEL, SUSE or
Amazon Linux advisory providers. See [software CVE matching](software-cve-matching.md)
for the existing Debian, Ubuntu and Windows OS-build paths.

## A resolved identity is not an assessment

`package_identity.identify()` resolves the package version and distribution.
Before counting that package as assessed, `match_software()` also needs a
provider with usable data for the device's release.

| Condition | Match result | Package counters |
| --- | --- | --- |
| Invalid or unsupported identity | Existing identity-specific `unknown_reason` | Unassessed |
| Provider absent, or its JSON dataset missing, unreadable, empty or invalid | `unknown / no_advisory_data` | Unassessed |
| Loaded dataset has no records for the device's release | `unknown / advisory_release_not_covered` | Unassessed |
| Dataset covers the release, but has no matching package entry | No CVE candidate in this dataset | Assessed |
| Matching advisory exists | Existing vendor state and distribution EVR comparison | Assessed |

An unlisted package in a loaded release is not proof that the package is free
of vulnerabilities. A seed or incomplete feed is not complete vendor coverage.
This change does not add feed freshness thresholds, a completeness manifest or
per-package coverage guarantees. Existing rules that drop unusable individual
feed entries are unchanged.

Identity failures retain precedence over feed failures. For example, a package
without a version still reports `no_version`, not a missing-feed reason. The
Linux counter invariant is `packages_total = packages_assessed +
packages_unassessed`.

Unassessed inventory is grouped by reason, with an empty CVE ID, full package
count and at most 25 sample names. This is distinct from a per-CVE `unknown`
produced when the installed/fixed versions cannot be compared. Neither is a
vulnerability with an invented CVE. The existing storage/read contract supports
these reasons without a schema migration. A loaded feed's date and provider
are retained without exposing a filesystem path or parser exception in the UI.

## One dataset per device pass

`advisories.coverage.snapshot_provider()` pins the currently loaded JSON dataset
for a device's matching pass. Availability, release coverage, advisory lookups
and provenance use that same object. A file refresh, deletion or provider cache
reload during the pass takes effect on the next pass, not halfway through the
packages. The dataset index is shared, not copied, and the matching pass performs
one provider file-stat lookup rather than one for each package and lookup.

This relies on the existing JSON loader replacing datasets instead of mutating
them. The snapshot optimization applies only when the provider inherits the
base JSON read methods unchanged. Subclass or instance overrides of availability,
lookup, releases or provenance must not be bypassed by a raw dataset view.
Those providers, like non-JSON custom providers, keep their existing protocol
and remain responsible for their own consistency. Direct callers of
`evaluate_package()` must still check identity and coverage before interpreting
an empty list as an assessment; the guarded entry point is `match_software()`.

Invalid file encoding, excessive JSON nesting, integer conversion limits and
Unicode errors during normalization are handled by the shared `load_dataset()`.
The resulting unavailable dataset is cached and used by matching, provider
status and closure checks alike. Restoring the file allows it to reload normally.
Other programming exceptions are not broadly swallowed. This is not a complete
feed validator and does not prove that partially usable or seed data is complete.

## Console and finding lifecycle

The endpoint panel explains both new reasons and existing Microsoft reasons.
Missing Windows OS-build or MSRC data is an unassessed operating system, not
zero packages. Windows application inventory is a separate subject. A per-CVE
unknown retains its installed package name even without aggregate evidence.
Without any recorded count or subject, the UI does not invent a zero count.
The UI displays at most six names and counts all omitted names, including those
already omitted from the API sample.

The existing live `assessment_possible()` guard in `software_findings.py` is
necessary but not sufficient: a feed can recover between matching and folding,
or the stored verdict for a particular CVE can be `unknown`. Review of #494
added two vetoes on automatic closure, shared by both fold entry paths:

- A stored `unknown` row with `no_advisory_data` or
  `advisory_release_not_covered` blocks closure from that unassessed result,
  even when the provider has since recovered.
- A stored per-CVE `unknown` blocks closure of that CVE. Unrelated unknown
  application inventory does not block a correctly assessed CVE.

Blocked findings retain their state, `machine_verified`, SLA, assignments,
exceptions and observation timestamps; they use the existing
`held_open_stale_snapshot` counter. Unknown rows do not create remediation
findings. The existing fresh-snapshot and live-provider requirements still
apply to assessed absence, `fixed` and `not_applicable` closure. This change
neither replaces finding keys nor adds a database migration or new state machine.

## Rollout and verification

The next normal or explicitly requested matching pass replaces the device's
match rows using the existing replacement path. Restoring a feed alone does
not turn a previously stored unknown into a successful assessment: run the
matcher again or let it process a newer accepted inventory snapshot. No
network fetch, scan or historical rewrite is started by this change.

Rolling back also restores the old overcounting and unknown-closure defects.
Existing unknown rows remain readable as strings. Backport comparisons and
the Windows matching algorithm are unchanged.

In a complete checkout with project dependencies installed:

```bash
python -m pytest -q tests/test_advisory_coverage.py \
  tests/test_advisory_coverage_review.py tests/test_software_cve_match.py \
  tests/test_advisory_providers.py tests/test_windows_cve_match.py
cd web-next
npx vitest run src/components/endpoint/software-cve-unknown.test.ts \
  src/components/endpoint/software-cve-unknown-review.test.ts \
  src/components/endpoint/software-cve-panel.test.tsx
```

Fixtures are synthetic and make no external requests. The PR records which
commands were actually run and any subset/import-harness limitations. Full
application, database and rendered-component checks are distinct from pure
unit tests. Provider integration and end-to-end acceptance remain open in #358.
