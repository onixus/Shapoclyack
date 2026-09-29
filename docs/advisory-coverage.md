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

Unknown packages are grouped by reason. Each row has an empty CVE ID, the
reason, full package count and at most 25 sample names; it is not a vulnerability
with an invented CVE. The current storage/read contract already supports these
strings, so no database migration is required. A loaded feed's date and provider
are retained on the unknown row without exposing a filesystem path or parser
exception to the endpoint panel.

## One dataset per device pass

`advisories.coverage.snapshot_provider()` pins the currently loaded JSON dataset
for a device's matching pass. Availability, release coverage, advisory lookups
and provenance use that same object. A file refresh, deletion or provider cache
reload during the pass takes effect on the next pass, not halfway through the
packages. The dataset index is shared, not copied, and the matching pass performs
one provider file-stat lookup rather than one for each package and lookup.

This relies on the existing JSON loader replacing datasets instead of mutating
them. Non-JSON custom providers keep their existing protocol and remain
responsible for their own consistency. Direct callers of `evaluate_package()`
must still check identity and coverage before interpreting an empty list as an
assessment; the guarded orchestration entry point is `match_software()`.

Invalid UTF-8 and excessive JSON nesting are converted to missing usable data
at this matching boundary. Programming exceptions are not broadly swallowed.
The provider's separate status/fetch interfaces are unchanged; this is not a
new universal feed validator.

## Console and finding lifecycle

The endpoint panel gives readable descriptions for both new reasons and the
existing Microsoft reasons. A missing Windows OS build or MSRC dataset is shown
as an unassessed operating system, not as zero unassessed packages. Windows
application inventory remains separate from Windows OS-build assessment.
The UI displays at most six names and counts all omitted names, including those
already omitted from the API sample.

Tracked-finding closure already has an independent `assessment_possible()`
guard in `software_findings.py`. This change does not introduce that protection
or alter it. It fixes the assessment counters and match rows presented to the
operator; finding keys, assignments, SLA, exceptions and closure policy are
unchanged. Unknown rows do not become remediation findings.

## Rollout and verification

The next normal or explicitly requested matching pass replaces the device's
match rows using the existing replacement path. Restoring the dataset allows a
later pass to assess packages again. No automatic network fetch, scan, bulk
historical rewrite, schema change or new dependency is introduced.

Roll back the application code to roll back this stage. Existing unknown rows
remain readable as strings and are recomputed by the next matching pass; a
rollback also restores the old overcounting defect. Backport comparisons and
the Windows matching algorithm are unchanged.

In a complete checkout with project dependencies installed:

```bash
python -m pytest -q tests/test_advisory_coverage.py tests/test_software_cve_match.py \
  tests/test_advisory_providers.py tests/test_windows_cve_match.py
cd web-next
npx vitest run src/components/endpoint/software-cve-unknown.test.ts \
  src/components/endpoint/software-cve-panel.test.tsx
```

The new fixtures are synthetic and make no external requests. The PR records
which of these commands were actually run and any local subset limitations.
Full application, database and rendered-component checks are distinct from
pure matcher/helper tests. Provider integration and its end-to-end acceptance
remain open in #358.
