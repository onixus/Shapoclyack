# RHEL, SLES and Amazon Linux package advisories

Issue #358, extending [advisory-coverage.md](advisory-coverage.md). These
providers assess **installed binary RPM versions**, not running processes,
reboot/kernel/livepatch state, arbitrary software or the entire VEX portfolio.

## Supported inputs

| Provider | Input and binding | Dataset override |
| --- | --- | --- |
| `redhat-csaf` | Final Red Hat CSAF 2.0; `fixed` / `first_fixed`, explicit RHEL platform IDs, exact inventory release (minor preserved), binary name and architecture | `OCTO_RHEL_ADVISORY_DATABASE` |
| `suse-csaf` | Final SUSE CSAF 2.0; `fixed` / `first_fixed`, or `recommended` **and** corresponding `vendor_fix`; explicit SLES platform IDs/service pack, binary name and architecture | `OCTO_SUSE_ADVISORY_DATABASE` |
| `amazon-alas` | Final security updates in `updateinfo.xml[.gz|.bz2]`; explicitly bound Amazon Linux 2 or 2023 **core** repository, binary name and architecture | `OCTO_ALAS_ADVISORY_DATABASE` |

Recognised releases: RHEL 7/8/9/10, SLES 12/15 with service pack or 16, AL2 and
AL2023. Recognition is not proof of data coverage. Default files are
`scanner/data/advisories/{rhel,suse,alas}-advisories.json`. No synthetic
production seeds are shipped. Without an imported dataset the provider is
unavailable and matching reports `no_advisory_data`. `/api/system` and the
existing offline enrichment bundle include all three dataset names. Their
optional one-entry manifest floor measures presence, **not completeness**.

Rocky/Alma/CentOS/Oracle/Fedora/openSUSE, SLES for SAP/HPC, AL2 Extras, ALAS
livepatch repositories, modular RPMs, source-RPM-only VEX and legacy OVAL are
not silently equated with these inputs. They need additional authoritative
product/collector context. An SRPM is never expanded into guessed binaries.

**Channel selection is an operator responsibility.** Inventory currently has
no repository/EUS/E4S/module-stream field. The administrative manifest binds
selected platform IDs to an inventory release for this installation. Only use
it when the binding is true for the managed package population; do not combine
incompatible channels or tenants with different channels under one release.
Use separate installations for those populations until channel-aware inventory
and per-tenant feed selection exist. A version and RPM manager name do not
prove the installed package's publisher authenticity.

A RHEL major-product CPE may explicitly bind to a minor of that same major;
a minor-specific EUS/E4S CPE cannot bind to another minor. SLES service packs
are preserved. AL2023 build dates resolve to series 2023, but the imported
metadata must be from the intended current repository version: older AL2023
repository snapshots do not acquire later advisories automatically.

## Offline import

Obtain vendor documents via a trusted administrative/mirror process. Verify
origin/signatures independently and retain licence notices. The importer does
**not** crawl feeds, contact URLs or verify signatures. SHA-256 checks bytes,
not authorship. Create a manifest beside the original local source files:

```json
{
  "version": 1,
  "vendor": "rhel",
  "sources": [{
    "path": "rhsa-2025_23127.json",
    "sha256": "REPLACE_WITH_VERIFIED_FILE_SHA256",
    "url": "https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_23127.json",
    "release": "9.2",
    "product_ids": ["BaseOS-9.2.0.Z.E4S"]
  }]
}
```

This example binds **E4S 9.2**, not arbitrary RHEL 9. The selected product CPE
must agree with the release; its `default_component_of` relationships identify
applicable binary RPMs. For SLES use `vendor: suse`, for example `release: 12.5`
and `product_ids: ["SUSE Linux Enterprise Server 12 SP5"]` from the actual
CSAF document. For ALAS use `vendor: alas`, `release: "2"` or `"2023"`,
`repository: core`, a local updateinfo file and its canonical repository URL;
omit `product_ids`. SHA-256 covers raw file bytes, including compression.
Credential/query-bearing URLs are refused. URLs are provenance, never followed.

```bash
python scripts/import-rpm-advisories.py sources.json \
  -o /srv/shapoclyack/advisories/rhel-advisories.json --min-entries 1
# Repeat with SUSE/ALAS manifests and corresponding output paths.
```

Set the matching `OCTO_*_ADVISORY_DATABASE` in the API. Mount/copy the file
read-only and give the API service account read access: imports create private
`0600` files. Choose `--min-entries` for the expected corpus, not this example.
Supply the **complete intended replacement** manifest, not an incremental batch.
Import is deterministic, deduplicated and atomic. Invalid/missing sources,
checksum mismatches, XML DTD/entities, wrong products, unsupported selected
applicability and too few statements leave the previous output intact.
Symlinks and paths outside the manifest directory are refused. Limits: 4096
bindings, 64 MiB per raw/expanded source, 512 MiB combined input and a bounded
normalised dataset. This is an administrator CLI, not an upload endpoint.

Dropping existing coverage requires `--allow-shrink` after reviewing the change.
Conflicting fixed EVRs for one binary/CVE/architecture produce
`rpm_advisory_ambiguous`, not an arbitrary min/max winner. Resolve conflicting
corpus/channel selections explicitly. Each match retains vendor publication
time, source URL/digest and product ID. No automatic freshness or completeness
guarantee is implied by a successful import or a populated dataset.

## Assessment and closure

Collectors must supply full `[epoch:]version-release` and the **package's own**
architecture, not merely the host CPU. Names preserve case; existing RPM epoch,
`~` and `^` comparison is reused. `amd64`/`arm64` aliases map to
`x86_64`/`aarch64`; `noarch` only matches `noarch`, not every CPU. No name-suffix
stripping creates a source-to-binary correspondence.

Missing package entries, wrong/missing architecture, modules and conflicting
thresholds are explicit `unknown` and excluded from `packages_assessed`.
A partial patch-gap corpus is not a list of safe packages. Debian/Ubuntu keep
their existing no-package-entry semantics and MSRC remains a separate OS path.

Existing device/CVE finding identity, assignments and SLA are retained. RPM
automatic closure additionally needs a **positive fixed match in the current
inventory snapshot**, no unresolved RPM gaps and existing freshness/live-feed
guards. Disappearing packages or advisories alone cannot prove remediation.
With device/CVE deduplication, an unassessed binary could carry the same CVE;
RPM gaps therefore conservatively hold closure. Unrelated non-distribution
application inventory does not. Partial estates can require analyst verification.
An installed kernel/microcode update does not prove a reboot or applied livepatch.
Existing inventory duplicate-name/version limits remain; this is not a new
collector protocol. Network-banner retro matching intentionally does not use
these providers because it lacks installed binary and architecture context.

## Verification and rollback

```bash
python -m pytest -q tests/test_rpm_advisories.py tests/test_rpm_advisory_lifecycle.py \
  tests/test_advisory_coverage.py tests/test_advisory_coverage_review.py \
  tests/test_advisory_providers.py tests/test_software_cve_match.py \
  tests/test_package_identity.py tests/test_version_compare.py tests/test_retro_match.py
# With isolated, migrated PostgreSQL configured:
python -m pytest -q tests/test_api_rpm_advisories.py tests/test_api_software_cve_match.py \
  tests/test_software_findings.py tests/test_software_finding_closure.py
```

Fixtures include reduced **real** Red Hat/SUSE CSAF structures with original
and reduced digests in `tests/fixtures/advisories/rpm/provenance.json`, and
explicitly synthetic ALAS XML. The PR records the executed matrix; this is not
live-fleet validation of every vendor format. Restore the previous dataset or
application image to roll back. Changes take effect on a subsequent matching
pass, not an automatic mass rewrite. No schema migration, dependency or active
scan/network request was added.

## Primary references

- [Red Hat CSAF/VEX structure](https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/docs/csaf-vex.md).
- [SUSE CSAF information](https://www.suse.com/support/security/csaf/).
- [Amazon Linux advisory/updateinfo semantics](https://docs.aws.amazon.com/linux/al2023/ug/alas.html).

Retain vendor attribution/licence notices with mirrors and exported data.
