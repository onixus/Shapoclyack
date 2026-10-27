# Evidence-backed remediation lookup

The optional operator exposes read-only remediation cards for an endpoint's
accepted software inventory. This implements a bounded slice of
[#590](https://github.com/onixus/Shapoclyack/issues/590): deterministic vendor
fix lookup, package grouping and a bounded administrator-reviewed upgrade plan.
It makes no language-model quality claim.

`GET /api/operator/remediation/devices/{device_id}` requires an explicit
`tenant_id` and a current console session. Optional arguments are `language`
(`ru` or `en`, default `ru`) and `limit` (1–100 matcher rows, default 50).
Unknown and duplicate query arguments are rejected. Viewer access is enough
for this read; machine service tokens are refused. Live account, session,
tenant and membership checks fence both evidence reads. The second read must
equal the first before data is returned; an intervening replacement returns
409 and an intervening revoked session returns 403.
Before disclosure the append-only audit records the actor, tenant, tool version
and bounded source ID/hash/snapshot references; a failed audit prevents a
successful response. Raw inventory/advisory bodies and credentials are omitted.

The service reads tenant-owned `EndpointDevice`, `EndpointInventorySnapshot`
and `SoftwareCveMatch` rows. A matcher row must refer to the currently accepted
software snapshot. Its vendor advisory is looked up again in a pinned local
dataset; the advisory ID, CVE, fixed version, release and applicable RPM
architecture must still agree. Debian and RPM installed/fixed comparisons use
the existing distro comparator. MSRC uses the existing Windows build parser;
a KB-only fixed verdict with an older OS build remains unknown in this surface
until current KB inventory can be checked. Network banners never establish
package versions here.

The first version uses conservative, visible freshness limits: inventory at
most seven days old and vendor/matched feed dates at most thirty days old.
Future or missing timestamps, missing coverage and seed/unidentified feeds
cannot supply a supported fix. These are operator-surface limits; they do not
change the underlying matcher or vulnerability lifecycle's policies.

Each card has a closed status (`fix_available`, `no_fix`, `fixed`,
`not_applicable`, `unknown` or `stale`), versions when supported,
distribution/release/architecture, CVEs, bound source references and a proposed
endpoint-inventory verification method. `no_fix`, `unknown`, `stale` and
`not_applicable` cards have no target version or command. A vendor `open`
advisory cannot yield a fix even when a legacy matcher row has a version.
Empty matches are unknown, never a claim that a host is safe. Truncation is
explicit and makes the response incomplete.

For comparable Linux packages, grouping and highest-fix selection reuse
`patch_gap`. Different installation, OS/release, package grammar, architecture,
inventory and feed identities are kept separate. Upgrade commands reuse the
existing deterministic shell-quoting renderer and are display-only. The
command names the package; it does not pin a repository transaction to the
displayed minimum fixed version or guarantee that an enabled repository
actually offers that version.

Sources open through
`GET /api/operator/remediation/devices/{device_id}/sources/{source_id}` with
explicit `tenant_id`, `snapshot_id` and `source_hash`. The SHA-256 binds the
matcher provenance, exact vendor record fingerprint, current feed source/date,
inventory payload digest, installation identity, current support status and
the pinned operator runbook SHA. Each numeric source also binds the whole
grouped target/version decision: a newly applicable advisory that raises the
group's target invalidates an older citation, even if its individual matcher
row did not change.
Old or changed references return 409; absent or foreign sources return 404.
Only the first 100 matcher rows are exposed by this bounded operator surface;
larger inventories use the existing inventory APIs. Raw advisory URLs, free
text, evidence blobs and credentials are never returned or sent to inference.

Package cards declare `kind=package_upgrade` and include `plan` from the pinned
`package-upgrade-runbook-v1.json` catalog. `plan.origin` explicitly identifies
our operator runbook, separately from the cited vendor applicability/fixed
version facts. Bilingual preconditions require current authenticated inventory,
exact OS/architecture/installation identity, vendor review, approved repository,
administrator approval and a maintenance window. Backup scope and completion
require manual approval. Service restart/reboot needs and rollback safety remain
`unknown`, with no invented commands. The runbook requires a tested restore path
and warns that downgrades may be unsupported, restore vulnerabilities or fail
after data migrations. No feed-derived fixed version proves operational safety.

The plan's upgrade step uses only the existing matcher/patch-gap target and
display-only command; unknown/no-fix/stale cards expose an unsupported upgrade
step. `plan.vendor_workaround` is explicitly unsupported without a reviewed
vendor workaround source. A fresh complete authenticated inventory and current
vendor reassessment are required after an approved change. The same fixed plan
opens inside the numeric citation response, with runbook and plan SHA bindings.
No endpoint installs packages, executes the plan, closes vulnerabilities or
marks `machine_verified`; effectful verification remains separately confirmed.

For a current finding from the exact shipped Pulse `shapo_http_trace` plugin,
`GET /api/operator/remediation/findings/{vuln_id}` exposes configuration guidance
only after a current administrator records hash-bound independent Apache 2.4
process/container inventory through the `applicability-review` route. A remote
banner is insufficient. The offline reviewed Apache source recommends
`TraceEnable off` and expects HTTP 405; the card explicitly treats this as
configuration hardening, with no Apache CVE, package or fixed-version claim.
Its backup/reload/rollback preconditions are labelled our runbook guidance.
Source reads return pinned text and a fixed vendor URL without network fetches.

Validation includes deterministic golden cases and real PostgreSQL API tests
for tenant isolation, current-session revocation, replacement during a held
read, strict arguments and stale citation rejection. These tests establish the
contract and authority boundaries; they are not the final model-quality or
workstation acceptance report.
