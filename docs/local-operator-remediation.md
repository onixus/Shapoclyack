# Evidence-backed remediation lookup

The optional operator exposes read-only remediation cards for an endpoint's
accepted software inventory. This implements a bounded slice of
[#590](https://github.com/onixus/Shapoclyack/issues/590): deterministic vendor
fix lookup and package grouping. It makes no language-model quality claim.

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
inventory payload digest, installation identity and current support status.
Old or changed references return 409; absent or foreign sources return 404.
Only the first 100 matcher rows are exposed by this bounded operator surface;
larger inventories use the existing inventory APIs. Raw advisory URLs, free
text, evidence blobs and credentials are never returned or sent to inference.

No endpoint installs packages, changes a finding, marks `machine_verified`,
closes vulnerabilities, dispatches verification or invents backup/restart/
rollback instructions. Verification requires a separate confirmed control-plane
operation. Vendor workarounds, source-backed operational caveats, complete
inventory/advisory semantic retrieval, real-model evaluation and physical
offline/GPU acceptance remain outstanding for the full epic.

Validation includes deterministic golden cases and real PostgreSQL API tests
for tenant isolation, current-session revocation, replacement during a held
read, strict arguments and stale citation rejection. These tests establish the
contract and authority boundaries; they are not the final model-quality or
workstation acceptance report.
