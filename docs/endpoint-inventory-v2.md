# Lariska inventory v2 and signed native updates

Deploy this server migration before upgrading Lariska agents. Registration and
heartbeat responses advertise `inventory_schema_version: 2`; an older server
that omits it supports v1. Both inventory versions remain accepted for a mixed
fleet. The shared contract fixtures are
`tests/fixtures/endpoint_inventory_v2_valid.json` and
`tests/fixtures/endpoint_signed_manifest_v1.json`.

## Installation identity

V2 keeps the existing software metadata and requires `product_identity`,
`installation_identity`, `scope`, and `install_instance_id`. The two installation
identifiers are opaque lowercase SHA-256 values. `package_id` is optional.
`installation_identity` identifies one installation, independently of its
version; changing that installation's version creates an update event while
removing a second installation creates its own removal. The API stores all
installations and matches each assessable installation separately. Device/CVE
tracked findings retain their existing identity and select the worst remaining
installation, so a fixed parallel copy cannot close a vulnerable one.

V2 rejects raw `install_location` values. The agent computes endpoint-scoped
instance hashes locally; neither canonical private paths nor registry key paths
are needed by the server. Existing v1 digests, comparison keys, rows and replay
responses are preserved by migration 0080. The first v1-to-v2 snapshot establishes
a new installation baseline without synthetic installed/removed events. A v1
rollback after v2 retains the v2 inventory and marks its sources degraded until
a v2 complete collection arrives.

## Source completeness

A v2 `sources` entry contains `source`, `status`, `collected_at`,
`collector_version`, optional `last_complete_at`, and optional `diagnostic_code`.
Every software row must name a declared source. Supported source values are
`apt`, `dpkg`, `rpm`, `pacman`, `winreg`, `msi`, `kb`, `brew`, `mac_bundle`, `pip`,
`npm`, `java`, and `other`.

Only `complete` replaces a source's effective inventory and authorizes removals.
`partial`, `failed`, `not_applicable`, or an omitted previously known source
retain the last accepted rows. Incomplete observations do not replace previously
known rows, and a new incomplete source has no authoritative rows yet. Other
complete sources continue to progress in the same snapshot. A failed OS-package
source cannot be used as proof that an existing CVE finding was patched, even
when a healthy runtime source causes the device to be processed again. The server derives
`last_complete_at` from accepted complete collections, retaining the previous
value on degradation; it does not trust an agent-supplied freshness claim.

Device and snapshot read APIs expose source status, collector version, diagnostic
code and last-complete timestamp. The Endpoints page shows degraded sources and
the age of their last complete collection independently of the latest receipt.
A delayed snapshot or complete source collection cannot replace a newer accepted
inventory. Existing device rows are locked during reconciliation.

The durable `software_snapshot_id` points to the last effective inventory change
or accepted complete source collection. A complete collection triggers another
advisory assessment even when its software is unchanged, so newly published CVEs
are discovered and recovered collectors can supply fresh closure evidence.
Degraded-only receipts update `latest_snapshot_id` and source diagnostics while
unchanged software avoids another advisory matching pass. Retention protects
both pointers. V1 agents retain their previous full-snapshot matching behavior
until a v2 baseline has been established.

## Signed native release envelopes

Platform release upload accepts an optional multipart `signed_manifest` JSON
field alongside `version`, `platform`, and `binary`. The envelope is
`{"manifest": {...}, "signature": "<128 lowercase hex characters>"}`. The
manifest contains exactly `schema: 1`, `key_id`, `version`, `platform`,
`package_kind` (`deb`, `rpm`, `msi`, or `pkg`), `size_bytes`, `sha256`, `expires_at`
(Unix seconds), and `sequence` (unsigned 64-bit integer).

The publisher signs compact, lexicographically sorted UTF-8 JSON of the manifest,
without a newline. The server binds its version, platform, digest and size to
the uploaded bytes and preserves the envelope unchanged. It rejects expired
manifests, unsigned replacement of an existing signed release, decreasing
sequences, and different bytes under the same sequence. Ed25519 trust keys are
provisioned in the endpoint's local configuration; endpoints verify the real
signature and enforce their persistent sequence floor. Upload does not grant
any key trust.

New agents declare the `signed_updates` capability. The server blocks an unsigned
release for those agents and carries the exact envelope in `managed_update`.
Old agents can continue using existing unsigned releases during fleet migration.
Expired signed manifests are not offered to either client generation. Release
writes keep the platform-admin permission and recent second-factor policy.
