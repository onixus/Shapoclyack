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

Platform release upload requires a multipart `signed_manifest` JSON
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

Lariska declares `signed_updates: true` on registration and heartbeat. The server
maps this boolean to its stored `signed_updates` capability; explicit `false`
removes it, heartbeat omission preserves it, and other declared capabilities are retained.
Endpoint re-registration renegotiates native update support: omitting both
capability fields removes a previously stored `signed_updates` declaration,
including rollback to an older client with the same identity or version string.
Clients using `capabilities: ["signed_updates"]` remain supported. The server blocks an unsigned
release for those agents and carries the exact envelope in `managed_update`.
Unsigned uploads, managed-update offers and downloads are blocked, including
legacy release rows stored before #513. Existing collection can continue, but
a legacy agent must be migrated administratively before managed updates resume.
Expired signed manifests are not offered to either client generation. Release
writes keep the platform-admin permission and recent second-factor policy.

Legacy agents without the `signed_updates` capability must never be offered a native package: their historical self-update code treats downloaded bytes as an executable. The server blocks a signed native release for these clients. Migrate the endpoint through a protected native installation, retain identity/spool, establish trust and seed rollback before enabling native managed updates. Legacy unsigned executable releases are retained for audit/deletion only;
this API does not serve them as an update or a download.

## Installer variants (migration 0081)

Signed releases are keyed by `(version, platform, package_kind)` so DEB and RPM
packages for the same Linux target triple can coexist, each with its own bytes,
signature and sequence floor. Unsigned executables use `package_kind: binary`.
Promoting a version/platform to signed native releases retires its unsigned
executable; unsigned replacement remains forbidden. Finish upgrading API replicas
before uploading multiple formats under one version/platform.

Heartbeat may report the locally configured `package_kind` (`deb`, `rpm`, `msi`,
`pkg`). Existing Lariska clients omit it: Windows and macOS target triples imply
MSI and PKG respectively; Linux uses the accepted inventory's active package
database sources (`apt`/`dpkg` or `rpm`). `not_applicable` sources do not count.
An absent inventory or both package databases cannot establish a Linux installer
format: the server blocks the update until an unambiguous inventory arrives or
the client explicitly reports its installer. It never selects an arbitrary row.

Heartbeat download URLs include `?package_kind=...`; administrative deletion
accepts the same qualifier. An unqualified download or deletion remains accepted
for a single variant, but returns HTTP 409 when multiple variants exist. Release
listing and audit details expose the installer kind.

Migration 0081 preserves existing release bytes and derives native kinds from
stored signed manifests. Downgrade refuses duplicate version/platform pairs
before changing schema; remove the extra variants deliberately before rollback.
