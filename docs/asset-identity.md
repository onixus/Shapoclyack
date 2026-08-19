# Asset identity (P4.2)

How Shapoclyack decides that an IP observation and an FQDN observation
are the same asset.

Phase 7 already attaches every identifier on **one host record** to one
asset. A later scan of the same IP as a bare FQDN (domain monitor, CT,
a hostname-only target) used to create a second row.
`identity_candidates_for_host` still does not correlate across records —
that would pull every name on a shared-hosting certificate into one
asset.

## When two records become one

A pair is mergeable only when **both** are true:

1. **Forward DNS** — `hostnames.json` or `dns_resolution.json` says this
   FQDN resolves to this IP. PTR / reverse names are ignored (same
   reason as [P4.1](../ROADMAP.md#p4-breakdown--differentiating-features):
   a reverse name belongs to the address-block owner).
2. **Certificate** — `tls_posture.json` has a certificate **on that IP**
   whose DNS identities cover the FQDN (RFC 6125, including a leftmost
   `*`). The SAN list never *introduces* a name we did not resolve.

And **not** when the IP has two or more such pairs: that is shared
hosting. One IP legitimately serves names that are not the same asset.
A wrong merge is worse than two rows.

Evidence is written to `asset_identity_links` (`sources`, `confidence`,
`shared`, `merged`) and returned on `GET /api/assets/{id}` as
`identity_links`. Nothing is dissolved into a number.

On merge, identifiers and tracked findings move to the survivor. Context
(#146) is copied onto empty fields; a decommissioned asset is never
absorbed. Lookups by IP (`asset_criticality`, `exposure_level`) go
through `asset_identifiers`, so a survivor that kept the FQDN-side id
still answers.

## What this does not do

- Infer exposure from a public IP ([#171](https://github.com/onixus/Shapoclyack/issues/171)).
- Treat a CDN SAN list as a set of assets.
- Build an ownership graph (P4.3).
- Model privilege-escalation or lateral-movement steps
  ([#173](https://github.com/onixus/Shapoclyack/issues/173) names a
  same-asset foothold+local pair; it does not invent a takeover).
