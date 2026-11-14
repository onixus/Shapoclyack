# ADR 0007: Product licensing (signed entitlements)

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-11-14 |
| **Related** | Lariska endpoint inventory, domain monitor / Brand Watch, scan admission |

## Context

The product needs a commercial boundary distinct from per-tenant quotas:
installation-wide access to Lariska (endpoint inventory), Brand Watch
(domain-monitor / brand-protection stage), and the right to start **new**
scans for the contracted product term. Quotas answer "how much"; the license
answers "whether, and until when".

## Decision

1. **Offline generator, online verifier.** A separate CLI
   (`tools/license_gen`) signs license documents with an Ed25519 private key
   that never ships in the product image. The control plane verifies with a
   pinned public key (`OCTO_LICENSE_PUBLIC_KEY`).
2. **Duration calculator lives only in the generator.** Operators set term as
   `--days` / `--months` / `--years` / `--until`; the signed payload stores
   absolute `valid_from` / `expires_at` UTC timestamps.
3. **Entitlements in the signed payload:**
   - `features.lariska` — endpoint inventory API and Lariska policies.
   - `features.brand_watch` — Brand Watch / domain-monitor stage.
   - Product availability is the half-open interval
     `[valid_from, expires_at)` — valid at `valid_from`, refused at
     `expires_at`.
4. **On expiry (or missing valid license when enforcement is on):** refuse
   **new** scan starts at `job_submission.start_scan`. Existing jobs, assets,
   and history remain readable. Lariska ingest/management and Brand Watch
   stages are treated as disabled. A license-store read failure fails
   **closed** for new scans (an uploaded expired license must not reopen
   because Postgres blinked).
5. **Upload in the product.** Platform admins upload a signed file via
   `POST /api/license`; status via `GET /api/license`. One active license per
   installation (partial unique index on `active`; newest upload replaces the
   previous active row). Signature verification runs at upload; runtime gates
   read the denormalised columns (they do not re-verify the document on every
   scan).
6. **Enforcement flag.** `OCTO_LICENSE_ENFORCEMENT_ENABLED` defaults to
   `false` so existing installs and CI keep working without a license file.
   When `true`, a missing/expired/not-yet-valid license blocks new scans and
   the gated features, and `OCTO_LICENSE_PUBLIC_KEY` is **required** (upload
   and scan start refuse without a pin). When `false`, env feature flags
   (`OCTO_ENDPOINT_INVENTORY_ENABLED`, etc.) remain authoritative if no row is
   installed, but an uploaded+expired license still blocks new scans once a
   license row is active (hard commercial stop after upload).

## Format

`shapoclyack-license` v1 — Ed25519 over canonical JSON payload (same style as
compliance evidence packages). Payload fields: `license_id`, `customer_name`,
`issued_at`, `valid_from`, `expires_at`, `features.{lariska,brand_watch}`,
optional `note`.

## Consequences

- Generators and private keys stay outside the product deployment boundary.
- Brand Watch is introduced as a license entitlement even where the UI surface
  is still thin; the scanner's `discovery.domain_monitor` stage is the
  technical gate.
- Scan schedules and the operator still go through `start_scan`, so expiry
  covers every admission path.
