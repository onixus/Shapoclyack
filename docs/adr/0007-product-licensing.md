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
   - `features.brand_watch` — Brand Watch API writes, sensor claim, and the dispatcher.
   - Product availability is the half-open interval
     `[valid_from, expires_at)` — valid at `valid_from`, refused at
     `expires_at`.
4. **On expiry (or missing valid license when enforcement is on):** refuse
   **new** scan starts at `job_submission.start_scan`. Existing jobs, assets,
   and history remain readable. Lariska ingest and management (policies,
   release upload/download) are refused; device history stays readable.
   Brand Watch writes, sensor claim/result, and the dispatcher are refused.
   A license-store read failure fails **closed** for those gates. A schedule
   tick that is refused is deferred by one poll, not skipped for the day.
5. **Upload in the product.** Platform admins upload a signed file via
   `POST /api/license`; status via `GET /api/license`. One active license per
   installation (partial unique index on `active`). A replacement is a new
   row; the previous document stays inactive. `OCTO_LICENSE_PUBLIC_KEY` is
   required for every upload. Runtime gates re-verify that document against
   the pin; denormalised columns are not an entitlement.
6. **Enforcement flag.** `OCTO_LICENSE_ENFORCEMENT_ENABLED` defaults to
   `false` so existing installs and CI keep working without a license file.
   When `true`, a missing/expired/not-yet-valid license blocks new scans and
   the gated features, and the public-key pin is required. When `false` and
   no row is installed, env feature flags remain authoritative and Brand
   Watch stays available. An uploaded license is the commercial boundary
   even if enforcement is off: an expired or unsigned-by-the-pin document
   blocks new scans and the gated features.

## Format

`shapoclyack-license` v1 — Ed25519 over canonical JSON payload (same style as
compliance evidence packages). Payload fields: `license_id`, `customer_name`,
`issued_at`, `valid_from`, `expires_at`, `features.{lariska,brand_watch}`,
optional `note`.

## Consequences

- Generators and private keys stay outside the product deployment boundary.
- Brand Watch is gated on its own API and dispatcher, not on
  `discovery.domain_monitor`. That scan stage is a separate typosquat check
  and is forced off only as defense in depth.
- Scan schedules and the operator still go through `start_scan`, so expiry
  covers every admission path.
