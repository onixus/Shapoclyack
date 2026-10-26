# Confirmed operator actions and published comparisons

The optional operator exposes explicit `start_scan`, `cancel_scan` and
`verify_finding` proposals. These endpoints require a current console session,
an explicit `tenant_id` and current operator authority in that tenant. They do
not accept model-generated shell commands, arbitrary tools, URLs, tenant
overrides, quota exemptions, priority overrides or scanner configuration.
The feature remains disabled with `operator_enabled=false`.

## Prepare, review, confirm and track

1. Create a personal conversation with `POST /api/operator/sessions`.
2. Prepare a plan with
   `POST /api/operator/sessions/{session_id}/proposals?tenant_id=...`.
   Supply `action` and its closed `arguments` object. A scan requires explicit
   `ranges` or `domains`, and explicit TCP `ports`; optional fields are `mode`,
   `intent`, `ports_udp` and `agent_group`. Cancellation accepts `job_id`;
   verification accepts `vuln_id`.
3. Review returned `arguments`, `impact`, `arguments_sha256` and `expires_at`.
   Preview executes admission checks without creating a job. Its scan impact
   includes parsed targets, approved scope, policy limits and the resolved
   sensor group. Promoted domains are not added. An omitted UDP port override
   is labelled `server_default`; normal scanner discovery and approved scope
   semantics still apply.
4. Confirm with
   `POST /api/operator/proposals/{proposal_id}/confirm?tenant_id=...` and
   `{"arguments_sha256":"<the reviewed digest>"}`. The digest covers canonical
   stored action arguments. The stored proposal also binds actor, tenant,
   conversation, current login session, account token version and a five-minute
   expiry. A chat message is not confirmation.
5. Poll `GET /api/operator/proposals/{proposal_id}?tenant_id=...`. Personal
   session history includes proposal summaries; poll the individual proposal
   for execution evidence. Job IDs use the ordinary job status APIs.

Fresh account, login, tenant and role checks run before claiming and again
before dispatch. Membership and account locks fence revocation through dispatch.
Scan submission checks its actual admission digest against the preview before
writing job inputs or inserting a job. Scope, policy, target or group drift
requires a new proposal. Quotas, maintenance and queue limits remain the normal
service's authority. Verification checks its actual detector-plan digest and
uses the existing vulnerability lifecycle and sensor/coverage requirements;
it cannot set `machine_verified` or close a finding. Cancellation reports the
actual `cancelled` or `cancelling` state and preserves ordinary local-execution
limitations.

## Recovery and deletion

An execution claim commits before calling an effectful service. A unique
proposal-to-execution constraint and proposal row locking prevent double
clicks from dispatching twice. Starts use the stable internal key
`operator:<proposal_id>`. A confirm retry can reconcile an accepted start to its
existing job after a lost response; it does not submit a second start.

A service exception after dispatch whose type proves that nothing was created
(quota or maintenance refusal, scope/permission denial, a `ValueError` such as
"Confirmed scan admission changed", an operator-store refusal, a verification
dispatch refusal of the verification service itself, but not one that wraps an
arbitrary failure of the job start) produces `failed` with `error`, `no_effect=true` and
`retryable`. Quota and maintenance refusals are also answered `429`/`409` with
`Retry-After`, exactly like a refusal at the first check; the same failure in the
re-check transaction after the claim is logged, committed as `failed` and
answered the same way. The plan is then spent: retrying means preparing a new
proposal. Any other exception (a lost connection, a failure after the effect
was committed, such as starting the executor thread) produces `unknown` with
`requires_reconciliation=true`, because an effect may already have committed.
An interrupted claim remains `executing` if no outcome was persisted. A retry
may recover an existing scan by its key; absence of that job never causes
automatic replay. Verification and cancellation uncertainty needs manual
inspection of existing finding/job state. There is no automatic retry or lease
that turns an uncertain action into a fresh network job.

A genuinely `unknown` action (and an `executing` claim older than 15 minutes
whose process died) is closed by a tenant administrator with
`POST /api/operator/proposals/{proposal_id}/close` and
`{"resolution": "no_effect" | "effect_confirmed"}`: the admin records, after
inspecting jobs and findings, that nothing was created (`failed`) or that the
effect exists (`succeeded`). Nothing is redispatched. The call requires the
tenant `admin` role (`403` otherwise), is audited as `operator.action.close`
with the resolution, and makes the session deletable and expirable again. A
settled or never-confirmed proposal answers `409`.

The confirmation audit records the proposal, the arguments digest, `job_id` or
`vuln_id` where the action names one, and `targets_sha256` (a digest of the
approved targets, never the targets themselves). Plan expiry is compared as a
datetime, and `GET /api/operator/proposals/{id}` takes only shared locks so
status polling never waits behind a confirmation in flight.

Verification also holds a fail-fast claim shared with campaign and ordinary
verification entrypoints. Its native job key binds tenant, finding, current
detector plan and lifecycle epoch, so a lost finding receipt reconciles an
existing job rather than dispatching another. Current admission and confirmed
plan checks still apply. A known job that has already finished or is cancelling
requires manual reconciliation: the finding is not parked in `VERIFYING` after
its completion event. The operator execution remains `unknown` and includes
the known job link/status for inspection; confirming it again never redispatches.

Session deletion and retention refuse conversations with `executing` or
`unknown` proposals, preserving reconciliation evidence until an administrator
closes them. A session admits at
most 100 retained proposals. Privacy erasure and tenant purge follow the
platform's dedicated audited procedures. Migration
`0101_operator_actions` extends the existing proposal/execution tables;
downgrade refuses non-reserved action evidence instead of silently discarding
it. Back up PostgreSQL with the rest of operator history before upgrade.

## Read-only comparison

`GET /api/operator/compare?tenant_id=...&previous_run_id=...&current_run_id=...&language=ru`
supports `ru` and `en` for viewer or higher console users. Both runs must belong
to the selected tenant and have accepted, succeeded publications. The service
projects bounded counters from the scanner's published `diff.json`, whose
baseline/current run labels must match the selected pair. It does not compute
differences from incomplete pages or CVE-only sets. Missing or mismatched diff
data returns `unsupported`; accepted counters remain `incomplete` and
`quality_unverified`, because matching detector coverage is unproven.

The response carries both summary citations and the diff artifact digest.
Summary citations can be resolved through the authenticated operator summary
endpoint using their snapshot/hash parameters. Diff paths, raw event text and
arbitrary artifact fields are not returned. Source hashes are checked again
before returning. Removed observations never mean verified remediation.

These tests establish control-plane behavior with private PostgreSQL and
queued scanner jobs. They do not establish model quality, physical GPU fit,
offline operation, live sensor behavior or final epic acceptance.
