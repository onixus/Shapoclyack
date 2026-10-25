# Durable operator service and grounded count summaries

Delivery for [#586](https://github.com/onixus/Shapoclyack/issues/586), extending
[the architecture](local-operator.md) and [provider adapters](local-operator-providers.md).
This guide covers the personal session/queue/worker boundary and read-only
count summary. Confirmed actions, remediation, the console and local runtime
have their own guides linked from the architecture; model-quality acceptance
is recorded separately in [the quality evaluation](local-operator-quality.md).

## Deployment

Apply the current migration head through the normal migration command before
starting this version. `0097_operator_state` introduced five tenant-scoped tables with PostgreSQL RLS and
grants: `operator_sessions`, `operator_messages`, `operator_tasks`,
`operator_proposals`, and `operator_executions`. Later migrations enable the
confirmed-action, evidence, semantic-index and planning contracts; applying
only the original `0097` baseline is insufficient for current code.

Keep the API's normal production database, authentication, encryption and network
settings. Enable `OCTO_OPERATOR_ENABLED=true` and explicitly select a provider and
model. Run a **separate** process with `OCTO_OPERATOR_WORKER_ENABLED=true`:

```bash
python -m api.services.local_operator.worker
# Maintenance/testing: process at most one queued task, then exit.
python -m api.services.local_operator.worker --once
```

The API never starts an inference worker. Hosted inference additionally requires
`OCTO_OPERATOR_ALLOW_EXTERNAL=true` and a provider key. No models, containers or
feeds are downloaded by this process. A compatible inference runtime must already
be available; its deployment and measured GPU behavior remain #585/#593.

## API and authority

Every operator request requires an authenticated **console** user and an explicit
nonblank `tenant_id` query parameter, including for platform administrators.
Scoped service tokens fail closed. Personal reads and mutations recheck the
console session family and current tenant role inside the database transaction.
Authority lookup sees all memberships, so another tenant's grant cannot restore
the legacy `default` fallback. With PostgreSQL RLS enabled, the same transaction
then drops to the tenant role before accessing personal data, retaining its account/session locks;
a request paused before account deletion cannot resume into a recreated account.
Session/task ownership is always the pair
`tenant_id + username`: an administrator cannot read another user's history by
naming its ID. A missing resource and a foreign resource both return 404.

| Method and path under `/api/operator` | Authority | Behavior |
|---|---|---|
| `GET /status` | Viewer in selected tenant | Configuration only, runtime not checked; durable sessions available; task admission flag separate from analysis acceptance |
| `POST /sessions` | Operator in selected tenant | Empty `{}` body creates one personal session |
| `GET /sessions` | Viewer | Personal list with bounded limit/offset |
| `GET /sessions/{session_id}` | Viewer, own session | Up to the latest 100 messages/tasks; use task polling for individual reconnects |
| `DELETE /sessions/{session_id}` | Operator, own session | Deletes inactive personal state; active tasks or legal hold return 409 |
| `POST /sessions/{session_id}/tasks` | Operator, own session | Required `Idempotency-Key`; strict summary request below |
| `GET /tasks/{task_id}` | Viewer, own task | Durable outcome for polling/reconnect; no repeated action |
| `POST /tasks/{task_id}/cancel` | Operator, own task | Queued work cancels immediately; running work is cooperatively stopped |

An admitted summary task body is:

```json
{"tool":"summarize_run","run_id":"approved-run-id","language":"ru"}
```

`language` is `ru` or `en`. No free-form prompt, actor, tenant, role, endpoint,
provider key or model-selected tool arguments are accepted. Unknown fields fail
validation. The request must name an accessible stored run. The worker applies
stricter source eligibility before disclosure: a server-tagged tenant marker,
a matching succeeded control-plane job, no pending publication, and a bounded
summary. Legacy/unmarked, cancelled, missing, oversized or unpublished data gives
an explicit failure without contacting a model.

Only five whitelisted nonnegative integer counts may enter inference. Run IDs,
tenant IDs, usernames, raw banners, findings, arbitrary summary fields, secrets
and metadata do not enter the prompt. Source bytes are limited to 64 KiB, marker
to 8 KiB. These limits describe `summarize_run`.

The same endpoint also accepts `tool=analyze_run`. It refreshes the bounded
[published evidence index](local-operator-retrieval.md), selects at most ten
finding observations within a 12,000-character context envelope, and submits
only normalized public identifiers, severity, service and port plus opaque
source references. IPs, hostnames, package/version strings and arbitrary prose
are excluded from analysis inference. Missing or empty findings produce a
deterministic abstention without contacting a provider. Every disclosed source
is checked again after inference. Structured output permits fixed labels only;
the server supplies localized text and citations. See the
[contract evaluation boundary](local-operator-eval.md). Semantic search remains
unsupported and real model quality remains unverified. Status exposes
`analysis_task_supported=true`; `analysis_available=false` and
`runtime_status=not_checked` continue to distinguish implementation from runtime
acceptance.

## Queue, recovery and cancellation

Task state is `queued`, `running`, `succeeded`, `failed`, `cancelled` or
`interrupted`. Admission serializes on the tenant row and enforces
`OCTO_OPERATOR_QUEUE_LIMIT` across all that tenant's queued/running tasks. The
same idempotency key and exact session/run/language/tool return the existing task;
changed arguments return 409. This does not create a scan or install a patch.

A PostgreSQL advisory leader lock (registered ID 9) selects the worker; a
transactional queue lock (ID 10), one global running lease, and ownership checks
fence state changes. Provider calls execute outside database transactions. The
default 180-second lease exceeds the maximum provider deadline by 30 seconds;
total task execution is bounded by the provider deadline plus 15 seconds.

Before evidence access, before inference and after inference, the gateway reads
the account's current disabled state, role/membership, tenant status and token
generation. Demotion, membership removal, account disable or session-generation
revocation prevents publication of the result. It rereads the source after
inference and refuses a changed/deleted source. Current authorization is required
again on every history/poll request. These checks do not freeze authority across
a network call; they bound disclosure to the checks around it.

Running cancellation keeps the running slot until the provider coroutine has
been cancelled and awaited. SIGINT/SIGTERM request graceful shutdown; unfinished
work becomes interrupted. Expired claims become interrupted, never automatically
requeued. A new user request with a new idempotency key is required to retry.
An old worker cannot overwrite a recovered task. Advisory locks do not fence a
remote inference server: configure runtime parallelism to one and verify actual
remote cancellation behavior in the runtime acceptance gate.

The count operation takes one evidence read and one inference request, below
the design ceiling of eight steps; it cannot execute a model-generated tool
loop. The server renders a fixed RU/EN sentence from only the present
allowlisted integer counts; absent fields are not invented as zero. The
provider receives an exact `summary` const schema and must return that sentence.
Independent validation rejects any changed number, arbitrary prose, URL or
extra field without repair or fallback, even if the provider ignores the
generation schema. Prompt/tool version2 binds the schema into the audit hash.
The server adds the actor/tenant
context, exact source digest and snapshot-bound citation. Answers always remain
`incomplete` with `quality_status=quality_unverified`: source freshness, detector
coverage are not established by count totals. The attached citation binds the
input and the disclosed sentence is constructed from it; no free-form model
claim is accepted as part of this count summary.

## Audit, retention and deletion

Audit rows include the actor, tenant, task IDs, canonical argument hash, selected
provider/model, prompt/tool versions, prompt/output hashes and source references.
Disclosure provenance is committed before the provider request, so timeouts and
provider failures retain the attempted provider/model, prompt hash and sources.
Audit rows omit raw prompts, generated answer bodies and upstream exception text.
Provider failures use a closed set of safe operational error codes. Personal
answer bodies live in the tenant/actor-scoped task and message tables.

Every enabled leader runs a bounded history sweep (20 eligible sessions, once per minute).
Suspended tenants and queued/running sessions are excluded before the batch limit,
so they cannot indefinitely block another tenant's expired history. Protection is
checked again before deletion.
It uses the existing tenant `runs` retention window and honors legal hold, taking
the tenant lock before rechecking disposition. Queued/running sessions are kept.
Deleting a session cascades its messages/tasks/reserved proposals/executions.
Tenant purge lists the five personal-state tables and two shared evidence tables
explicitly, children before parents. The worker also checks up to 20 derived
snapshots per sweep, removing invalid sources while honoring legal hold.

Account data-subject export includes only that username's operator records; it
refuses oversized exports instead of silently omitting records. Erasure removes
personal state; hard deletion also removes it so recreating the username cannot
inherit conversations or queued tasks. Holds preserve both records and account
linkage. If records disappear while the worker runs, cancellation polling and the
finish fence discard the late response. Audit retention remains the existing
append-only audit policy, separate from chat/history retention.

## Backup, restore and upgrade

The five tables are ordinary PostgreSQL data: include them in the existing
transactionally consistent backup and restore procedure and retain the migration
version. No private in-memory queue or separate vector cache is required by this
pilot. Protect backups as personal tenant data. Provider credentials remain
external deployment secrets and must be restored separately through their normal
secret process.

Quiesce the worker before restore or rollback, and stop outstanding runtime calls.
After restore, review running leases; expired work is interrupted and never
replayed. Recovery cannot reconstruct an outcome lost after inference but before
commit, so it remains interrupted rather than guessing success. Downgrading 0097
drops all operator tables and history; back up first and stop API/worker use.
Disabling the feature preserves stored state and leaves normal scanning working.
A real clean-station backup/restore/offline/GPU drill is not established by unit
or PostgreSQL integration tests and remains part of deployment acceptance.
