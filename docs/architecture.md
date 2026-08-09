# Architecture

Shapoclyack separates control-plane state, scan execution, analytical results,
and the operator interface. Optional services are activated by configuration;
the scanner can still run as a standalone process.

## Components

| Component | Responsibility | Persistent data |
|---|---|---|
| Web UI | Operator workflows and visualization | Browser JWT only |
| FastAPI API | Auth, tenant scope, jobs, schedules, assets, reports, config | PostgreSQL and run artifacts |
| Scanner | Discovery, probing, enrichment, diff, and report generation | Run and checkpoint directories |
| Remote agent | Claim jobs, execute scanner, upload results | Local temporary work |
| PostgreSQL | OLTP state, tenants, inventory, schedules, overrides | Database volume |
| NATS JetStream | Job and ingest messaging with durable delivery | JetStream volume |
| ClickHouse | Vulnerability and port analytics across runs | ClickHouse volume |

## Data flow

```mermaid
flowchart TD
    U["Operator"] --> W["Web UI"]
    W --> A["FastAPI control plane"]
    A --> P["PostgreSQL"]
    A --> N["NATS JetStream"]
    N --> G["Remote agents"]
    G --> S["Scanner pipeline"]
    S --> R["Run artifacts"]
    S --> N
    N --> C["ClickHouse ingest"]
    A --> R
    A --> C
```

In local execution mode, the API launches the scanner without the NATS job
path. In agent mode, a worker claims the tenant-scoped job and reports
completion through the API or configured broker.

## Control-plane state

Jobs and the agent registry are rows in PostgreSQL (`jobs`, `agents`), not
process memory. Any API replica therefore sees the same queue and the same
fleet, and a restart does not lose in-flight state. Claims are serialized in
the database (`SELECT … FOR UPDATE SKIP LOCKED`), so two agents claiming at
the same moment receive different jobs regardless of which replica each one
talks to.

### Job lifecycle

A job holds one of six states, and the moves between them are validated on
every write (`api/services/job_states.py`) rather than assigned:

```text
queued ─┬─→ claimed ─┬─→ running ──→ succeeded | failed
        │            └─→ succeeded | failed
        ├─→ running ──→ succeeded | failed        (local execution)
        └─→ cancelled                             (also from claimed)

claimed | running ──→ queued                      (lease expired, see below)
```

- `claimed` means an agent has taken the job but has not yet reported working
  on it; the agent's first heartbeat naming the job promotes it to `running`.
  Local jobs skip the state — the API process is the worker.
- `cancelled` is set by `POST /api/jobs/{job_id}/cancel` and is only available
  before execution starts. A `running` job cannot be cancelled: nothing can
  stop an in-flight scan today, so the API answers 409 instead of recording a
  stop that never happened.
- Terminal states never move again, so a result upload retried after a network
  timeout cannot rewrite the outcome. Such a retry is recognised as a replay
  and answered with the stored result (see below), not with an error.

### Idempotency

Both writes that create work accept a client-supplied key, because the failure
that matters is not a duplicate *request* but a lost *response*:

- `POST /api/jobs` with an `Idempotency-Key` header creates at most one job per
  (tenant, key). Uniqueness is a database constraint, not a read-then-insert —
  two replicas serving the same retry would both read "no such key".
- `POST /api/agent/jobs/{id}/results` with an `idempotency_key` field returns
  the stored outcome when the same completion is uploaded twice, and 409 when a
  second upload contradicts the first. Without a key, the natural key (same
  agent, same job, same exit code) serves the same purpose for older agents.

The schedule dispatcher uses the first of these: it keys each dispatch on the
schedule's own due time, so replicas that all wake for the same tick produce
one job rather than one each. That bounds the damage of having no leader
election, but does not replace it — see the dispatcher note below.

### Leases

Every job handed to an executor carries a deadline (`claimed_until`) that the
executor must keep pushing forward: agents on each heartbeat, local jobs from a
renewal thread running beside the scan. A lapsed lease therefore means the
executor is gone rather than slow — it had the whole window, several renewal
intervals, to say otherwise.

A background sweep (`OCTO_JOB_REAPER_INTERVAL_SECONDS`, default 60s) acts on
what it finds:

- **agent** jobs go back to `queued` for another worker, until
  `OCTO_JOB_MAX_ATTEMPTS` hand-outs are used up; past that they are failed, so
  a target that kills whatever picks it up cannot cycle through the fleet;
- **local** jobs are failed outright — their only executor was a thread in the
  process that died, so no other replica would ever pick the row up.

The sweep runs in every replica and needs no leader election: expiry is a
property of the row, and candidates are taken with `FOR UPDATE SKIP LOCKED`.
`octo_job_lease_expired_total{outcome}` counts what it did. Tune the lease with
`OCTO_JOB_LEASE_SECONDS` (default 300) — it must stay comfortably above the
agent heartbeat interval, or live scans get reaped.

Two properties still bind a job to one process:

- A **local-mode** job executes in a thread inside the replica that accepted
  it. That replica is recorded as the job's owner (`OCTO_INSTANCE_ID`,
  defaulting to the hostname), and on startup a replica fails only its *own*
  orphaned local jobs. A local job orphaned by a replica that never comes back
  under the same identity is caught by the lease sweep above instead.
- The **schedule dispatcher** runs in every replica without leader election, so
  every replica wakes for the same due schedule. Duplicate *scans* are already
  prevented — each dispatch is keyed on the schedule's due time, so the losers
  get the winner's job back (see Idempotency above) — but the replicas still
  all poll and still race on the schedule's own bookkeeping. Run a single API
  replica, or disable the dispatcher on all but one
  (`OCTO_SCHEDULER_DISPATCH_ENABLED=false`), until ROADMAP P1.6.

Installations upgrading from a release that kept `state/api_jobs.json` and
`state/api_agents.json` need no manual step: the API imports each file once at
startup and renames it to `*.imported`.

## Scanner stages

The main pipeline is intentionally staged so partial output can be inspected and
long-running work can resume:

1. validate input contract and configuration;
2. resolve domains and normalize targets;
3. discover alive hosts;
4. collect hostnames and optional passive discoveries;
5. scan TCP/UDP ports;
6. run service, OS, NSE, and optional Nuclei checks;
7. enrich vulnerabilities and assets;
8. calculate run and asset changes;
9. write reports, notifications, and export artifacts.

Optional discovery modules can identify candidates or findings without merging
them into active scan scope. Read the configuration comments before enabling
third-party or shared-infrastructure probes.

## Identity and tenancy

- User JWTs carry a username and role.
- Agent JWTs carry agent identity and `tenant_id`.
- The API is authoritative for tenant scope.
- Jobs, assets, schedules, provisioning keys, and agent claims are
  tenant-bound.
- Asset identity is stable across runs and derives from tenant plus primary
  identifiers.

The current UI displays a default global tenant context. API clients must still
send and validate tenant scope explicitly where the endpoint contract requires
it.

## Storage boundaries

PostgreSQL is the primary transactional store. ClickHouse is an optional
analytical projection, not the source of truth for users, tenants, or asset
lifecycle. Run artifacts remain on the filesystem/PVC so operators can inspect
raw tool output and downloadable reports.

## Trust boundaries

| Boundary | Main controls |
|---|---|
| Browser → API | JWT, role checks, TLS at ingress, no secrets in system-status responses |
| Agent → API/broker | Provisioning-key exchange, short-lived agent JWT, tenant match |
| API → databases | Dedicated credentials, network policy, least privilege |
| Scanner → targets | Explicit allowlist, rate caps, timeouts, isolated workers |
| Artifacts → UI | Path validation, authorization, binary-safe download endpoint |
| External enrichment | Opt-in providers, candidate caps, timeouts, fail-soft parsing |

## Deployment topology

The all-in-one image packages scanner tools, API, and static Web UI. The thin API
image excludes scanner execution tools and is appropriate for results-only or
remote-agent deployments. Kubernetes overlays add agents, enrichment storage,
read-only API behavior, and production resource settings without changing the
base manifests.
