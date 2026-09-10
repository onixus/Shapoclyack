# Operations

## Run directories

Every scan writes to:

```text
scanner/output/runs/<run_id>/
```

The directory can contain:

- run metadata and normalized summaries;
- resolved and alive hosts;
- open ports and service aggregates;
- Nmap XML and tool logs;
- vulnerability and enrichment JSON;
- Markdown, HTML, and PDF reports;
- `sarif.json` — OASIS SARIF v2.1.0 export of the run's vulnerabilities
  (`reporting.sarif_export`, on by default);
- diff and normalized asset events;
- DefectDojo exports;
- diagnostic stage output.

Artifact presence depends on the enabled stages and whether a stage produced
data.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Successful run |
| `1` | Unexpected internal error |
| `2` | Configuration validation error |
| `3` | No valid targets after input validation |
| `4` | External tool failed after retries |
| `130` | Interrupted by the operator |

Automation should distinguish invalid configuration/inputs from transient tool
failure.

## Resume

Checkpoints are stored under `scanner/state`. Preserve both state and the
corresponding run output when moving or resuming a run.

```bash
python -m scanner.main \
  --config scanner/config/default.yaml \
  --resume
```

Do not resume after changing target scope or incompatible stage settings.
Start a new run instead so provenance stays clear.

## Scheduling

Two scheduling models exist:

- `scanner/scheduler.py` and the Kubernetes CronJob for simple single-tenant
  installations;
- API-managed tenant schedules for the platform deployment.

The API dispatcher skips a schedule tick while its previous job is still
running. Use this behavior to prevent overlapping long scans; it is not a
replacement for capacity planning.

The dispatcher runs in every API replica but dispatches only in the one holding
its advisory lock, so multiple replicas need no special configuration — see
[architecture.md](architecture.md#schedule-dispatcher-leadership). Confirm which
replica leads with `octo_scheduler_is_leader` on `/metrics`; the fleet-wide sum
should always be exactly 1.

## Diffs and events

Run diffs compare current and previous compatible results. Normalized events
include new assets, open ports, CVEs, certificate-expiry findings, and manual
decommissioning. Verify that both compared runs use equivalent scope and
profiles before treating a count change as a security event.

## Active checks and target authorization

Every org-profile stage is passive except one. `org_profile.dns_hygiene.axfr_probe`
attempts a **zone transfer (AXFR)** against each nameserver of each seed domain.
That is a request the target's nameserver records as an attempted transfer, so
it needs the same authorization as any other active test — the platform will not
infer it from the fact that a scan was started.

- **Default is off**, and the flag exists only in the scanner config file. It is
  deliberately absent from the API config overrides (`EDITABLE_PATHS` in
  `api/services/config_override.py`), because those overrides are
  installation-wide rather than per-tenant and would enable AXFR for every
  tenant's scans at once; and it is absent from the start-scan request, because
  that would put the decision on the `operator` who launches a scan rather than
  on whoever authorizes the target. Enabling it is a deployment change, made by
  whoever can edit the scanner config and reviewed like one.
- **Only this run's own seed domains** are probed. Attribution candidates from
  the related-domains stage are never probed: a wrongly attributed domain would
  mean an active request against a third party's infrastructure.
- **A nameserver on a non-public address is refused**, not dialled. NS records
  are written by the scanned party, so `ns1.target.example -> 10.0.0.5` would
  turn the probe into a TCP/53 connection inside the agent's own network. The
  refusal is logged as `refusing AXFR against <ns>` and recorded in the artifact
  as `status: refused`.
- **A successful transfer is never written down.** `dns_hygiene.json` records
  only `status: open` and the number of records; the zone itself reaches neither
  the artifact directory nor `scan.log`. If you need the zone contents, transfer
  it yourself with `dig axfr` — the scanner will not keep a copy for you.

Before switching `axfr_probe` on, confirm the engagement covers active testing
of the domains in `org_profile.dns_hygiene.domains` (or of every base domain the
run derives from its scope, when that list is empty).

## Approved scan scope per tenant

Since #226 a scan target is checked against the tenant's **approved scanning
scope** (`tenant_scan_scopes`, migration `0025`), not only against target
syntax. Without it the platform accepted any well-formed CIDR or FQDN from any
tenant — including `169.254.169.254/32`, the provider's cluster ranges, or a
third party's network — and could not afterwards answer whether that tenant
had been entitled to scan it.

The scope is a list of allow/deny entries, each stamped with who approved it
and when. Three rules decide a target:

- **Deny beats allow**, by overlap. A range that intersects a denied one at all
  is refused, so `10.0.0.0/8` is not a way to reach a denied `10.1.2.0/24`.
- **Allow is containment.** A range is permitted only if it fits entirely
  inside one allowed range; a partly approved range is not partly approved.
- **No entries means no scanning.** A tenant with an empty scope starts no
  scan at all, not even one that would have used the installation's default
  target files.

Domain entries are suffixes: `example.com` covers `example.com` and its
subdomains. The literal `*` is the explicit any-value wildcard for either kind.

The check runs three times. Twice in the API: when the targets are submitted,
and again inside `start_scan` at the moment the scan actually starts — which is
what covers the schedule dispatcher, whose targets were stored days earlier and
may no longer be inside a scope that has since been narrowed. The third is
inside the run itself, on the addresses the scan is really about to touch
([below](#the-third-barrier-inside-the-run-244)). Refusals are recorded in the
access-decision journal (`GET /api/auth/events?outcome=denied`, admin) with the
offending targets in `detail`.

### Upgrading an existing installation

Enforcement is fail-closed, so migration `0025` **grandfathers every tenant
that exists at upgrade time** with an explicit allow-all scope (`0.0.0.0/0`,
`::/0`, `*`) stamped `approved_by = migration-0025`. Nothing stops scanning on
upgrade, and the permission is a row an admin can see and narrow rather than an
implicit rule in the code. Tenants created *after* the upgrade start with no
scope and cannot scan until one is approved.

Read and narrow a scope (platform admin):

```http
GET /api/tenants/{tenant_id}/scan-scope
PUT /api/tenants/{tenant_id}/scan-scope
{"entries": [
  {"effect": "allow", "kind": "cidr", "value": "203.0.113.0/24", "note": "engagement 2026-Q3"},
  {"effect": "allow", "kind": "domain", "value": "customer.example"},
  {"effect": "deny", "kind": "cidr", "value": "169.254.0.0/16", "note": "cloud metadata"}
]}
```

`PUT` replaces the whole scope in one transaction and stamps the caller on
every resulting row — a scope is evaluated as a set, so applying a narrowing
entry by entry would leave a window in which a half-applied set is enforced.
An admin narrowing a grandfathered tenant should therefore send the entries
they want to keep, not only the ones they are adding.

Recommended order per tenant, after the upgrade:

1. `GET .../scan-scope` and confirm the `migration-0025` rows are still there.
2. Agree the ranges and domains the engagement actually covers.
3. `PUT` that list, keeping a deny entry for cloud metadata (`169.254.0.0/16`)
   and for any range of your own infrastructure the tenant must never touch.
4. Start one scan and confirm it is accepted; a refusal answers `403` and names
   the offending target.

### The third barrier: inside the run (#244)

The two checks above both happen before the scan starts, and both decide about
*names*. The scanner resolves those names again when it runs — minutes later
for an ad-hoc scan, hours later for a scheduled one — and the record in between
belongs to the scanned party, not to you. A name that was in scope at admission
can be pointing at a denied address by the time the scan reaches it.

Since #244 the approved scope travels with the job and is enforced a third
time, inside the run:

- `start_scan` writes the tenant's scope to `state/job_inputs/<job_id>/scan_scope.json`
  and passes it to the pipeline as `--scan-scope`. For an agent job it rides the
  claim response beside `ranges.txt` and `domains.txt`, and the worker writes it
  out on its own host.
- **Resolved addresses are filtered against deny entries only**, exactly as the
  API filters them. Approving `customer.example` is its own permission and says
  nothing about the addresses behind it, so requiring them to also sit inside an
  approved CIDR would refuse every domain-scoped engagement.
- **Names and ranges get the full check**, including the ones discovery added
  after admission — CT subdomains, Cloudflare zone imports and ASN ranges are
  targets no API check has ever seen.
- **The default target files are now covered.** A run with no target overrides
  reads the installation's own files; the API never opens them, but the scanner
  does, and it now holds the scope while it does.
- **A refused target is dropped, not fatal.** This is not the authorization
  boundary — the agent host already runs whatever it is handed — it is the last
  point at which the real target list is known. Failing the whole run instead
  would let a third party's DNS change end an engagement. The exception is a
  scope with **no entries**, which stops the run with `INPUT_ERROR` rather than
  quietly producing an empty result.
- **Refusals are journalled.** The run writes `scan_scope_denied.json` into its
  output directory (always, even when nothing was refused, so "filtered and
  found nothing" is distinguishable from "never filtered"). The scanner has no
  database, so the entry in `auth_events` is written when the results land —
  `GET /api/auth/events?outcome=denied`, attributed to whoever requested the
  scan, with `dropped by the scanner` in `detail`.

A run started outside the API — `python -m scanner.main` with no `--scan-scope`
— has no tenant behind it and is not filtered. An **agent older than #244**
ignores the extra input and its runs are likewise unfiltered; upgrade the
workers before narrowing a scope you intend the runs to respect.

One limit remains: deny entries for addresses that must never be reached still
belong in the agent's network policy as well, not only here. The pipeline
filter runs in the same process as the scan and is a control over what that
process aims at, not a boundary around what it can reach.

## Alerts and exports

Supported integrations include Slack/Telegram summary alerts, SMTP, DefectDojo,
and report artifacts. Configure credentials only through secrets or environment
injection. Test notification delivery with non-sensitive data before enabling
production findings.

## Retention

Retention must cover all stateful layers:

| Layer | Retain/backup |
|---|---|
| Run filesystem/PVC | Raw artifacts, reports, checkpoints |
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory, risk snapshots, the append-only audit trail |
| ClickHouse | Analytical vulnerability and port history |
| NATS | Pending jobs and ingest messages |

Set retention according to legal, operational, and privacy requirements. Scan
artifacts can contain internal hostnames, IPs, software versions, and
vulnerability evidence.

### ClickHouse analytical data retention (ROADMAP #187)

ClickHouse tables `shapoclyack.shapoclyack_vulnerabilities` and `shapoclyack.shapoclyack_open_ports`
define a table-level TTL policy:
```sql
TTL timestamp + INTERVAL 90 DAY
```
`shapoclyack.shapoclyack_controls` (the org_profile control matrix, one row per
control per run) keeps 365 days instead: a control trend is only useful across
release cycles, and the rows are a few hundred bytes each.
Expired partitions and rows are merged and deleted automatically in the background
by ClickHouse without requiring external cron scripts. To modify the retention window,
run:
```sql
ALTER TABLE shapoclyack.shapoclyack_vulnerabilities MODIFY TTL timestamp + INTERVAL 180 DAY;
ALTER TABLE shapoclyack.shapoclyack_open_ports MODIFY TTL timestamp + INTERVAL 180 DAY;
ALTER TABLE shapoclyack.shapoclyack_controls MODIFY TTL timestamp + INTERVAL 180 DAY;
```

### Scan run artifact retention (ROADMAP #187)

Scan artifacts written to `output_dir/runs/<run_id>/` accumulate over time on persistent storage.
An in-process retention worker runs every `OCTO_RUN_RETENTION_INTERVAL_SECONDS` (1h) and
deletes expired run directories whose age exceeds `OCTO_RUN_RETENTION_DAYS` (30).

- Age is determined from `run_meta.json` timestamps (`finished_at`, `started_at`) or directory mtime.
- `0` days disables the reaper.
- Safe across multiple API replicas (directory removal is idempotent and fail-soft).

### Audit-trail immutability and retention (#327, #329)

`audit_events` is the administrative trail: what was changed, by whom, with the
value before and after. Migration `0037_audit_events` installs triggers that
refuse every `UPDATE`, `DELETE` and `TRUNCATE` on it:

```
ERROR:  audit_events is append-only: DELETE refused (#329)
```

(`TRUNCATE` has its own statement-level trigger. A row trigger never fires for
it, so a `DELETE`-only guard would leave the whole trail removable in one
statement.)

**Read what that buys carefully.** Out of the box it stops *a bug in the API*,
unconditionally. It stops *someone holding the API's database credential* only
once `audit_events` is owned by a role the API does not run as — an owner may
drop its own triggers, and the owner check below is satisfied by whoever owns
the table. The manifests in `k8s/` connect the API, the migration initContainer
and the retention example to the same superuser role (`octo`), so on a stock
deployment the property is "the API cannot rewrite its own trail by accident",
not "cannot rewrite it at all". The GRANT layout below is what turns the second
into a true statement, and the verification after it is how you prove it landed.

The one way past it is `audit_events_prune(cutoff timestamp)`, a `SECURITY
DEFINER` function. It sets a transaction-local GUC that the trigger honours, and
the trigger *also* requires the effective user to be the table's owner — true
inside the definer function, false for anyone who merely sets the GUC
themselves. So the escape hatch is the function, and **`EXECUTE` on the function
is the privilege to guard**. (The alternative, `ALTER TABLE … DISABLE TRIGGER`
around the delete, was rejected: it needs ownership anyway, takes an ACCESS
EXCLUSIVE lock for the length of the sweep, and opens the table to *every*
session while it is off.)

Retention is therefore a **separate job with its own credentials**, not the API:

```
python -m api.services.audit_retention --days 365
```

`--days` defaults to `OCTO_AUDIT_EVENT_RETENTION_DAYS` (365). `0` is refused
rather than read as "delete everything" — the value that means "keep forever" in
the configuration must not become "keep nothing" because a variable was unset in
the job's environment. Run it from a `CronJob` (weekly is plenty; the sweep is
idempotent) using the retention role, not the API role. A worked example —
CronJob plus the separate Secret holding that role's DSN — is
[`k8s/shapoclyack/examples/audit-retention-cronjob.example.yaml`](../k8s/shapoclyack/examples/audit-retention-cronjob.example.yaml);
it is not in the base kustomization, because applying it before the GRANT layout
above would either fail on every run or run as the API's role and prove nothing.

#### Recommended GRANT layout

The migration does not create roles — it does not know what this installation
calls them, and a migration that invents them fails on every installation whose
names differ. Apply this once, substituting your own role names:

```sql
-- FIRST, and the step the rest depends on: move the table and both functions
-- off the API's role. A migration cannot do this — it runs as the role that
-- would have to be given up — and without it every REVOKE below is undone by
-- the fact that an owner may re-GRANT and drop triggers at will.
CREATE ROLE shapoclyack_audit_owner NOLOGIN;
ALTER TABLE audit_events OWNER TO shapoclyack_audit_owner;
ALTER SEQUENCE audit_events_id_seq OWNER TO shapoclyack_audit_owner;
-- The prune function is SECURITY DEFINER: it runs as *its* owner, and the
-- trigger's owner check is what makes that the only way to delete a row. Owned
-- by the API's role, it would run as the API.
ALTER FUNCTION audit_events_prune(timestamp without time zone)
  OWNER TO shapoclyack_audit_owner;
ALTER FUNCTION audit_events_immutable() OWNER TO shapoclyack_audit_owner;

-- The API may append to the trail and read it back. Nothing else — TRUNCATE
-- named explicitly because REVOKE ALL is easy to narrow later by accident.
REVOKE ALL ON TABLE audit_events FROM shapoclyack_api;
REVOKE TRUNCATE ON TABLE audit_events FROM shapoclyack_api, PUBLIC;
GRANT SELECT, INSERT ON TABLE audit_events TO shapoclyack_api;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO shapoclyack_api;

-- And it may not reach the escape hatch. (REVOKE … FROM PUBLIC is already done
-- by the migration; this is the explicit statement of the same thing.)
REVOKE EXECUTE ON FUNCTION audit_events_prune(timestamp without time zone)
  FROM shapoclyack_api;

-- The retention job, and only it, may prune.
GRANT EXECUTE ON FUNCTION audit_events_prune(timestamp without time zone)
  TO shapoclyack_audit_retention;
```

The migration initContainer runs as the API's role in the shipped manifests, so
re-run the ownership statements after any future migration that recreates the
table or the functions.

A superuser can still do anything at all; what this layout buys is that the
credential in the API's Secret is not enough.

#### Verifying it after a deploy

Two checks, and the first is the one that matters — it is what separates a real
split from an installation where nothing changed:

```sql
-- 1. As anyone: who owns the table? This must NOT be the API's role.
SELECT pg_get_userbyid(relowner) AS owner
  FROM pg_class WHERE relname = 'audit_events';
--   owner
-- ------------------------
--  shapoclyack_audit_owner

-- 2. As the API's role, with the escape hatch's GUC deliberately set — this is
--    what an attacker holding the API's credential would try, and a plain
--    DELETE without the SET proves nothing, because it fails for the table's
--    owner too:
BEGIN;
SET LOCAL shapoclyack.audit_retention = 'on';
DELETE FROM audit_events WHERE id = (SELECT min(id) FROM audit_events);
-- expected: ERROR ... audit_events is append-only: DELETE refused (#329)
TRUNCATE audit_events;
-- expected: ERROR ... audit_events is append-only: TRUNCATE refused (#329)
ROLLBACK;
```

If check 1 returns the API's role, check 2 will still fail — the trigger's owner
test is against the *table's* owner — but it is not evidence: that role can drop
the trigger and repeat the delete. Proof for an auditor is check 1, then check 2,
then the grants in `\dp audit_events` and the function ACL in
`\df+ audit_events_prune`.

**Not done here, deliberately:** a hash chain over the rows (`prev_hash`/`hash`).
It only detects tampering by someone who could bypass the trigger *and* the
grants — i.e. the database's owner or a superuser — and to be a chain at all it
would have to serialise every audit write behind one lock, which is a
throughput cost paid on every administrative request. If an installation needs
tamper-evidence against its own DBA, ship the rows off-box (the NDJSON export
into a WORM bucket or a log pipeline) rather than hashing them in place.

### ClickHouse ingest consumer subjects (#230)

Stream `INGEST` carries the whole `ingest.>` tree, but the ClickHouse worker
only wants scan results. Its durable consumer therefore filters on
`ingest.results.>`; the S8 endpoint-inventory subject
(`ingest.endpoint_inventory.{tenant}`) and the legacy `ingest.raw_results`
duplicate of every result no longer reach it.

JetStream will not change the filter subject of an existing durable, so the
consumer was renamed `octo-ch-ingest` → `octo-ch-ingest-results`. The API
creates the new one on start. **Delete the retired consumer after the upgrade**,
otherwise it keeps a pending count that no one drains:

```
nats consumer rm INGEST octo-ch-ingest
```

The new durable starts at `DeliverPolicy.ALL`, so it replays whatever the
stream still retains. That is safe to repeat: both ClickHouse tables are
`ReplacingMergeTree` keyed on what the transform emits, and every publish
carries a `Nats-Msg-Id`.

### Risk snapshot retention (#229)

`risk_score_snapshots` (migration `0023`) gains one row per tenant on every
finished run, plus one per manual `POST /api/vulnerabilities/risk-history/snapshot`.
The table arrived after #187 closed, so nothing bounded it until #229: the
service had a `prune_snapshots()` that only its own unit test ever called.

An in-process sweep runs every `OCTO_RISK_SNAPSHOT_RETENTION_INTERVAL_SECONDS`
(6h) in every API replica and deletes snapshots older than
`OCTO_RISK_SNAPSHOT_RETENTION_DAYS` (90), across all tenants. `0` days disables
the sweep, as does `OCTO_RISK_SNAPSHOT_RETENTION_ENABLED=false`.

The delete is a range delete on `(tenant_id, recorded_at)`, so replicas sweeping
the same rows is a no-op for whichever loses. Keep the window at or above the
window the console charts: `/risk-history` defaults to the last 90 points, and a
shorter retention silently shortens the trend line.

### Screenshot retention


Web screenshots (ROADMAP P4.4) are the other automatic policy. A PNG of a
login page can still hold names after the DOM overlay, so pixels must not
live as long as the rest of a run directory.

The API walks `output_dir/runs/*/screenshots/*.png` every
`OCTO_SCREENSHOT_RETENTION_INTERVAL_SECONDS` (1h) and unlinks files whose
age — the older of the PNG mtime and `run_meta.json` — exceeds
`OCTO_SCREENSHOT_RETENTION_DAYS` (14). `screenshots.json` is kept: it names
what was captured, not the pixels. `0` days disables the reaper.

Several API replicas may sweep the same tree; a missing file is a no-op.
Disabling `OCTO_SCREENSHOT_RETENTION_ENABLED` stops the worker; existing
PNGs stay until the run directory is pruned.

The stage itself is off by default (`screenshots.enabled`). Turning it on
needs Playwright + Chromium on the scanner host (`pip install playwright &&
playwright install chromium`). Without that binary the stage writes
`skipped_reason: playwright.unavailable` and no files. Capture is not in
the default image.

PNG download is operator-or-higher. A viewer requesting
`/api/runs/{id}/download/screenshots/…png` gets `404`, same as a missing
file.

### Endpoint inventory retention

Endpoint inventory is the one layer with an automatic policy. The API runs an
in-process sweep every `OCTO_ENDPOINT_RETENTION_INTERVAL_SECONDS` (6h) that,
per tenant:

- deletes `endpoint_software_items` for snapshots received more than
  `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` (90) ago, keeping the
  snapshot summary row — submission history, digests, counts, and collector
  warnings stay queryable;
- deletes `endpoint_software_changes` older than
  `OCTO_ENDPOINT_INVENTORY_CHANGE_RETENTION_DAYS` (365) — the audit trail
  deliberately outlives the raw software rows it was derived from.

A device's current snapshot is never pruned regardless of age: it backs the
diff for that device's next submission, so pruning it would report a quiet
endpoint's entire software list as freshly installed.

Sizing: one snapshot row plus up to
`OCTO_ENDPOINT_INVENTORY_MAX_SOFTWARE_ITEMS` (5000) software rows per accepted
submission, bounded per agent by
`OCTO_ENDPOINT_INVENTORY_RATE_LIMIT_PER_HOUR` (12). At one daily snapshot of
~1500 packages per endpoint, 10,000 endpoints hold roughly 1.35 billion
software rows over the 90-day window — plan for a daily-or-slower collection
cadence, or shorten the window, before scaling past a few thousand endpoints.

Runbook:

- **Storage growing faster than expected** — check
  `octo_endpoint_inventory_software_items` (entries per snapshot) and
  `octo_endpoint_inventory_submissions_total{result="accepted"}`. Lower the
  collection cadence on the Lariska side first; shorten
  `OCTO_ENDPOINT_INVENTORY_SNAPSHOT_RETENTION_DAYS` second.
- **Sweep not running** — the System page shows "Last Retention Sweep"; a
  never-run sweep means `OCTO_ENDPOINT_RETENTION_ENABLED` is off or the API
  pod restarted within the interval. The worker is in-process, so with several
  API replicas each one sweeps; deletes are idempotent, so overlap is safe.
- **Sweep too heavy** — lower `OCTO_ENDPOINT_RETENTION_BATCH_SIZE`; each
  statement deletes at most that many rows.
- **Rollback** — retention deletes are irreversible; restore from the
  PostgreSQL backup. Disable the sweep (`OCTO_ENDPOINT_RETENTION_ENABLED=false`)
  before investigating an unexpected data-loss report so the next interval
  cannot compound it.
- **Ingestion rejected** — `octo_endpoint_inventory_submissions_total{result}`
  separates `rate_limited`, `too_large`, `conflict`, and `invalid`. A body over
  `OCTO_ENDPOINT_INVENTORY_MAX_BODY_BYTES` is refused with `413` from the
  `Content-Length` header alone; a request without `Content-Length` is refused
  with `411` and never buffered.

Agent results upload rejected: an archive over
`OCTO_AGENT_RESULTS_MAX_BODY_BYTES` is refused with `413` from the
`Content-Length` header alone, before the multipart body is read; an upload
without `Content-Length` gets `411`. An archive that passes the transport cap
but whose tar headers add up to more than 512 MiB expanded is refused as
`archive expands to more than ... bytes` — the job stays in flight and the run
directory is not created, so the agent may retry with a smaller archive. Raise
the transport cap for a legitimately large run; the expansion ceiling is a
constant (`api/services/results_ingest.MAX_UNCOMPRESSED_BYTES`) because the
shared `output_dir` is what it protects.

Tenant offboarding: endpoint data has no bespoke delete/export flow and follows
whatever general tenant-deletion mechanism the platform adopts. The endpoint FK
chain cascades from `tenants` (migration `0006_endpoint_fk_cascade`), so
deleting a tenant row removes its devices, identifiers, snapshots, software
rows, and change events; a linked asset being deleted only nulls the device's
`asset_id`.

## Agent installation and upgrade

An agent can be installed three ways: by hand from the snippets on `/agents`
(systemd, Docker, Kubernetes — press **Generate key** there first, since the
snippets open with a `<PROVISIONING_KEY>` placeholder), by running the
installer directly, or by letting the API push it over SSH.

```bash
curl -sSL https://<api-host>/api/agent/install.sh | sudo bash -s -- --server https://<api-host> --key <provisioning-key> --tenant <tenant-id>
```

`scripts/install-agent.sh` covers Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, Alpine
and Arch, and takes `--agent-id`, `--install-dir`, `--docker`, `--nats-url` and
`--key-stdin` as options (`--help` lists them).

`--key-stdin` reads the provisioning key from standard input instead of taking
it as `--key`. Prefer it wherever the caller can write to stdin — an argument is
readable by every local user on that host for as long as the process runs. The
SSH push always uses it.

With `--docker` it is a thin wrapper: it writes `/etc/shapoclyack/agent.env`
(`0600`) and runs `ghcr.io/onixus/shapoclyack:latest` as the container
`shapoclyack-agent` (`--restart always`, host network, `--env-file` pointing at
that file), then exits. The credential is in the env file rather than in `-e`
arguments, which would be in the docker client's own argv.

Without it, the native path installs Python and a virtualenv under
`/opt/shapoclyack-agent`, creates a `shapoclyack` system account, writes
`/etc/shapoclyack/agent.env` (`0600`, owned by that account), and — where
systemd is present — installs and enables `shapoclyack-agent.service`
(`Restart=always`, `EnvironmentFile=/etc/shapoclyack/agent.env`). Without
systemd the agent is started with `nohup` and is **not** restarted on boot; on
such a host, supervise it yourself.

**The native path does not ship the agent source.** The API serves no agent
bundle, so the package has to come from somewhere explicit: pass
`--bundle-url <URL>` with a tarball containing the `agent` package, or stage
that package in the install directory beforehand. With neither, the installer
**fails** and says why — it will not leave systemd restarting a worker that
cannot import its own module. Before starting the service it runs
`import agent.worker` and checks the unit is still active three seconds after
start, because `Type=simple` means "started" on its own proves nothing. Use
`--docker` (or the Kubernetes snippet) for a host that has no checkout.

**Where the provisioning key ends up.** On the target it lives in
`/etc/shapoclyack/agent.env` (`0600`, owned by the `shapoclyack` account) and
nowhere else: the systemd unit is `ExecStart=…/venv/bin/python -m agent` with a
mandatory `EnvironmentFile`, so the key is not in the agent's argv for the life
of the process. It is still on the command line if you invoke the installer
with `--key` yourself — use `--key-stdin`, or accept that the key is in your
shell history and in the host's process list while the installer runs. Rotate
the key if the host is shared.

The variables in `agent.env` are the ones `agent/worker.py` reads:
`OCTO_API_URL`, `OCTO_AGENT_PROVISIONING_KEY`, `OCTO_AGENT_ID`,
`OCTO_TENANT_ID`, `OCTO_NATS_URL`. Earlier versions of the installer wrote
`OCTO_SERVER_URL` / `OCTO_PROVISIONING_KEY` and passed `--server` / `--key` /
`--tenant` to `python -m agent.worker`; the worker accepts none of those flags,
and `agent/worker.py` had no `__main__` guard, so that unit started a process
that did nothing and exited 0 — forever, under `Restart=always`. The guard is
there now, so both `python -m agent` and `python -m agent.worker` run the
agent, but the flags in an old unit are still wrong: **an agent installed by an
older installer needs a re-run of this one.**

### Agent lifecycle: disable, quarantine, deregister

An agent has two states at once, and they answer different questions
([#308](https://github.com/onixus/Shapoclyack/issues/308)):

- **What it reports** — `idle` / `busy` / `error`, with `stale` derived from
  `last_seen_at` against `OCTO_AGENT_STALE_SECONDS`. Written by the agent.
- **What you decided** — `lifecycle_status`: `active`, `disabled` or
  `quarantined`. Written only by a tenant **admin**, through
  `PATCH /api/agents/{id}` or the **Agent State** controls in the agent's
  drawer on `/agents`.

A `disabled` or `quarantined` agent is refused job claims, result uploads and
inventory submissions with `403` and the reason you typed. Its **heartbeat is
still accepted**: the heartbeat response is the only channel that reaches a
running agent, so it is where the agent learns why it is being refused, and
refusing it too would drop the agent out of the fleet view at the moment you
are watching it. The agent logs the reason once and backs off to one poll every
five minutes rather than one per second — over NATS as well as over HTTP, and
at start-up as well as mid-run.

The state survives re-registration *and* a re-exchange of the provisioning key:
the exchange reads the lifecycle state too, so a restarted host is refused a
fresh token rather than coming back under a new id. Only `PATCH … {"status":
"active"}` puts it back, and that clears the reason.

**What quarantine does not stop.** A job the agent claimed *before* you
quarantined it keeps running on the host — nothing on the target is killed —
and its results upload is then refused, so the archive is lost and the job
stays `running` until its lease expires and it is requeued for another agent.
That is deliberate: accepting the upload would mean a quarantined host still
writes scan output into the tenant. If the run matters more than the
quarantine, wait for the job to finish before switching the state.

**Deregistering is weaker than it looks.** `DELETE /api/agents/{id}` removes
the row; it does not stop the remote process, and it does not revoke anything.
The host still holds its provisioning key and a JWT valid for up to
`OCTO_AGENT_JWT_EXPIRE_MINUTES`, so it re-registers on its next poll and the
delete was a pause. Two ways to make it stick, depending on what you mean:

| You want | Do this |
|---|---|
| This host must stop working, the rest of the fleet must not | `PATCH /api/agents/{id}` → `quarantined`. Survives restarts; the host keeps its credential but can claim nothing |
| This host is gone and its credential must die with it | `DELETE /api/agents/{id}?revoke_key=true` — revokes the key it registered with, which also invalidates the JWTs already minted from it, at once. **Check `other_agents_on_key` first**: one key commonly provisions a fleet, and revoking it stops every one of them |
| The key itself is compromised | `POST /api/tenants/{tenant_id}/provisioning-keys/{key_id}/revoke` — every agent that registered with it is refused on its next request |

The delete response says which of these happened, and both it and `GET
/api/agents/{id}` carry `other_agents_on_key` — how many *other* agents hold
the same key, which is exactly what `revoke_key=true` would strand. The agent
drawer shows that number the moment the checkbox is ticked, before the delete. `provisioning_key_id: null,
key_revoked: false` means there was no key on record to revoke: an agent that
registered before this was tracked, or a legacy `OCTO_AGENT_TOKEN` one, which
has no per-agent credential at all. Those agents record a key the first time
they re-register.

**Rotating provisioning keys.** Keys minted from now on expire after
`OCTO_PROVISIONING_KEY_TTL_DAYS` (90 by default). `GET
/api/tenants/{tenant_id}/provisioning-keys` reports `expires_at` and
`expires_soon` (within 14 days), which is the list to work from. **Keys minted
before this feature have `expires_at: null` and never expire** — nothing
back-dates them, because stranding a fleet on a deadline nobody was told about
is worse than a key that outlives its usefulness. Find them in that list,
re-install the agents against a fresh key, then revoke the old one.

**Revoke before you re-provision, not after.** An `agent_id` is bound to the
key it first registered with, so an exchange asking for that id under a
*different* key answers `403` while the old key is still active — that refusal
is what stops one key's holder impersonating another key's agent. Revoking the
old key releases the id (and stops its live JWTs in the same move), after which
the new key adopts the host under its own name. Re-provisioning first leaves
the agent unable to authenticate until you get to the revocation.

### SSH push deployment

`POST /api/agent/deploy/ssh` (tenant **admin** since
[#231](https://github.com/onixus/Shapoclyack/issues/231), and the **Deploy
agent** dialog in the UI) runs the same installer from the API: verify the
target's host key → connect → mint a tenant provisioning key → run the
installer on the target, feeding it the key on stdin → wait up to 30 s for the
agent's first heartbeat. The API runs the OpenSSH client (`ssh`,
`ssh-keyscan`); the `api` and `aio` images install `openssh-client` for it.
Images before `0.43-0828` inclusive shipped no SSH client at all, and every
deployment from them failed at the host-key probe with `HostKeyUnavailable`.
Paramiko is used instead when it happens to be installed, but it is not a
declared dependency and the images do not carry it.

**What the target needs.** Three things a live run against a real host
(2026-09-02) made explicit, in the order the deployment meets them:

- The user's login shell does not matter: the remote command is wrapped in
  `sh -c`, so a fish or zsh login shell only passes one argument through.
  (Before that wrapper the first live run exited 127 under fish.)
- A non-root user needs **passwordless sudo** (`sudo -n`). A sudo that prompts
  would consume the provisioning key arriving on stdin as its password guess,
  so the deployer never lets it prompt; on a host where `sudo` asks, the run
  fails at `Installation failed` with `sudo: a password is required` in the
  remote log. Root over SSH needs no sudo.
- The installer needs an agent package. The API serves none, so a native
  (systemd) install through this route ends with `No agent package available`
  unless an `agent` directory is already staged in `/opt/shapoclyack-agent`;
  `use_docker: true` avoids that by running the published
  `shapoclyack-scanner` image (`AGENT_IMAGE` overrides it), which is the
  shape this route can complete unattended today.

**Host key verification.** The first deployment to a host is refused unless the
request names the fingerprint you expect:

```bash
# On the target, the authoritative answer:
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Send that as `expected_host_key` (`SHA256:…`), or press **Read from host** in
the dialog and compare what it reports against the line above before accepting
it. The probe (`POST /api/agent/deploy/ssh/host-key`) authenticates to nothing
and pins nothing: it reports what answered, which is a claim, not a
verification. On a match the key is pinned in `agent_ssh_host_keys` for that
tenant and target, and later deployments need no fingerprint.

A host whose key no longer matches the pin is a `409` naming both fingerprints,
and nothing is sent to it. If the host genuinely was rebuilt, confirm that with
whoever owns it, then drop the pin — tenant **admin**, the same bar as
deploying ([#241](https://github.com/onixus/Shapoclyack/issues/241)):

```bash
curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" \
  "$OCTO_API/api/agent/deploy/ssh/host-key?host=10.0.0.5&port=22"
```

The response is the pin that was removed, so the fingerprint you stopped
trusting is in front of you. The next deployment to that host needs
`expected_host_key` again, which is the point: a rebuilt machine is re-verified
against the target rather than silently re-trusted.

This used to be a `DELETE` against `agent_ssh_host_keys` in Postgres. That
required database access — a privilege an order of magnitude above running an
agent fleet — so the predictable substitute was to pass whatever fingerprint
the target offered as `expected_host_key`, which leaves the check switched on
and meaning nothing. **Do not do that.** Read the key on the host itself.

Both halves are journalled: the removal and the pin that replaces it appear in
`GET /api/auth/events?outcome=trust_change` (platform admin), each with the
tenant, the target and the fingerprint. That *pair* is what separates a planned
rebuild from a substitution after the fact — one host, two fingerprints, and
the operator who decided.

**Where a deployment may point.** Both the probe and the run open a TCP
connection to a host and port taken from the request body, so both are checked
against a target policy first ([#240](https://github.com/onixus/Shapoclyack/issues/240)).
It is not the webhook policy: agents live inside private networks, so RFC1918
is allowed here. Refused with `403` (and a row in
`GET /api/auth/events?outcome=denied`) are this platform's own reflection —
loopback, link-local, multicast, the unspecified address — a port outside
`OCTO_AGENT_DEPLOY_SSH_PORTS` (default `22,2222`), and any host the tenant's
approved scan scope denies. If your fleet listens on another port, name it in
`OCTO_AGENT_DEPLOY_SSH_PORTS` rather than working around the refusal; see
[configuration.md](configuration.md#environment-variables).

Operational limits worth knowing before relying on it:

- deployment runs are rows in `agent_deployments`, so the status poll answers on
  any replica and survives a restart; the last 100 runs per tenant are kept,
  each with its last 500 log lines, and a run in another tenant answers `404`;
- SSH credentials cross the API and are used for the run only — nothing is
  persisted. A password reaches `ssh` through `SSH_ASKPASS`, never as an
  argument;
- **the SSH account must reach root without being asked for a password.** The
  installer is invoked with `sudo -n` when the SSH user is not root, so a target
  whose sudo would prompt fails fast rather than reading the provisioning key
  off stdin as a password guess. Give the account NOPASSWD for the installer, or
  deploy as root. There is no sudo-password field on the request: one was
  accepted and silently ignored, which is worse than not offering it;
- a heartbeat that has not arrived within the verification window is reported as
  a warning, not a failure: the install may still be fine, so check `/agents`.

### Upgrade

`POST /api/agents/{id}/upgrade` (the drawer's **Upgrade** button) sets
`upgrade_requested` on the agent record. That is a marker for the operator
surface — no channel carries it to the host, and the agent does not act on it.
The upgrade itself runs on the host. `scripts/update-agent.sh` is not installed
by the installer — copy it to the target and run it as root, telling it where
the new package comes from:

```bash
sudo bash update-agent.sh --bundle-url https://internal.example/shapoclyack-agent.tar.gz
```

It reads `/etc/shapoclyack/agent.env`, refreshes the virtualenv's build tooling,
replaces the `agent` package from that tarball, verifies the result imports, and
restarts `shapoclyack-agent.service` or the `shapoclyack-agent` container. With
no `--bundle-url` it refuses to run unless you pass `--restart-only`, which
refreshes dependencies and restarts **without** changing the agent package and
reports exactly that. There is no self-update: nothing polls the server for a
new version. For a Docker install, pull the new image and re-run the installer
with `--docker` (or roll the Kubernetes deployment).

**Removing an agent** from `/agents` (`DELETE /api/agents/{id}`) only forgets the
registration. Stop `shapoclyack-agent.service` (or the container) on the host
first, otherwise the next heartbeat registers it again.

## Sessions and revocation

Since [#314](https://github.com/onixus/Shapoclyack/issues/314) a console token
is checked against the account row on every request, so revocation is
immediate rather than "when it expires":

| You want | Do |
|---|---|
| One person out of everything, now | `PUT /api/users/{username}/disabled {"disabled": true}` |
| One person's sessions ended, account untouched | `POST /api/users/{username}/sessions/revoke-all` (admin) |
| Your own sessions ended everywhere | `POST /api/auth/sessions/revoke-all` |
| This browser signed out | `POST /api/auth/logout` — the console does it for you |

Disabling, deleting, demoting and a password change already end that account's
sessions on their own — when they actually change something: a `PUT` that
re-asserts the role or the disabled flag an account already has leaves its
sessions alone, so a reconcile loop against a directory does not sign the
tenant out on every pass. The route list is in
[api-and-rbac.md](api-and-rbac.md#sessions-logout-and-revocation).

**If Postgres is unreachable**, the check cannot be made and authenticated
requests answer `503` with `Retry-After: 5`, not `401`. That distinction is
operational: a 401 would sign every console in the fleet out over a database
restart, and the consoles could not sign back in either. Nothing is revoked by
an outage — sessions resume as they were once the store answers again.

**After the upgrade to #314.** Tokens minted before it carry no version claim
and keep working until they expire (up to `OCTO_JWT_EXPIRE_MINUTES`, 8 hours by
default) — the migration deliberately does not sign everyone out mid-rollout.
If your threat model does not allow that, run `revoke-all` for every account
once the rollout is complete:

```bash
# every account but yours, from a platform-admin token
ME=admin  # the account $TOKEN belongs to
for u in $(curl -sf -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/users \
             | python3 -c 'import json,sys; print(" ".join(u["username"] for u in json.load(sys.stdin)))'); do
  [ "$u" = "$ME" ] && continue
  curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
    "http://localhost:8080/api/users/$u/sessions/revoke-all" || echo "FAILED: $u"
done
# last, and only now: your own sessions, this token included
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/auth/sessions/revoke-all || echo "FAILED: $ME"
```

The order matters and the skip is not cosmetic. `/api/users` is sorted by
username, so an `admin` running the loop over itself would revoke its own
token on the first iteration and every call after it would answer 401 — which
`curl -sf` reports by exiting non-zero and printing nothing, leaving a run that
signed out one account looking exactly like a run that signed out all of them.
Hence `|| echo "FAILED: $u"` as well: a silent loop is the failure mode here.

### Resetting a lost second factor

An account that has enrolled TOTP and lost the phone cannot sign in and cannot
turn the factor off — `POST /api/auth/mfa/disable` asks for a live code by
design. The recovery codes issued at enrolment are the first answer; when those
are gone too, a **platform admin** clears it
([#315](https://github.com/onixus/Shapoclyack/issues/315)):

```bash
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/users/$USER/mfa/reset
```

**The reset is itself behind a step-up** (#315): if the admin running it has a
second factor of their own and has not proved it in the last
`OCTO_MFA_STEPUP_MINUTES`, the call is refused with `403` — and `curl -sf`
reports that by exiting non-zero and printing nothing, which at three in the
morning reads as "the database is broken". Prove it first and use the token
that comes back:

```bash
TOKEN=$(curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}' \
  http://localhost:8080/api/auth/mfa/verify | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

The console does this for you: a refused action raises a dialog asking for a
code, after which you repeat the action.

It deletes the secret
and the recovery codes and bumps the account's `token_version`, so every
session that account has open ends — including any opened by whoever has the
phone. It is recorded as `user.mfa_reset` in the administrative trail, which is
the row a review looks for: it is the only way a factor comes off an account
without the factor.

Verify the account before you do it. This route is the whole reason MFA has a
help-desk bypass, and the trail records who used it:

```bash
curl -sf -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8080/api/audit?action=user.mfa_reset"
```

If `OCTO_MFA_REQUIRED_ROLES` names the account's role, its next login is a
session confined to the enrolment flow, so the reset does not leave it locked
out — it leaves it in front of the setup page.

### Break-glass local login

On an installation with SSO configured, `OCTO_LOCAL_LOGIN=break-glass` reserves
password login for the accounts named in `OCTO_BREAK_GLASS_USERS`. Everyone
else gets the same `401 Invalid credentials` a wrong password gets — the mode
is public in `GET /api/auth/sso`, the account list is not.

Set it up so the emergency door exists *before* the emergency:

```bash
OCTO_LOCAL_LOGIN=break-glass
OCTO_BREAK_GLASS_USERS=breakglass
```

`break-glass` with an empty list is the same thing as `disabled` and warns at
startup in `prod` — the moment to discover that is not during an IdP outage.
Give the break-glass account its own strong password, its own second factor,
and nothing else: it is a credential nobody uses day to day.

Each such login announces itself in four places, because they are read by
different people at different times:

| Where | What to look for |
|---|---|
| Administrative trail | `GET /api/audit?action=auth.break_glass_login` |
| Login trail | `GET /api/auth/events` — `reason=break_glass_login` |
| Metrics | `octo_break_glass_logins_total` — **alert on any increase**, this is not a series to graph |
| API log | `WARNING … Break-glass password login by …` |

A Prometheus rule along these lines is the intended use:

```yaml
- alert: ShapoclyackBreakGlassLogin
  expr: increase(octo_break_glass_logins_total[5m]) > 0
  labels: { severity: critical }
  annotations:
    summary: "A break-glass password login bypassed SSO"
    description: "Confirm it was expected; see GET /api/audit?action=auth.break_glass_login"
```

Recording is deliberately fail-soft: if the audit write fails, the login still
succeeds and the failure is logged. An operator reaching for the emergency door
is usually doing it because something is already broken, and a database that
cannot take the row is a realistic version of that — refusing the login would
turn a degraded installation into an unreachable one.

### Rotating the JWT signing key

`OCTO_JWT_SECRET` used to be unrotatable in practice: changing it invalidated
every console session at the moment of the rollout, and (while
`OCTO_AGENT_JWT_SECRET` is unset, which is the default) every agent token with
them. `OCTO_JWT_SECRET_PREVIOUS` makes it a window instead.

1. **Generate the new key** — `openssl rand -hex 32`.
2. **Deploy both.** Set `OCTO_JWT_SECRET` to the new value and
   `OCTO_JWT_SECRET_PREVIOUS` to the old one (comma-separated if you are
   retiring more than one). From this deploy on, new tokens are signed with the
   new key and old ones still verify.
3. **Wait out the window.** `OCTO_JWT_EXPIRE_MINUTES` for console sessions
   (default 8 hours) and `OCTO_AGENT_JWT_EXPIRE_MINUTES` for agents (default 2
   hours). Every replica must carry the same pair throughout — a replica
   missing the previous key refuses the tokens its neighbours accept.
4. **Deploy again with `OCTO_JWT_SECRET_PREVIOUS` removed.** The old key stops
   being trusted. To end the window early instead of waiting, revoke every
   account's sessions as above and then remove the variable.

Both `OCTO_JWT_SECRET_PREVIOUS` entries and the current key are checked at
startup: a `prod` API refuses to start if the list carries the shipped
development secret or repeats the current key.

Rolling back to a pre-#314 image mid-window costs the sessions signed with the
retired key: that build knows only `OCTO_JWT_SECRET`, which by then holds the
new value, so the tokens signed with it keep working and the older ones do not.
Nobody is locked out — they log in again — but plan the rollback for the same
reason you planned the rotation.

## Logs and observability

### Log format, level, and the request id

`OCTO_LOG_FORMAT=json` puts the API and the agent on one line-per-object
format; `text` (the default) keeps them readable in a terminal.
`OCTO_LOG_LEVEL` sets the level for both — see
[configuration.md](configuration.md#environment-variables). The API hands the
same formatter to uvicorn, so `uvicorn.access` is in the chosen format too
instead of uvicorn's own colourised one.

```json
{"ts":"2026-09-09T11:04:21.318452Z","level":"INFO","logger":"uvicorn.access","msg":"10.42.0.7:53114 - \"GET /api/runs?token=*** HTTP/1.1\" 200","request_id":"3f9c1a7be0d4472f8a1e6b2c5d8e0f11"}
```

Every request carries a correlation id. `X-Request-Id` is taken from the
caller when it is safe to echo and to log — at most 128 characters of
`[A-Za-z0-9._:@=+/-]`, so a uuid, a ULID, a W3C `traceparent` or nginx's
`$request_id` all pass — and a fresh uuid4 is minted otherwise. An id that
fails that check is *replaced*, not escaped: a client whose id we had to
rewrite cannot correlate on it anyway. The value comes back in the response's
`X-Request-Id`, appears in the `request_id` field of every log line the request
produces, and is set on the OpenTelemetry span as `shapoclyack.request_id` when
tracing is on.

Following one request from a user report:

```bash
# the id the console (or your ingress) reported — the console appends it to
# the error toast for a 5xx, and it is on the response as `X-Request-Id`
kubectl -n network-scan logs deployment/shapoclyack-api --tail=-1 \
  | grep '"request_id":"3f9c1a7be0d4472f8a1e6b2c5d8e0f11"'

# text format: the id is the bracketed field after the logger name
kubectl -n network-scan logs deployment/shapoclyack-api | grep '\[3f9c1a7b'
```

Both formats timestamp in **UTC**: `json` writes an ISO string ending in `Z`,
`text` a `%Y-%m-%d %H:%M:%S,mmm` followed by a literal `Z`. Neither reads the
pod's `/etc/localtime`, so a text line and a JSON one line up with each other
and with everything else in the cluster.

`OCTO_LOG_LEVEL=DEBUG` raises the application's loggers, not every library's.
`sqlalchemy.engine` and `sqlalchemy.pool` stay at `WARNING`, `paramiko`,
`httpx`, `httpcore` and `nats` at `INFO` — the SQL statement log prints every
statement *with its bound parameters*, and on this schema those are bcrypt
hashes, `token_hash` values and session ids. Chasing a bug at DEBUG must not
write the credential store to stdout. The floor only holds the level down: a
quieter `OCTO_LOG_LEVEL` still applies to them. `OCTO_LOG_LEVEL=NOTSET` is
refused (it would mean "no level check at all") and reads as `INFO`.

Beyond the request id, correlate by tenant, `job_id`, `run_id`, and `agent_id`
— a scan outlives the request that started it, and those are the keys that
follow it into the agent's own logs.

### Secret redaction, and what it does not cover

A `logging.Filter` on the process's handler rewrites each record's **rendered**
message before it is formatted, on both the API and the agent. It renders the
record first (so a secret passed as a `%s` argument is masked exactly like one
written into the format string) and masks four shapes:

| Shape | Example in, example out |
|---|---|
| Keyed pairs — `password`, `passwd`, `pwd`, `token`, `secret`, `api_key`, with `=` or `:`, quoted or not | `token=abc123` → `token=***`, `{"password": "hunter2"}` → `{"password": "***"}` |
| The `Authorization` header, scheme word included (`Bearer`, `Basic`, `Token`, `ApiKey`, `Digest`, `Negotiate`), however it was written | `Authorization: Token abc` → `Authorization: ***`, `{"Authorization": "Bearer abc"}` → `{"Authorization": "***"}` |
| A bare `Bearer` credential with no header name | `Bearer abc.def` → `Bearer ***` |
| Credentials in a URL, empty user included | `postgresql://octo:s3cret@db/octo` → `postgresql://octo:***@db/octo`, `redis://:s3cret@cache` → `redis://:***@cache` |
| JWTs in compact serialization | `eyJhbGciOi….payload.sig` → `eyJ***` |

A separator is *required* for the keyed pairs, so "the token is invalid"
survives intact — a redaction that eats the only line saying what went wrong
protects nothing.

This is a backstop, not a licence to log credentials. Its limits, stated
plainly:

- It masks the log **message** (a `logging.Filter`) and the **formatted
  traceback** (the formatter, in both `text` and `json`). Anything written to
  stdout by something other than the `logging` module — a subprocess the
  scanner runs, a library printing directly — never passes through it.
- It is syntactic. A secret logged with no key, no scheme and no recognisable
  shape (`LOG.info(value)`) looks like ordinary text and is emitted as it is.
- It runs on the handlers this process installs. A sidecar or an operator that
  adds its own handler to the root logger gets unfiltered records.

Useful checks:

```bash
curl --fail http://localhost:8080/api/health   # console-facing status, always 200
curl --fail http://localhost:8080/readyz       # 503 when a dependency is down
kubectl -n network-scan get pods,jobs,cronjobs
kubectl -n network-scan logs deployment/shapoclyack-api --tail=200
```

`GET /metrics` exposes the Prometheus series used by the dashboards and alerts
referenced above. It answers anyone who can reach the API unless
`OCTO_METRICS_TOKEN` is set, in which case the scraper sends
`Authorization: Bearer <token>` — for the Prometheus Operator that is
`bearerTokenSecret` in `k8s/shapoclyack/examples/servicemonitor.example.yaml`. Objectives, PromQL, and the error-budget policy built on these
series are in [slo.md](slo.md); scrape wiring for Kubernetes is in
[k8s/README.md](../k8s/README.md). Endpoint-inventory series (all labels are low-cardinality —
no agent, device, asset, tenant, or product names):

| Series | Use |
|---|---|
| `octo_endpoint_inventory_submissions_total{result}` | Accept/replay/reject breakdown; alert on a sustained non-`accepted` share |
| `octo_endpoint_inventory_ingest_duration_seconds` | Ingest latency |
| `octo_endpoint_inventory_software_items` | Entries per snapshot; drives storage growth |
| `octo_endpoint_inventory_software_changes_total{event_type}` | Installed/removed/updated volume |
| `octo_endpoint_devices{state}` | Active vs. stale endpoints; alert when the stale share climbs |
| `octo_endpoint_retention_deleted_total{table}` | Rows the sweep removed |
| `octo_endpoint_retention_run_duration_seconds` | Sweep cost; alert if it approaches the sweep interval |

## Backup and disaster recovery

### Recovery objectives and verification status

The base deployment takes a logical PostgreSQL backup every day at 02:15 UTC.
That schedule gives a **design RPO of at most 24 hours** for PostgreSQL, assuming
the scheduled backup succeeds and is uploaded. The **RTO target is 60 minutes**
for restoring Postgres + API into an isolated namespace (the path
`scripts/restore-postgres.sh` implements). ClickHouse and the artifact PVC have
no in-repo snapshot object — see below.

| Measure | Target | Last measured |
|---|---:|---:|
| PostgreSQL RPO | <= 24 h | 3 min (backup `2026-08-20T09:21:29Z` → recovery `2026-08-20T09:24:32Z` on kind `shapoclyack-dev`; the CronJob still bounds worst-case at 24 h) |
| Full base-stack RTO | <= 60 min | 31 s (`recovery_seconds` from the restore script: `pg_restore` + API migrate rollout) |
| PostgreSQL `pg_restore` duration | n/a | < 1 s (`db_restore_seconds=0` at 1 s resolution; 82 KiB custom dump of the live lab: 5 assets, 10 identifiers, 3 users, 2 jobs) |
| Restore drill date | n/a | 2026-08-20 |

Namespace `shapoclyack-restore`, overlay `k8s/shapoclyack/overlays/kind-restore`.
Row counts after restore matched the source. JetStream was **not** replayed —
Postgres is the durable store; see [NATS / JetStream recovery](#nats--jetstream-recovery).
ClickHouse and `scanner-data` were not snapshotted (kind `local-path` has no
`VolumeSnapshotClass`); that remains an install-specific choice, not an unmeasured
Postgres drill.

### PostgreSQL scheduled backup

`k8s/shapoclyack/base/backup/postgres-cronjob.yaml` runs `pg_dump` in custom
format, creates a SHA-256 checksum, and uploads both files to S3 or an
S3-compatible object store. `concurrencyPolicy: Forbid` prevents overlapping
backups. The backup credentials come from `Secret/shapoclyack-backup`; the
External Secrets Operator example in
`k8s/shapoclyack/examples/externalsecret.example.yaml` documents the expected
keys and keeps credentials out of manifests.

For a one-off validation, create a Job from the CronJob and inspect its result:

```bash
kubectl -n network-scan create job \
  --from=cronjob/shapoclyack-postgres-backup \
  shapoclyack-postgres-backup-manual
kubectl -n network-scan logs -f job/shapoclyack-postgres-backup-manual
```

A successful run writes `backup_success` with the object prefix. Verify the dump
and its `.sha256` object exist in external storage before treating the run as a
usable recovery point.

When kube-state-metrics and Prometheus Operator are installed, apply
`k8s/shapoclyack/examples/prometheusrule-backup.example.yaml`. It uses
`kube_cronjob_status_last_successful_time` to alert when the last successful
backup is older than 26 hours and also reports failed backup Jobs. This keeps a
missed backup visible without an operator manually listing CronJobs.

### PostgreSQL restore drill

Always test recovery in a namespace that is separate from production. The
restore script refuses the base `network-scan` namespace unless
`ALLOW_PRODUCTION_RESTORE=1` is deliberately set.

1. Create an isolated namespace and deploy the same Shapoclyack Postgres + API
   version that will consume the backup. On the kind lab that is
   `kubectl apply -k k8s/shapoclyack/overlays/kind-restore` (namespace
   `shapoclyack-restore`, no NodePort, no NATS/ClickHouse/scan Jobs). Elsewhere:
   same image tag as the source, Postgres and API secrets present, ingress and
   external integrations disabled. Wait until Postgres is Ready and the API has
   rolled out once — the restore script then replaces that empty schema.
2. Download `shapoclyack.dump` and `shapoclyack.dump.sha256` from the same backup
   prefix. On the kind lab, dump the source with the CronJob's `pg_dump` flags
   (`--format=custom --compress=6 --no-owner --no-privileges`) and a SHA-256
   sidecar; S3 upload is not required for the restore path itself.
3. Run:

```bash
scripts/restore-postgres.sh \
  --namespace shapoclyack-restore \
  --backup ./shapoclyack.dump \
  --checksum ./shapoclyack.dump.sha256
```

The script verifies SHA-256, restores with `pg_restore --clean --if-exists`,
restarts the API Deployment so its `migrate` init container brings the schema to
head (`python -m api.db.migrate`, see
[Upgrade and rollback](#one-supported-path-to-the-current-schema)), waits for a
successful rollout, then verifies database
readiness, `alembic_version`, and the `tenants` table. Record the emitted
`db_restore_seconds` and `recovery_seconds` values in the verification table
above.

Calculate the measured RPO from the timestamp represented by the selected
backup object to the declared incident/drill recovery point. Record both the
selected backup timestamp and the drill start time so another operator can
reproduce the calculation.

A restore that completes `pg_restore` but cannot start the current API image is
a failed drill, not a successful database restore.

### Artifact PVC recovery

`scanner-data` contains reports, raw scan artifacts, checkpoints, and other run
state. The base PVC intentionally does not assume a storage vendor or a
`VolumeSnapshotClass`, so the repository cannot safely provide one universal
snapshot object.

For production, configure CSI `VolumeSnapshot` or the storage provider's native
snapshot/backup mechanism for `scanner-data`. Restore the snapshot to a **new
PVC in the isolated namespace** and mount that PVC into the recovery deployment
before validating reports or attempting resume. Do not overwrite the production
PVC during a drill.

Snapshot cadence must be chosen so artifact retention is compatible with the
PostgreSQL RPO. If PostgreSQL is restored to time T but the artifact PVC is much
older, runs referenced by the database may have missing files.

### ClickHouse recovery

The base ClickHouse StatefulSet is single-replica and stores data under
`clickhouse-data`. Production installations must choose one of these recovery
methods and test it with the PostgreSQL drill:

- ClickHouse native `BACKUP`/`RESTORE` to configured external object storage; or
- a CSI/storage-provider snapshot of `clickhouse-data`, taken while writes are
  quiesced or using a storage mechanism documented as application-consistent.

Restore ClickHouse into the isolated namespace before enabling the ingest
worker. Validate `/ping`, expected tables, and representative historical
queries. Do not infer ClickHouse consistency merely because a PVC snapshot
object exists.

### NATS / JetStream recovery

JetStream is an operational queue, not the source of truth for assets or scan
history. Recover durable stores first. Only then decide whether a JetStream
snapshot is required for messages that were accepted but not durably processed.

Shapoclyack publishes with stable `Nats-Msg-Id` values and uses idempotent
result/event identifiers. The EVENTS stream also has a duplicate window. A
restored stream can nevertheless contain messages whose effects already exist
in PostgreSQL or ClickHouse, especially when the queue snapshot and database
backup were taken at different times.

Recovery order:

1. restore and validate PostgreSQL, artifact PVC, and ClickHouse;
2. keep API/worker consumers that mutate durable state paused while inspecting
   the JetStream snapshot boundary;
3. identify queued messages newer than the durable recovery point and preserve
   their original `Nats-Msg-Id` / idempotency identifiers;
4. restore/replay only the required range;
5. re-enable consumers and verify duplicate/idempotency counters and durable
   record counts before exposing the recovered stack.

Never replay a restored stream by republishing every message with new message
IDs. That defeats the deduplication mechanisms the recovery procedure relies
on.

### Per-tenant job stream

Job offers are published on `jobs.scan.{tenant}` (stream `JOBS`, unchanged
subject filter `jobs.>`), and each tenant has its own durable pull consumer
`octo-agents-{tenant}` filtered to that subject. An agent learns its tenant
from the API — the `tenant_id` in the `POST /api/auth/agent/token` response,
or the registration response for an agent still on the legacy shared
`OCTO_AGENT_TOKEN` (tenant `default`) — and binds only that consumer.

A tenant id that is not a valid NATS subject token (anything outside
`[A-Za-z0-9_-]`, notably a `.`) is hashed into `h_<sha256[:32]>`, the same
encoding `ingest.results.{tenant}` and `events.asset.{tenant}.{kind}` use. Both
the API and the agent compute it, so `nats consumer ls JOBS` on an install with
older tenant ids shows `octo-agents-h_…` names; map one back with
`python -c "import hashlib;print(hashlib.sha256(b'<tenant id>').hexdigest()[:32])"`.

Operational consequences:

- **Upgrading.** The API no longer creates the shared `octo-agents` consumer,
  but does not delete one that exists — an agent on an older build keeps using
  it during a rolling upgrade. Once the whole fleet is upgraded, remove it and
  the six legacy tokens in the NATS `agent` permission list
  (`base/nats/configmap.yaml`):

  ```bash
  nats consumer rm JOBS octo-agents
  ```

  Offers already sitting on the bare `jobs.scan` subject are only readable
  through that consumer, so drain the queue before removing it (or accept that
  those jobs stay claimable over HTTP, which they always are).

- **A new tenant's first job.** The consumer is created by the API on the first
  offer for that tenant, and by the agent when it binds — whichever happens
  first. Neither is a startup step, so `nats consumer ls JOBS` on a fresh
  install lists nothing until the first agent job.

- **NATS unavailable.** Unchanged: the offer is not published, the job stays
  queued, and any agent picks it up over HTTP claim
  (`POST /api/agent/jobs/claim`), which enforces the tenant server-side.

- **Credentials are still shared.** One `agent` NATS user serves every tenant.
  The permission list bounds it to `octo-agents-*` consumers on `JOBS`, which
  is what an agent needs, but it does not bind a NATS credential to one tenant.
  Per-tenant NATS users are a separate change.

### NATS TLS

The client port runs in the clear in `base/` because the kind stand has no CA
and a `tls {}` block without a key file is a startup error. Apply
`examples/nats-tls-configmap-patch.yaml` anywhere the port is reachable from
outside the cluster: remote agents send their NATS password in the connection
URL, and every job offer — ranges, domains, the approved scope — crosses that
link. That file carries the cert-manager `Certificate` to copy and the
StatefulSet mount.

Clients (API and agent) read `OCTO_NATS_TLS_CA`, `OCTO_NATS_TLS_CERT`,
`OCTO_NATS_TLS_KEY` and `OCTO_NATS_TLS_HOSTNAME`; see
[configuration.md](configuration.md). A `tls://` URL with none of them set
verifies against the system trust store, which is all a publicly issued
certificate needs. `nats-server` reads the certificate files once at boot, so a
cert-manager renewal takes effect on the next
`kubectl -n network-scan rollout restart sts/shapoclyack-nats` unless a
reloader sidecar is in place.

### Pod disruption and API availability

`k8s/shapoclyack/base/api-pdb.yaml` sets `minAvailable: 1`. With the current base
`replicas: 1`, a voluntary eviction is blocked rather than reducing API
availability to zero. Production overlays that need drain-friendly maintenance
should run two or more API replicas; the scheduler is already protected by its
PostgreSQL advisory-lock leadership mechanism.

## Enrichment data in a release build

Image builds refresh GeoIP/ASN/CVSS4/EPSS/KEV before the image is sealed. A
third-party feed being down does not fail that build and should not: refusing to
produce an image because someone else's server is having a bad day trades a
small problem for a larger one. What changed
([#246](https://github.com/onixus/Shapoclyack/issues/246)) is that it no longer
happens quietly.

Two outcomes, deliberately not the same thing:

- **A source was unreachable.** The previous data — the last good refresh, or
  the committed baseline — is still in place and still usable. The build prints
  a warning, `scripts/fetch-enrichment.sh` exits `1`, and the manifest records
  `origin: stale` for the datasets it could not refresh. `GET /api/system`
  reports that per dataset, so the degradation is visible on a running install
  and not only in a build log.
- **A required dataset is missing or is a stub.** `cvss4`, `epss`, `kev` and
  `exploit` feed the risk model; with a handful of CVEs in them it keeps issuing
  confident verdicts while knowing almost nothing. The script exits `2`.

The vendor advisory datasets (`advisories_debian`, `advisories_ubuntu`) are in
the manifest under the same rules but are **not required**, so neither outcome
above fails a build on their account. They are also the only source the refresh
does not fetch by default: see
[software→CVE matching](software-cve-matching.md#getting-a-real-dataset-onto-an-installation)
for why, and for how to turn it on. A release image therefore ships them as
`origin: seed`, `usable: false` — present, loadable, and not coverage.

The second one fails a **release** build and warns on a dev build. The switch is
the `ENRICHMENT_STRICT` build argument, which defaults to `0`; the publish
pipeline (`Jenkinsfile.publish`) passes `1` for every image in the matrix. That
line is drawn at publication rather than at CI because a published image outlives
everyone's memory of the log that built it — a branch build is inspected the day
it runs, `ghcr.io/onixus/shapoclyack-aio:latest` is pulled for months.

```bash
# Reproduce the release gate locally.
docker build --build-arg ENRICHMENT_STRICT=1 -f Dockerfile.allinone -t shapo-aio:strict .

# Check what a built image actually shipped, without starting it.
docker run --rm shapo-aio:strict cat /app/scanner/data/enrichment-manifest.json

# …or on a running install, which also covers a mounted enrichment volume.
curl -sH "Authorization: Bearer $TOKEN" http://localhost:8000/api/system \
  | jq '.enrichment[] | {name, origin, source, updated, entries, usable, age_days}'
```

`usable` is there because age and entry count together still cannot answer the
question for a dataset that ships with a seed: eight advisories written into the
image an hour ago are present, current and worthless. It is the build's own
verdict against the per-dataset floor in `scripts/enrichment_manifest.py`, and
it is `null` when no manifest was found rather than `false` — "nothing recorded"
is not "the data is bad".

An `origin` of `stale` or `seed` on a freshly deployed release is the signal to
look at the build log or run the refresh CronJob by hand
(`k8s/shapoclyack/base/enrichment/cronjob.yaml`) — the data is usable, but it is
not what the release intended to ship.

`seed` means the last run that *attempted* this dataset found the committed
baseline, not merely that today's run did not fetch it. A run that never tried —
the advisory opt-in being off, which is also the case on every API rollout,
since the API's enrichment initContainer runs the same script without the flag —
leaves the origin alone. So `origin: fetch` on a dataset the CronJob refreshed
last night survives a rollout, and `seed` stays a statement worth acting on.

## Upgrade and rollback

### Probes, and what a rollout costs

Three probes on the API pod, with three different questions (#331):

| Probe | Path | Asks |
|---|---|---|
| `startupProbe` | `/livez` | Has the process finished booting? `create_app()` loads the tenant store and bootstraps accounts, so a cold start against a busy PostgreSQL takes a while; 5s × 30 attempts before the pod is failed, and neither probe below runs until this one passes |
| `livenessProbe` | `/livez` | Is this process wedged? Dependency-free on purpose — a database outage must not restart every replica and put a crash loop on top of the outage |
| `readinessProbe` | `/readyz` | Can this replica serve? PostgreSQL `SELECT 1`, plus a NATS round trip and a ClickHouse query where those URLs are set. Failing it removes the pod from the Service instead of killing it |

`/api/health` is neither probe any more. It stays the console- and
`HEALTHCHECK`-facing endpoint, always `200`, and its `status` now reads `ok` or
`degraded` from the same sweep `/readyz` runs.

The rollout itself: `maxUnavailable: 0, maxSurge: 1`, so the replacement pod is
ready before the old one goes away — with `replicas: 1` the default would have
taken the only API pod down first and made every upgrade a short outage. On the
way out, `terminationGracePeriodSeconds: 45` and a `preStop` sleep of 5s:
endpoint removal and `SIGTERM` are dispatched concurrently, so without the pause
the process starts shutting down while proxies still route to it.

A rollout that stalls at `Init:0/1` is the migration lock, not a probe — see
below. A pod that starts and never becomes ready is `/readyz` answering `503`:

```bash
kubectl -n network-scan exec deploy/shapoclyack-api -- \
  python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/readyz').read())"
```

The `checks` map in the body names which dependency failed; a `503` with
`{"postgres":"error"}` is a database problem, not an API one.

### One supported path to the current schema

`python -m api.db.migrate` — `alembic upgrade head` holding a PostgreSQL
advisory lock — run by the `migrate` init container on the API Deployment. Every
replica runs it and they queue on the lock, so a scaled Deployment no longer
starts N concurrent migrations. Each waiter still performs the upgrade after
acquiring the lock: skipping it would leave a replica running against whatever
schema the leader reached before it failed.

`models.Base.metadata.create_all` no longer runs on PostgreSQL. It is restricted
to SQLite, which is the dev and test fallback and is refused in production
anyway. Two ways to build the schema means the two eventually disagree, and the
disagreement is found in production: `create_all` builds today's models while
writing no `alembic_version`, so the database looks migrated to no revision at
all.

`OCTO_MIGRATION_LOCK_TIMEOUT_SECONDS` (default 600) bounds the wait for the lock.
On expiry the init container fails with a message naming the cause instead of
hanging at `Init:0/1`.

### The expand/contract rule

A rolling update runs the new schema against the **old** code: migrations
complete before the first new pod starts, while old pods keep serving. A
migration that removes or renames something the running version still uses takes
the API down during its own upgrade, and takes it down again if the deployment
is rolled back.

Therefore every schema change is split across two releases:

| Phase | Release N (expand) | Release N+1 (contract) |
|---|---|---|
| Add a column | Add it **nullable** or with a default; new code writes it, old code ignores it | Add `NOT NULL` once every row is populated and no old replica is left |
| Remove a column | Stop reading and writing it in code; leave it in the database | Drop it |
| Rename | Add the new name, write both, read the new with a fallback to the old | Drop the old name |
| Change a type | Add the new column, backfill, dual-write | Drop the old column |

The rule to apply when unsure: **release N's migration must leave release N-1's
code working.** That is what makes both the rolling update and the rollback
below safe, and it is the reason a rollback procedure can be short.

### Upgrade

1. Confirm the target image tag exists in GHCR. Images are published by the
   local Jenkins job `shapoclyack-publish` (`Jenkinsfile.publish`), started by
   hand with the release tag as `TAG` — not by pushing a git tag and not by
   `gh release create`. The Actions workflow that used to do it is disabled
   (its triggers are commented out; `workflow_dispatch` remains for a manual
   cross-check). `DRY_RUN` defaults to true, so a first run builds without
   publishing.

   A prerelease is the same tag with an `-alpha<N>`, `-beta<N>` or `-rc<N>`
   suffix (`shapoclyack-0.44-0907-beta1`). It is published exactly like a
   release except that it does **not** move `:latest`, so anything tracking
   `:latest` stays on the last real release. Upgrade to a prerelease by naming
   its tag explicitly; never by following `:latest`. The job reads the tag from
   the local clone, so the tag has to exist there — pushing it to GitHub alone
   is not enough.
2. Take a backup and confirm it is current — see
   [PostgreSQL scheduled backup](#postgresql-scheduled-backup). The rollback
   path below assumes one exists.
3. Read the release's `CHANGELOG.md` entry for migrations. A migration that
   cannot be written in expand/contract form (a genuinely destructive one) is a
   maintenance window, not a rolling update, and must say so in the release
   notes.
4. Update the image tags and apply. Watch the `migrate` init container first —
   it is where a schema problem appears:

   ```bash
   kubectl -n network-scan logs deploy/shapoclyack-api -c migrate --follow
   kubectl -n network-scan rollout status deploy/shapoclyack-api
   ```

5. Verify: `GET /api/system` reports the new version, `GET /metrics` is served,
   and `sum(octo_scheduler_is_leader)` is exactly 1 across replicas.

### If a migration fails halfway

`api/db/migrations/env.py` wraps the whole upgrade in **one** transaction
(`context.begin_transaction()` around `run_migrations()`, not per revision), and
PostgreSQL executes DDL transactionally. A failing statement therefore rolls back
every revision in that run, and `alembic_version` still names the revision the
database was on before it started — there is no half-applied schema to
reconcile, and the init container fails instead of letting the API start on one.

The exception to be aware of: a migration that does its own commit, or that
operates outside the transaction (a concurrent index build), is not covered by
this. Any such migration must say so in its docstring, because it changes what
this section promises.

1. Read the init container's log — it names the failing revision.
2. Do **not** delete the pod repeatedly hoping it passes: a migration that
   failed on data will fail identically on the next attempt, and the advisory
   lock means each retry also blocks any other replica.
3. If the failure is environmental (disk, connection, lock timeout waiting for
   an unrelated long transaction), fix that and let the rollout retry.
4. If the failure is in the migration itself, roll back the image tag to the
   previous release (below). By the expand/contract rule the previous code runs
   against the current schema, so this is a safe place to stand while the
   migration is corrected.
5. `alembic downgrade` is **not** part of the routine path. Downgrade scripts
   are not exercised by CI and cannot restore data a migration dropped. The
   supported way back from a schema change that must be undone is a restore
   from backup into a fresh namespace — see
   [PostgreSQL restore drill](#postgresql-restore-drill).

### Rollback

```bash
kubectl -n network-scan rollout undo deploy/shapoclyack-api
kubectl -n network-scan rollout status deploy/shapoclyack-api
```

This reverts the code, not the schema — and by the expand/contract rule it does
not need to. The previous release's code runs against the newer schema because
release N's migration was required to leave release N-1 working.

Two consequences worth stating plainly:

- **Rolling back past a contract migration is not supported.** Once the
  contract half of a change has been applied, the code from before the expand
  half no longer matches the database. Roll back at most one release, or
  restore from backup.
- A rollback leaves the schema at the newer revision. That is intended: the next
  attempt at the upgrade is then a no-op on the migration and a plain image
  change.

Verify a rollback the same way as an upgrade, and confirm that jobs claimed by
the newer replicas are still progressing — a lease expiring during the rollout
is requeued by the reaper (P1.4), which is expected and not a failure.

#### Revisions whose downgrade destroys data

A rollback normally does not touch the schema at all, which is what makes it
short. If you nevertheless run `alembic downgrade`, this list is the one to
read first.

| Revision | What its downgrade destroys |
|---|---|
| `0032_endpoint_software_findings` | **Every software finding** (`source = 'endpoint_software'`) and its `vulnerability_events`, tickets and SLA history. The two columns it drops are the only thing telling a software finding from a scan one, so leaving the rows behind is worse than deleting them: after a subsequent upgrade they would read as `source = 'scan'` with `device_id IS NULL`, stop being a `409` on `/verify`, fall out of the inventory fold's lookup and be duplicated wholesale by the next snapshot. The matcher re-creates the findings from the current snapshots on its next run, with new ids and a fresh SLA clock — the work is not lost, the history of it is |
| `0033_software_match_queue_marker` | Only the matcher's queue marker. Every device becomes due at once, so the first tick after the downgrade re-folds the estate. The fold is idempotent, so this is a load spike and not a correctness problem |
| `0035_asset_scan_coverage` | **Every asset's scan-coverage history**: when it was last actually scanned, by which run, and when it was last assessed for vulnerabilities. There is no backfill and there cannot be one — nothing else in the schema records which past run covered which asset — so a downgrade followed by a re-upgrade does not restore them: the whole Coverage block on `/adoption` reads `n/a` again until every asset has been reached by a *new* run, which on a monthly scan cadence is a month of no coverage reading. Nothing else breaks; the findings and the assets themselves are untouched. |
| `0034_vuln_false_positive` | Every false-positive verdict on `vulnerabilities`: the reason, who made it, its evidence, when the suppression expires, and how many times the finding was seen while suppressed. Nothing else in the schema holds them, so they cannot be reconstructed. The affected findings stay `CLOSED`; the downgrade rewrites their `closure_reason` to `manual`, because the older code does not know the `false_positive` value. The `vulnerability_events` trail (`false_positive_set`, `fp_reobserved`, `fp_overridden`) survives, so *that a verdict existed* is still auditable — only the live suppression is gone, and the next scan re-opens the finding. |
| `0036_oidc_pending_states` | Every **in-flight** SSO login: the nonce and the PKCE verifier of an authorization request the browser has not come back from yet. Nothing is lost that matters — a row lives for at most `OCTO_OIDC_STATE_TTL_SECONDS` (10 minutes) and a login whose record is gone is refused and retried. The same is true of the *upgrade*: during the rolling deploy in either direction the old and the new code disagree about where a pending login is kept, so logins begun before the switch and finished after it are refused. No account, membership or session is touched. |

### Legacy JSON state import

`api/services/{jobs,agents}.py` still import pre-P1.2 `state/api_{jobs,agents}.json`
once at startup, renaming them `*.imported` afterwards. That code is a one-time
migration aid for installations upgrading from before the Postgres control
plane. It is scheduled for removal in the **second** release after `0.41`: one
release is not enough, since an installation may skip a version, and keeping it
indefinitely means every future start pays for a path nothing has used in years.
An installation older than that must upgrade through `0.41` first, or accept
that the queued jobs and registered agents in those files are lost — neither is
state that a scan cannot recreate.

### NetworkPolicy decision

`k8s/shapoclyack/examples/networkpolicy-agent.example.yaml` deliberately remains
an example instead of a base resource. NetworkPolicy enforcement and ingress
controller labels vary by CNI/environment, and the platform can legitimately
need environment-specific egress to DNS, S3-compatible backup storage, NATS,
ClickHouse, webhooks, scanners, vulnerability sources, SMTP, or ticketing
systems. Applying a guessed restrictive policy in base can silently break
backup and integrations; applying the current example unchanged would also
permit API ingress from any namespace.

Production deployments should copy/patch the example into their overlay and use
explicit namespace/pod selectors plus the exact external egress destinations
for that environment. Treat the absence of an environment-specific policy as a
production deployment finding, not as a reason to ship a misleading universal
base policy.

#### Revised for ingress to the stateful services (#225)

The reasoning above is about **egress**, and it stands unchanged. Where a pod
is allowed to connect *out* genuinely depends on the installation: DNS resolver
addresses, the S3 endpoint the backup CronJob uploads to, the vulnerability
feeds and webhook targets an operator has enabled, and the scan targets
themselves. Base cannot know any of those, and guessing them breaks backups and
integrations silently. Egress policy stays an overlay concern.

**Ingress to Postgres, ClickHouse and NATS is a different question**, and it
was answered wrongly by lumping it in with egress. The set of legitimate
clients there does not vary by installation — it is written down in the
manifests themselves:

| Service | Port | Legitimate clients |
|---------|------|--------------------|
| Postgres | 5432 | API (incl. its `migrate` init container), backup CronJob |
| ClickHouse | 8123 / 9000 | API |
| NATS | 4222 | API, scanner agents |

That is a closed list, so `k8s/shapoclyack/base/networkpolicy-datastores.yaml`
is a base resource: one `Ingress`-only policy per datastore, default-deny by
omission, allowing exactly the pod labels above. Nothing about it is
environment-specific, and getting it wrong fails loudly (a pod cannot reach its
database) rather than silently, which is the opposite of the egress case.

Two things it does not cover, both by design:

- **Agents outside the cluster.** A pod selector cannot name them. An
  installation that exposes 4222 through a NodePort, LoadBalancer or Ingress
  must add its own `ipBlock` rule for that source. Their authentication is the
  `agent` NATS user either way (below).
- **A CNI that does not enforce NetworkPolicy.** The objects are then inert.
  They were never the only control: every one of these three services now also
  requires credentials, and that is the part that holds regardless of CNI.

**Verified under enforcement.** `k8s/scripts/verify-networkpolicy.sh` is the
proof rather than the argument: it creates a throwaway kind cluster with
Calico (pinned; kindnet does not enforce NetworkPolicy), deploys the real
`overlays/kind-dev`, waits for the API to become Ready — which is the allowed
direction working, since the API reaches all three datastores on the way
there — and then connects from pods the policies must refuse and pods they
must admit. Run on 2026-09-02 against Calico v3.30.3: 16 of 16 rows matched —
an unlabeled pod is refused by Postgres, ClickHouse (both ports) and NATS
4222 and admitted by NATS 8222; a `backup`-labelled pod reaches Postgres and
nothing else; an `agent`-labelled pod reaches NATS and nothing else; the API
pod reaches all three. The datastores' kubelet probes kept passing, as the
manifest's note on host traffic predicted. Needs docker, kind and the
locally built aio image (`scripts/dev-up.sh` builds it); `KEEP=1` leaves the
cluster up for inspection.

## Data-plane credentials

The control plane (JWT, RBAC, tenant scoping) has always been authenticated.
The three stateful services behind it were not: ClickHouse ran the `default`
user with an empty password, `<networks>::/0</networks>` and
`access_management=1`, and NATS had neither `authorization` nor `accounts`. Any
pod in the cluster could read every tenant's raw scan results over 8123,
create ClickHouse users, subscribe to `ingest.results.*` for all tenants, and
publish forged `jobs.scan` offers. Since #225 all three require credentials.

### Where they live

| Secret | Keys | Consumed by |
|--------|------|-------------|
| `shapoclyack-postgres` | `password` | Postgres, API, backup CronJob |
| `shapoclyack-clickhouse` | `password` | ClickHouse StatefulSet, API |
| `shapoclyack-nats` | `api_password`, `agent_password` | NATS StatefulSet, API, agents |

`base/kustomization.yaml` generates dev placeholders for all three, the same
way it always has for Postgres — a fresh `kubectl apply -k` comes up without
any manual step. The placeholders are published in this repository. Override
them with `examples/api-secrets.example.yaml` (or
`examples/externalsecret.example.yaml` with ExternalSecrets) before any install
that holds real scan data.

### Rotating the agent token signing key

Agent JWTs are signed with `OCTO_AGENT_JWT_SECRET`, or with a key derived from
`OCTO_JWT_SECRET` when it is unset ([#312](https://github.com/onixus/Shapoclyack/issues/312)).
Rotate it when an agent host is suspected of being compromised, and rotate it
rather than `OCTO_JWT_SECRET` when the console's own sessions should survive.

1. Set (or change) `OCTO_AGENT_JWT_SECRET` in the API Secret — the same value
   on every replica, or agents will authenticate against some pods and not
   others — and roll the API.
2. Every agent token in the fleet stops verifying at that moment. Nothing else
   has to be done: an agent that meets a `401` re-exchanges its provisioning
   key on its next pass, and one that somehow does not re-exchanges when its
   token expires, within `OCTO_AGENT_JWT_EXPIRE_MINUTES` (default 2 hours).
   Jobs already claimed keep running; their result upload re-authenticates the
   same way.
3. Confirm with `GET /api/agents` that `last_seen_at` is moving again for every
   agent. One that is not has lost its **provisioning key**, not its token —
   mint a new one and re-run the installer on that host.

Revoking a provisioning key is the narrower tool and does not need this: it
stops new exchanges for one agent, while an already-issued token stays valid
until it expires.

NATS has two users rather than one because they are not equally trusted. `api`
owns the whole subject tree. `agent` may open an `octo-agents-*` pull consumer
on the `JOBS` stream, fetch `jobs.scan.{tenant}`, and ack — and nothing else:
it cannot subscribe to `ingest.>` or `events.>`, cannot publish `jobs.scan.*`,
and cannot open a consumer on the `INGEST` stream. A compromised remote agent
therefore cannot read other tenants' results or inject work. It remains one
credential for the whole fleet — see
[Per-tenant job stream](#per-tenant-job-stream). Both users share the global
account: the streams are common to both, and JetStream cannot share a stream
across accounts without export/import plumbing on every subject.

Passwords reach the API and the agents inside the connection URL
(`nats://api:$(NATS_PASSWORD)@…`, `http://default:$(CLICKHOUSE_PASSWORD)@…`),
expanded by the kubelet from a `secretKeyRef` declared **earlier** in the same
container's env list. Any overlay that sets `OCTO_NATS_URL` or
`OCTO_CLICKHOUSE_URL` must declare the matching password variable in the same
patch — a strategic merge places a patch's env entries ahead of the base list,
so relying on the base declaration alone leaves a literal `$(NATS_PASSWORD)` in
the URL.

### Upgrading an existing installation

This is a **breaking change** for any cluster already running Shapoclyack.
Read this before the upgrade, not after.

ClickHouse's password is applied by the config at every start, so the moment
the new StatefulSet rolls, an API still holding a credential-free
`OCTO_CLICKHOUSE_URL` gets `Authentication failed`. NATS is the same: the
broker starts requiring credentials and every existing client is rejected as
unauthorized. Neither restarts the other for you.

1. Create the two new Secrets **first**, with real values, in the namespace:

   ```bash
   kubectl -n network-scan create secret generic shapoclyack-clickhouse \
     --from-literal=password="$(openssl rand -hex 24)"
   kubectl -n network-scan create secret generic shapoclyack-nats \
     --from-literal=api_password="$(openssl rand -hex 24)" \
     --from-literal=agent_password="$(openssl rand -hex 24)"
   ```

   Doing this before `kubectl apply -k` means the generated placeholders never
   touch the cluster. If you apply first, the placeholder passwords are live
   until you replace them and restart — treat that window as a compromise.

2. Apply the overlay. Expect a short outage on the ingest path: NATS and
   ClickHouse restart, the API restarts to pick up the new URLs, and in-flight
   `jobs.scan.*` messages stay in JetStream (the stream is on the PVC and
   survives).

3. **Update every remote agent** that uses NATS job pull. Their
   `OCTO_NATS_URL` needs `agent:<agent_password>@` — an agent left on the old
   URL logs an authorization violation and falls back to nothing; it does not
   silently switch to the HTTP claim path. Agents that already use HTTP claim
   (`OCTO_NATS_URL` empty) are unaffected.

4. Verify:

   ```bash
   kubectl -n network-scan logs deploy/shapoclyack-api | grep -i nats
   kubectl -n network-scan exec sts/shapoclyack-clickhouse -- \
     clickhouse-client --password "$CH_PASSWORD" --query "SELECT 1"
   ```

   An anonymous query must now fail:
   `clickhouse-client --query "SELECT 1"` → `Authentication failed`.

An existing ClickHouse volume keeps whatever SQL-created users
`access_management=1` allowed to be made. `access_management` is now `0`, which
stops new ones being created but does not remove any that already exist. Audit
`SELECT name, storage FROM system.users` on an upgraded install and drop
anything you did not create.

### Transport encryption

Credentials are only half of it: they travel over these links, and so does
every row of scan data. As of
[#309](https://github.com/onixus/Shapoclyack/issues/309) the state is:

| Link | Encrypted | How it is configured |
|---|---|---|
| Console / API ingress | Yes, when you configure it | `spec.tls` + cert-manager in `examples/ingress.example.yaml`; `force-ssl-redirect` sends bookmarked `http://` links back to HTTPS |
| Agent → API | Yes | Plain HTTPS to `OCTO_PUBLIC_BASE_URL`; agents are outbound-only, there is no client certificate |
| API → Postgres | Only if you ask for it | `?sslmode=verify-full` in `OCTO_POSTGRES_URL`; a `prod` start without any `sslmode=` logs a warning |
| API → ClickHouse | Only if you ask for it | `https://` in `OCTO_CLICKHOUSE_URL`. The scheme decides, not the port |
| API → SMTP relay | Yes, verified | `OCTO_REPORT_SMTP_STARTTLS` (default on) with certificate verification; `OCTO_REPORT_SMTP_VERIFY_TLS=false` downgrades it deliberately |
| API / agents ↔ NATS | Yes, when you configure it | `tls://` in `OCTO_NATS_URL` plus `OCTO_NATS_TLS_*`; the broker side is `examples/nats-tls-configmap-patch.yaml`. Plain `nats://` is still accepted and still plaintext — do not expose `:4222` across an untrusted segment without `tls://` |

There is no mTLS anywhere yet: nothing in this repository issues or checks a
client certificate. Where the README once said "mTLS", read "TLS, one-way".

Which ports have to be open for any of it, how egress goes through a corporate
proxy (`OCTO_HTTPS_PROXY`, `OCTO_NO_PROXY`), and where an internal root goes
(`OCTO_CA_BUNDLE`) are in
[network-requirements.md](network-requirements.md) — including why NATS is the
one link a proxy cannot carry, and what an agent does instead
([#359](https://github.com/onixus/Shapoclyack/issues/359)).

**Postgres with a private CA.** `verify-full` needs the CA in the pod, not in
the operator's laptop:

```bash
kubectl -n network-scan create secret generic shapoclyack-postgres-ca \
  --from-file=ca.crt=/path/to/cluster-ca.crt
```

Mount it read-only on the API Deployment (and on the backup CronJob, which
reaches the same server) and point the URL at the mounted path:

```
OCTO_POSTGRES_URL=postgresql+psycopg://scan:...@postgres:5432/shapoclyack?sslmode=verify-full&sslrootcert=/etc/ssl/postgres-ca/ca.crt
```

`verify-full` also checks the hostname, so the certificate's SAN has to carry
the name in the URL — a Service name such as `shapoclyack-postgres.network-scan.svc`,
not the Pod IP. Managed Postgres (RDS, Cloud SQL, Yandex Managed) publishes its
CA bundle; use that file instead of minting one.

### Rotation

Rotating any of these is a rollout, not a Secret edit. `nats-server` reads
`$NATS_*_PASSWORD` once at boot; the API resolves its URLs once at boot.
ExternalSecrets' `refreshInterval` rewrites the Secret and restarts nothing.

1. Update the Secret (or the upstream store).
2. `kubectl -n network-scan rollout restart sts/shapoclyack-nats` /
   `sts/shapoclyack-clickhouse`.
3. `kubectl -n network-scan rollout restart deploy/shapoclyack-api` and any
   agent Deployment.
4. Re-key remote agents outside the cluster.

There is no overlap window: between steps 2 and 3 the old clients are rejected.
Schedule it like a short maintenance window rather than expecting a seamless
rotation.

## Secrets at rest

The credentials this installation holds *for other systems* — a webhook's HMAC
signing key, and the header values that carry a Jira / ServiceNow / DefectDojo
API token — are stored in `webhook_subscriptions`. Until
[#310](https://github.com/onixus/Shapoclyack/issues/310) they were stored as
typed, so a dump, a base backup, a read replica or a shell in the API pod
yielded every tenant's tracker tokens at once. The API-level redaction that was
already there answers a different question: what an API *caller* may read.

They are now envelope-encrypted. Each write mints a 256-bit data key, encrypts
the value with it under AES-256-GCM, and stores that key wrapped by the
key-encryption key (KEK) from `OCTO_MASTER_KEY`:

```
v1:<kek_id>:<b64 wrapped dek>:<b64 nonce>:<b64 ciphertext>
```

`kek_id` is a non-secret label derived from the key, so a row states which key
opens it — which is what makes a rotation resumable and a half-rotated table a
working one.

### What is and is not covered

| Value | Where it lives | At rest |
|-------|----------------|---------|
| Webhook HMAC secret, ticket API token (`webhook_subscriptions.secret`) | Postgres | Encrypted (#310) |
| Configured header values, e.g. `Authorization` (`webhook_subscriptions.headers`) | Postgres | Encrypted (#310) |
| TOTP shared secret of an enrolled account (`users.mfa_secret`) | Postgres | Encrypted (#315), under its own GCM context `users.mfa_secret`, and covered by the same `python -m api.db.reencrypt_secrets` passes |
| Recovery codes (`users.mfa_recovery_codes`) | Postgres | bcrypt hashes — a recovery code is a password |
| Console passwords, service tokens, agent provisioning keys | Postgres | bcrypt / SHA-256 hashes — never reversible, so nothing to encrypt |
| SSH host keys pinned for agent deployment | Postgres | Public keys; not secret |
| `OCTO_OIDC_CLIENT_SECRET`, `OCTO_REPORT_SMTP_PASSWORD`, `OCTO_JWT_SECRET`, the data-plane URLs | Environment (Secret / ExternalSecret) | Not in the database at all — protected by Kubernetes Secret handling, not by this |

The last row is the deliberate boundary: encrypting a value the process reads
from its own environment with a key it reads from the same environment adds
nothing. If one of those ever moves into Postgres, it moves through
`api/services/crypto` on the way.

Encryption protects a *reader* of the database — a dump, a backup, a replica.
It does not protect against someone who can write to it or who can read the
API pod's environment: both have the key.

### Generating the key

```
openssl rand -base64 32     # or: openssl rand -hex 32
```

Put it in `OCTO_MASTER_KEY` in the `shapoclyack-api-users` Secret (see
`k8s/shapoclyack/examples/api-secrets.example.yaml`) or in the matching
ExternalSecret, and roll the API. Every replica must carry the same value.

Under `OCTO_ENV=prod` the API **refuses to start** without it if any
subscription already holds a secret or a configured header — either those rows
are plaintext, which is the problem, or they are encrypted and unreadable. An
installation with no integrations starts with a warning instead, so this does
not demand a key of a deployment that has nothing to protect. Under
`OCTO_ENV=dev` it is always a warning and the values stay plaintext.

That startup answer is about the rows that existed at boot, so it is asked
again on the way in: in `prod` with no key configured, creating or editing a
subscription that carries a secret or a header value is refused (`500`, with
the refusal in the API log) rather than writing the first integration as
typed.

### Encrypting an existing installation

The read path accepts both forms, so this is an online step with no maintenance
window and no migration hook. Deploy the key first, then:

```
kubectl -n network-scan exec deploy/shapoclyack-api -- \
  python -m api.db.reencrypt_secrets --dry-run
kubectl -n network-scan exec deploy/shapoclyack-api -- \
  python -m api.db.reencrypt_secrets
```

Each row is rewritten in its own short transaction under `SELECT … FOR UPDATE`,
and `PATCH /api/webhooks/{id}` takes the same lock, so a concurrent edit from
the console is serialised against the pass rather than lost. An interrupted
pass is resumed by running it again.

### Rotating the KEK

Unlike the data-plane credentials above, this one *does* have an overlap
window — that is what `OCTO_MASTER_KEY_PREVIOUS` is for.

1. Put the new key in `OCTO_MASTER_KEY` and move the current one to
   `OCTO_MASTER_KEY_PREVIOUS` (comma-separated; more than one is allowed).
2. Roll the API. Rows on the old key still decrypt; new writes use the new key.
3. Rewrap what is already stored:
   `python -m api.db.reencrypt_secrets --rotate`. A row whose key is in neither
   variable is left exactly as it was and counted at the end; the command exits
   non-zero and names how many, so the rest of the table is still rotated and
   the exception is visible rather than an abort on the first one.
4. Confirm nothing is left behind, then remove `OCTO_MASTER_KEY_PREVIOUS` and
   roll again:

   ```sql
   SELECT key_id, count(*) FROM webhook_subscriptions
    WHERE secret IS NOT NULL OR headers::text <> '{}' GROUP BY key_id;
   ```

   One row, with the current `kek_id`, means the rotation is complete. A `NULL`
   `key_id` means those rows are still plaintext — run the pass without
   `--rotate` first.

Skipping step 1 and simply replacing the key makes every stored secret
unreadable, which the next section is about. Recovery is putting the old key
back into `OCTO_MASTER_KEY_PREVIOUS`.

### When a row cannot be decrypted

`OCTO_MASTER_KEY_PREVIOUS` dropped one step too early, or a database restored
against a different key: the row names a `kek_id` this process does not have.
That is contained to the row rather than to the tenant.

* the console still lists and edits it — the read path holds no key, because
  the header values are redacted rather than decrypted-then-redacted;
* an event that fans out to it is still queued for every other subscription:
  routing reads `enabled` / `event_kinds` / `min_severity` only;
* its own deliveries **dead-letter on the first attempt** with
  `SecretDecryptionError` instead of consuming `OCTO_WEBHOOK_MAX_ATTEMPTS`.
  They are in the DLQ view (`status=dead`), which is where you find out.

Recovery is the key, not the data: put the key that wrote it back into
`OCTO_MASTER_KEY_PREVIOUS`, roll the API, run
`python -m api.db.reencrypt_secrets --rotate`, then retry the dead letters. If
the key is genuinely gone, nothing can read those values — set the secret and
the header again through `PATCH /api/webhooks/{id}`, which rewrites the row
under the current key.

The `GROUP BY key_id` query in step 4 above finds them before a delivery does:
a `kek_id` that is neither the current key nor one of the previous ones.

### Rolling back to a pre-#310 image

Older code reads `secret` and the header values as opaque strings and would
sign with — or send — the ciphertext. Decrypt first, while the key is still
configured.

Unlike the encrypting passes, this one is **not** an online step: the running
API re-encrypts on every write, so a `PATCH` of a subscription — or a
console edit — after the pass has walked past that row puts it straight back
under the key you are about to remove. Scale the API to zero first, or take it
out of the Ingress and confirm no writes are in flight:

```
kubectl -n network-scan scale deploy/shapoclyack-api --replicas=0
kubectl -n network-scan run reencrypt --rm -it --restart=Never \
  --image=<the image the API runs> --env-from=secret/shapoclyack-api-users \
  --env OCTO_POSTGRES_URL=... -- python -m api.db.reencrypt_secrets --decrypt
```

then roll back the image, scale up again, and apply
`alembic downgrade 0036_oidc_pending_states`, which drops only the `key_id`
column.

### Vault Transit and cloud KMS

`OCTO_MASTER_KEY_PROVIDER` selects where the KEK lives. Only `local` (the
default, `OCTO_MASTER_KEY`) is implemented; `vault-transit`, `aws-kms` and
`gcp-kms` are **named but not built** — setting one refuses at startup with a
message saying so, rather than silently falling back to a local key. What
exists is the interface (`KeyProvider` in `api/services/crypto/envelope.py`):
two methods, wrap and unwrap, which a Transit or KMS client fills in without
any call site changing. Do not plan a deployment around them until an issue
says they ship.
