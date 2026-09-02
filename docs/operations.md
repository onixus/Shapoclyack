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
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory, risk snapshots |
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
Expired partitions and rows are merged and deleted automatically in the background
by ClickHouse without requiring external cron scripts. To modify the retention window,
run:
```sql
ALTER TABLE shapoclyack.shapoclyack_vulnerabilities MODIFY TTL timestamp + INTERVAL 180 DAY;
ALTER TABLE shapoclyack.shapoclyack_open_ports MODIFY TTL timestamp + INTERVAL 180 DAY;
```

### Scan run artifact retention (ROADMAP #187)

Scan artifacts written to `output_dir/runs/<run_id>/` accumulate over time on persistent storage.
An in-process retention worker runs every `OCTO_RUN_RETENTION_INTERVAL_SECONDS` (1h) and
deletes expired run directories whose age exceeds `OCTO_RUN_RETENTION_DAYS` (30).

- Age is determined from `run_meta.json` timestamps (`finished_at`, `started_at`) or directory mtime.
- `0` days disables the reaper.
- Safe across multiple API replicas (directory removal is idempotent and fail-soft).

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

### SSH push deployment

`POST /api/agent/deploy/ssh` (tenant **admin** since
[#231](https://github.com/onixus/Shapoclyack/issues/231), and the **Deploy
agent** dialog in the UI) runs the same installer from the API: verify the
target's host key → connect → mint a tenant provisioning key → run the
installer on the target, feeding it the key on stdin → wait up to 30 s for the
agent's first heartbeat. Paramiko is used when installed, otherwise the OpenSSH
CLI.

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

## Logs and observability

Use structured application logs and correlate by tenant, `job_id`, `run_id`,
and `agent_id`. Do not log secrets or full authorization headers.

Useful checks:

```bash
curl --fail http://localhost:8080/api/health
kubectl -n network-scan get pods,jobs,cronjobs
kubectl -n network-scan logs deployment/shapoclyack-api --tail=200
```

`GET /metrics` exposes the Prometheus series used by the dashboards and alerts
referenced above. Objectives, PromQL, and the error-budget policy built on these
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
  | jq '.enrichment[] | {name, origin, source, updated, entries, age_days}'
```

An `origin` of `stale` or `seed` on a freshly deployed release is the signal to
look at the build log or run the refresh CronJob by hand
(`k8s/shapoclyack/base/enrichment/cronjob.yaml`) — the data is usable, but it is
not what the release intended to ship.

## Upgrade and rollback

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

NATS has two users rather than one because they are not equally trusted. `api`
owns the whole subject tree. `agent` may open the `octo-agents` pull consumer
on the `JOBS` stream, fetch `jobs.scan`, and ack — and nothing else: it cannot
subscribe to `ingest.>` or `events.>`, cannot publish `jobs.scan`, and cannot
open a consumer on the `INGEST` stream. A compromised remote agent therefore
cannot read other tenants' results or inject work. Both users share the global
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
   `jobs.scan` messages stay in JetStream (the stream is on the PVC and
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
