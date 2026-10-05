# Operations

## Run directories

Every scan writes to:

```text
scanner/output/runs/<run_id>/
```

That is where the scanner writes. Where the run *lives* afterwards depends on
`OCTO_ARTIFACT_BACKEND` ([#336](https://github.com/onixus/Shapoclyack/issues/336)):
`local` (the default) keeps it on this volume, and `s3` publishes it to object
storage once the scan finishes, after which each API replica keeps a node-local
working copy of the runs it is asked about. Everything below describes the run
either way — the layout inside it is the same, and so are the paths the console
and the API use to name its artifacts.

A run the API started is filed under its tenant
([#427](https://github.com/onixus/Shapoclyack/issues/427)):

```text
runs/_tenants/<tenant>/<run_id>/     # in the bucket, and under OCTO_OUTPUT_DIR
```

A sensor upload lands there directly; a local scan is moved there from the
flat directory above once it finishes, by the same `run_publications` row a
sensor upload gets (`local-<job_id>`,
[#454](https://github.com/onixus/Shapoclyack/issues/454)). If that move or the
store refuses, the job keeps its outcome and the row retries; once its attempts
are spent the row is `dead`, the job's `error` gains `run not published
(publication local-<job_id>): …`, and the fix is a requeue, not a copy by hand
(*Run publications* below). Two cases still leave a flat run in place, tagged
with its owner so no other tenant reads it, with `run not filed under its
tenant: runs/<run_id> …` on the job: a `runs/<run_id>` that already carried
another run's `tenant.json` when the scan finished, and a scan that finished
after its job had been written off (reaper, restart) — that job keeps the
error it was written off with. A custom `run_id` for
a local scan reserves `runs/<run_id>` when the job is created, so a second
scan asking for the same id is refused rather than written into the first. A scan run with `scanner.main` by hand stays flat — it has no tenant.
`<tenant>` is the tenant id itself, or `h_<hash>` for an id that is not a safe
path segment (ids that predate tenant-id validation).

**Upgrading needs no migration.** Runs already in the flat `runs/<run_id>/`
layout stay where they are and keep being served, to the tenant their
`tenant.json` names (no marker: `default`), exactly as before. Nothing moves
them, on purpose: on S3 a move is a copy and a delete per object, not atomic,
racing replicas that are serving the run meanwhile — and the flat run is
readable as it is. Retention ages both layouts out as usual, so the flat ones
disappear on their own after `OCTO_RUN_RETENTION_DAYS`. Until then, a bucket
policy scoped to `runs/_tenants/<tenant>/` does not cover that tenant's older
runs.

**A rolling update is safe for tenant isolation**, and the shipped manifests
keep `RollingUpdate` (switching to `Recreate` would make every rollout an
outage, #331). While old and new replicas overlap, an old one lists
`runs/_tenants` as if it were a single run. The new code writes
`runs/_tenants/tenant.json` naming an owner no tenant can be (`_tenants`), so
the old replica shows it to no tenant — including a platform admin with a
tenant selected. A platform admin's fleet-wide view on the old replica does
list it, as one odd run holding every tenant's runs; that view already shows
every tenant's runs, so nothing is disclosed that it did not already show, but
expect that entry in the list until the rollout finishes. A downgrade keeps
that entry for good and cannot open the runs written by this release.

The single-run layout (`per_run_output=false`, run id `default`) is the output
directory itself. It is served only while `runs/` does not exist under it;
once any per-run output is there, `default` answers 404 instead of exposing
the runs beneath it.

Two things change for local scans on the local backend. The directory under
`scanner/output/runs/` is empty once the job completes — look under
`runs/_tenants/<tenant>/` instead. And the scanner's own `diff.json` no longer
compares a job's scan with whichever run was last in `latest_run.json`, which
could be another tenant's: that run has moved, so no diff is produced (the
same as on the `s3` backend, where it had already moved into the cache).

The directory can contain:

- run metadata and normalized summaries;
- resolved and alive hosts;
- `l2_discovery.json` when directly attached ARP/mDNS/NetBIOS discovery is enabled;
- open ports and service aggregates;
- `hosts_without_open_ports.json`, the alive inventory that answered discovery but
  exposed no port from this run's scanned set;
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

A tick the tenant's maintenance calendar forbids is deferred to the moment the
block lifts rather than skipped — see
[Maintenance windows and the change freeze](#maintenance-windows-and-the-change-freeze).

## Internal L2 and IPv6 discovery

IPv6 ranges use bounded subnet batching. The shipped `/120` threshold makes a
`/116` sixteen resumable batches; a `/64` is refused because it would require
2^56 of them. This is intentional. A 128-bit address space does not become
finite because somebody put it in YAML. The error names the calculated count
and `batching.max_ipv6_batches`; narrow the target rather than relying on a
partial prefix walk. fping discovery runs separate `-4` and `-6` invocations,
and bracketed IPv6 endpoints remain intact through naabu parsing and reporting.

Directly attached discovery is disabled by default. Enable `discovery.l2` only
on a sensor whose interface is actually connected to the authorized segment.
The stage:

1. selects configured networks that are wholly contained in this run's target
   scope, or derives private/link-local IPv4 targets when the list is empty;
2. refuses networks once their combined usable address count would exceed
   `max_hosts`;
3. runs bounded nmap ARP discovery and records MAC/vendor evidence;
4. optionally probes the ARP-alive hosts for NetBIOS and mDNS names. A policy
   `avoid_ports` entry of 137 or 5353 drops that probe, and `skip_service_probe`
   drops both.

The artifact records every skipped network and reason (`outside_scan_scope`,
`host_cap_exceeded`, missing nmap, or command failure). A sweep that exceeds
`timeout_seconds` is recorded as `arp.failed:TimeoutExpired` (or
`names_skipped_reason` for the name pass) and the run continues without L2
evidence; at a low `max_discover_rate`, size `max_hosts` so that
`max_hosts / max_rate` fits inside `timeout_seconds`. ARP-alive hosts seed the
ordinary discovery result, so a device that ignores routed ICMP/TCP probes still
continues into port scanning. Link-local names are marked `l2`; they are not
misrepresented as forward DNS.

Every report also writes `hosts_without_open_ports.json` and the corresponding
summary count. These are real discovered devices whose scanned port set was
empty, not failed scans. Review them for hosts that only expose an avoided,
UDP-only, or nonstandard service before deciding they are irrelevant.

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
- **A public suffix is never probed**, not even when it is listed in
  `org_profile.dns_hygiene.domains`. The nameservers of `co.uk`, `com.ru` or
  `github.io` belong to a registry, a registrar or a hosting platform, not to
  anyone under them. The seed derived from scope already stops at the
  registrable domain (see below); this refusal is what holds if a suffix gets
  in anyway. It happens before any nameserver is contacted and is recorded as
  `axfr.status: refused`, `reason: public_suffix` (or `not_a_domain_name` for
  an IP literal or similar), with a `refusing AXFR for <domain>` warning in the
  log.
- **A nameserver on a non-public address is refused**, not dialled. NS records
  are written by the scanned party, so `ns1.target.example -> 10.0.0.5` would
  turn the probe into a TCP/53 connection inside the sensor's own network. The
  refusal is logged as `refusing AXFR against <ns>` and recorded in the artifact
  as `status: refused`.
- **Only the checked address is dialled.** The probe speaks AXFR itself over
  one TCP connection to the nameserver's first address — the IP literal that
  passed the check above, IPv6 included — and resolves nothing. It does not go
  through `dnsx`, whose `-axfr` looks up the zone's NS set on its own and
  connects to addresses that were never checked, and it does not follow the NS
  records or glue the zone hands back.
- **Reading the result.** `status: open` means the nameserver sent zone data;
  `records` counts the records between the opening and closing SOA, and a
  non-null `reason` (`transfer_incomplete`, `transfer_capped` at 16 MiB,
  `malformed_response`, `connection_error`) marks the count as a lower bound.
  `status: closed` is the server saying no: `rcode_refused`, `rcode_notauth`,
  `rcode_formerr`, `rcode_notimp`, `rcode_nxdomain`, an empty answer
  (`empty_answer`), a clean hang-up before any answer (`connection_closed`), or
  an SOA…SOA transfer with nothing between (`soa_only`). `status: error` means
  the nameserver could not be checked, not that it is closed: unreachable
  (`connect_failed`, `timeout`, `connection_reset` — a reset may come from a
  middlebox on the sensor's side), `rcode_servfail` or an unknown RCODE, or an
  answer that started and broke off before any record past the SOA.
- **A successful transfer is never written down.** `dns_hygiene.json` records
  only `status: open` and the number of records; the zone itself reaches neither
  the artifact directory nor `scan.log`. If you need the zone contents, transfer
  it yourself with `dig axfr` — the scanner will not keep a copy for you.

Before switching `axfr_probe` on, confirm the engagement covers active testing
of the domains in `org_profile.dns_hygiene.domains` (or of every registrable
domain the run derives from its scope, when that list is empty).

**How the seed is derived.** When a stage's `domains` list is empty, its seed
is the registrable domain of each in-scope name, taken from the Public Suffix
List: `www.bbc.co.uk` gives `bbc.co.uk`, `shop.example.com.ru` gives
`example.com.ru`, `x.github.io` gives `x.github.io` itself. The list is a
snapshot committed at `scanner/pipeline/public_suffix_list.dat` and read from
disk only — a sensor in a restricted network never fetches it — and
`dns_hygiene.json` names the snapshot in `public_suffix_list`. Both sections
of the list are used; the private one is what keeps hosting platforms
(`github.io`, `herokuapp.com`) from becoming seeds. Two consequences worth
knowing:

- a stale snapshot does not know a suffix added upstream since, and derives
  the last two labels for it — the pre-list behaviour. Refresh with
  `scripts/fetch-public-suffix-list.sh`, review the diff and ship it like any
  other change; the script refuses a truncated download;
- an organisation whose own domain is listed in the private section (a
  platform scanning its own `*.platform.example`) gets per-customer seeds, not
  the platform domain. Name the platform domain in `domains` explicitly — and
  note that AXFR will still refuse it, because it is a public suffix.

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
  and passes it to the pipeline as `--scan-scope`. For a job run by a sensor (API
  resource `agents`, `agent_kind = scanner`) it rides the claim response beside
  `ranges.txt` and `domains.txt`, and the sensor writes it out on its own host.
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
  boundary — the sensor host already runs whatever it is handed — it is the last
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
— has no tenant behind it and is not filtered. A **sensor older than #244**
ignores the extra input and its runs are likewise unfiltered; upgrade the
sensors before narrowing a scope you intend the runs to respect.

One limit remains: deny entries for addresses that must never be reached still
belong in the sensor's network policy as well, not only here. The pipeline
filter runs in the same process as the scan and is a control over what that
process aims at, not a boundary around what it can reach.

## Scan policy and the OT profile

The scope above decides what a tenant may be pointed at. Since
[#362](https://github.com/onixus/Shapoclyack/issues/362) a tenant also has a
**scan policy** (`tenant_scan_policies`, migration `0053`) that decides how
hard: rate ceilings, host concurrency, a per-host pace, ports that must never
be touched, and whether anything but the `safe` speed profile may run. It is
written through `PUT /api/tenants/{id}/scan-policy` — see
[api-and-rbac.md](api-and-rbac.md#scan-policy-how-hard-a-tenant-may-be-scanned)
for the document and the permissions.

**What changed operationally.** Before this, the API sent a sensor
`--mode` and nothing else; every rate came from
`scanner/config/default.yaml` *on the sensor's host* — 2000 packets per second
for `safe` discovery. That file is still read, and it is still what a
standalone `python -m scanner.main` uses, but it is now the **fallback, not the
decision**: when a tenant has a policy, the API writes it beside the job's
target files and the pipeline applies it on top of the local config, where it
can only ever lower a rate, add a port exclusion, or turn the service-probe
stage off. An installation that has hardened its own `default.yaml` keeps the
hardening; a policy cannot raise it.

**The `fragile` profile is for somebody else's production.** It is meant for
OT/ICS estates — plant networks, building automation — and it forces, on top of
whatever is stored: the `safe` speed profile, 100 pps discovery, 50 pps port
scanning, `max_host_concurrency: 1`, 25 pps at any single host, the
service-probe stage off, and an avoid-list of fieldbus ports (modbus 502, DNP3 20000, BACnet
47808, S7 102, IEC-104 2404, EtherNet/IP 44818 and the rest, in
`api/services/scan_policy.py`). These are floors: a stored value is used only
when it is stricter, and the avoid-lists are unioned.

What each of those numbers covers, because a ceiling that holds for one stage
and not the next is not a ceiling:

* **100 pps discovery** is all three discovery passes — wave 1, the adaptive
  wave 2 that re-probes the hosts which stayed silent (on a plant floor, the
  controllers), and the verify pass that re-probes alive hosts with no open
  ports. The shipped `default.yaml` gives the last two 2500 and 1250 pps of
  their own; the policy lowers those too, and so is the rate the TCP step of
  the probe ladder uses. It is also the ICMP step, which has no rate of its
  own: fping paces itself by the gap between packets, so the ceiling is turned
  into `discovery.icmp.period_ms` — 100 pps is 10 ms — and passed as fping's
  `-i`. fping's own gap, when nothing sets one, is that same 10 ms, so a
  ceiling of 100 pps or looser leaves the step exactly as it ran before the
  policy existed and a stricter one slows it down. A config that already waits
  longer keeps its own figure.
* **25 pps at any single host** is the per-host figure, and it is the one
  ceiling on this list that does not apply to every scan. naabu's `-rate` is a
  budget for a whole batch, so the per-host figure and the batch figure are the
  same number only when the batch happens to be one host — which is what a
  batch is when the targets are single addresses, and is not what it is for a
  range. Discovery and the port stage hold a single-host batch to 25; a batch
  of 254 addresses keeps the batch budget of 100, which is 0.4 pps per device
  on average but says nothing about the instantaneous pace at any one of them.
  The knob that does apply to a range is the rate itself: to hold a range to a
  per-device figure, lower `max_discover_rate` and `max_port_rate`, or put the
  devices in scope as addresses rather than as a CIDR. Where per-host means
  what it says without qualification is nuclei (`rate_limit`), NSE
  (`nse_max_rate`) and pulse (`rate`), which meter per target rather than per
  batch.
* **The service-probe stage off** means nmap NSE, pulse *and nuclei*. Nuclei is
  the stage that sends HTTP payloads rather than counting SYN/ACKs — ~8.9k
  templates at whatever web interface an engineering station exposes — so a
  fragile run turns it off entirely. It also turns fingerprint HTTP requests
  and browser screenshots off, and disables only the **direct-handshake
  fallback** of TLS posture. TLS posture itself stays enabled so it may parse
  certificate evidence already present in NSE/Pulse artifacts without opening
  a new connection. For a tenant that is throttled rather than silenced,
  `nuclei.rate_limit` is held to `per_host_rate` and every active secondary
  pool (`tls_posture.probe_concurrency`, `fingerprint.concurrency`,
  `screenshots.concurrency`) is held to `max_host_concurrency`.
* **`max_host_concurrency: 1`** is one *batch* at a time, not one host at a
  time, and the difference matters on a plant network. It lowers the discovery,
  port and NSE worker counts and pulse's `--host-parallel`; a worker takes a
  whole batch, and a batch is a `/24` subnet or up to 1024 addresses in the
  shipped `batching` block (`scanner/config/default.yaml`). So a `/24` in scope
  reaches naabu as one invocation covering 254 devices — serialised against
  every other batch, at the ceiling rate, but not device by device. The policy
  does not resize batches: making every batch one address would put a `/8` at
  16.7M batches and roughly 12 GB of expansion before a single packet, rewrite
  the whole checkpoint file after each one, and leave an artefact file per
  batch behind. **If a scan has to walk one device at a time, that is a scope
  decision, not a policy one**: list the addresses individually, or lower
  `batching.ipv4_prefix` on the executing sensor's config, which the policy will
  never raise. A config that already spells one host at a time as
  `pulse.host_parallel: 0` keeps the 0 — the scanner passes it to pulse as
  `--host-first`, which is stricter than any number a policy could put there.
  The TLS fallback, fingerprint and screenshot pools are endpoint workers rather
  than batch workers, but the same ceiling applies to them: a fragile run never
  has more than one active connection from any of those stages, and in fact
  disables their active work as described above.
* **The avoid-list of fieldbus ports** is every stage that puts a port on the
  wire, not only the port scan. The port scan gets `-exclude-ports`. Discovery's
  TCP probe step — which chooses a port list of its own, and which an
  installation can point at anything — drops the avoided ports from that list
  before it sends a SYN, and a probe whose whole port list is avoided is
  skipped instead of run. The last step of the ladder, `naabu -sn`, picks ports
  from naabu's own defaults rather than from the config: left alone it SYN- and
  ACK-pings 80 and 443, which `-exclude-ports` does not cover because that flag
  belongs to the port scan. So the step now spells its probes out (`-pe -pp -ps
  … -pa …`) with the avoided ports removed; if both are avoided it runs on ICMP
  alone. Naming any probe means the command also carries `-wn` — naabu 2.6.1
  refuses to start on probes without it, even alongside `-sn` — so that flag is
  part of the fix and not a spare: dropping it turns every discovery batch into
  `exit 1` and an estate that reads as dead. This is what `ports.exclude_ports` says in
  `scanner/config/default.yaml`: ports no scan started from this config may
  touch.

Every secondary stage that opens fresh connections to scanned hosts is
registered in `SECONDARY_ACTIVE_STAGE_POLICIES` (`scanner/pipeline/scan_policy.py`)
with its concurrency field and the switch that suppresses its active work, and
runs through the guarded wrapper `_run_policy_controlled_secondary_stage`.
Every other stage is listed in `NON_SECONDARY_ACTIVE_STAGES` with the reason it
is not one: a primary stage held by policy fields of its own, a third-party or
DNS source, or artifact-only work.

The guarantee is a test, not the wrapper. `tests/test_scanner_scan_policy.py`
parses `scanner/main.py`, collects the stage name of every `_run_stage` and
guarded-wrapper call, and fails when a name is in neither registry, when a
registered active stage bypasses the wrapper, or when a stage name is not a
string literal it can check. Adding a stage therefore requires a written policy
decision before CI goes green. The wrapper is the runtime backstop on top: it
stops the run if it is handed a name with no contract, but it only sees names
passed to it. Work run outside both wrappers is invisible to either check, so
new network work belongs in a stage.

Being outside the secondary registry is not the same as sending nothing to the
target's infrastructure. Two such stages are bounded by count, not by the
tenant policy: `dns_hygiene` with `axfr_probe` on (see
[Active checks and target authorization](#active-checks-and-target-authorization)),
and `mail_posture`, which fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt`
once per seed domain through the public-address-only HTTP client.

**Budget hours, not minutes** — a `/24` of live hosts at 100 pps is a long scan, and the
alternative it is measured against is not scanning the plant at all. If a
fragile scan has to fit a window, narrow the targets rather than the policy.

**Jobs already in the queue when the policy is written.** They are caught too:
the `PUT` holds every job of that tenant still in `queued` to the stricter of
its frozen snapshot and the new policy, and answers with how many
(`retightened_queued_jobs`). This matters for the one case the feature is
bought for — the recurring scan queued at 02:00 that was still waiting for an
offline sensor when somebody was told at 09:00 that the segment is a plant
floor. It is tightening only: a job that already carried a stricter ceiling
keeps it, a running or claimed job is not re-paced under the sensor executing
it, and *deleting* a policy leaves the frozen snapshots alone. A job that had
no policy at all now has one, which means it also now needs a sensor with the
`scan_policy` capability — the count in the response is where an operator sees
how many scans that is, and #360 gives them the cancel.

**Rolling it out to an existing fleet.** A job carrying a policy is handed only
to a sensor that reports the `scan_policy` capability; anything older is
answered `426` on claim and the job waits. So: upgrade the sensors of a tenant
*before* writing its first policy, or the first scan after the write will sit
in the queue. The symptoms are visible in three places — the sensor's own
journal (the `426` detail names the capability, logged once per *change* of
the message rather than once per poll, so a fleet waiting on an upgrade does
not bury everything else in its journal), the queue (the job stays
`queued`), and `octo_scan_policy_refusals_total{reason="agent_unsupported"}`,
which is the series to alert on because nobody is told about it
interactively. In NATS mode the wait is bounded rather than indefinite: the
offer is published once and a sensor refused the job NAKs it, so a mixed fleet
can burn the offer's delivery attempts — since #362 a sensor pulling from NATS
also asks the API directly once a minute when no offer arrives, which is how
queued work whose offer is gone is found. Tenants with **no** policy are
unaffected and are served by
sensors of any version, which is every tenant until somebody writes one.

**What this does not prove.** The ceilings are applied by the process that
sends the packets. The API can refuse work to a sensor that does not claim to
support policies, and it records the document each job was admitted under
(`scan_options.scan_policy`, with a `digest`), but it cannot verify from the
outside that a sensor on somebody else's host actually paced itself — the sensor
does not yet echo back the policy it applied. A sensor binary you do not trust
is a trust problem, not a rate-limit problem: treat the policy as a control
over what the platform *asks* for, and the sensor's host as part of the trust
boundary, exactly as with the scan scope's third barrier above.

## Maintenance windows and the change freeze

Since #352 a tenant has a calendar (`maintenance_windows`, migration `0048`)
and a switch (`tenants.change_freeze`). Both are checked at scan admission, in
`jobs_service.start_scan` — so the console, the recurring dispatcher and the
platform's own re-scans are held to them equally, and none of them can be
walked past at 02:00.

A window is a recurrence, not a single period:

```http
POST /api/maintenance-windows
{
  "name": "Saturday night change window",
  "kind": "blackout",
  "timezone": "Europe/Berlin",
  "rrule": "FREQ=WEEKLY;BYDAY=SA",
  "dtstart_local": "2026-09-12T22:00",
  "duration_minutes": 240
}
```

**The window is in the tenant's timezone, never the server's.** `timezone` is
an IANA name and `dtstart_local` is wall clock with **no offset** (an offset is
refused rather than converted — a series pinned to one UTC offset would drift
by an hour at every DST change). `duration_minutes` is then added in *absolute*
time, so a four-hour window over the night the clocks jump lasts four real
hours: it ends at 04:00 local on a spring-forward morning, not 03:00. A wall
clock the jump skipped (02:30 on that morning) resolves with the
pre-transition offset — the occurrence happens half an hour late rather than
silently not happening at all.

### The supported RRULE subset

No new dependency was added for this (`python-dateutil` is not in
`requirements.txt`; the repo already hand-parses cron in `scanner/scheduler.py`).
The parser in `api/services/maintenance.py` takes:

| Part | Values |
|---|---|
| `FREQ` | `DAILY`, `WEEKLY`, `MONTHLY` — required |
| `INTERVAL` | positive integer, default 1, counted from `dtstart` |
| `BYDAY` | `WEEKLY` only: `MO,TU,WE,TH,FR,SA,SU` (defaults to `dtstart`'s day) |
| `BYMONTHDAY` | `MONTHLY` only: 1–31 (defaults to `dtstart`'s day; a month without that day simply has no occurrence, as in RFC 5545) |
| `UNTIL` | `YYYYMMDDTHHMMSSZ` or `YYYYMMDD`, inclusive, in UTC |

Everything else — `COUNT`, `BYHOUR`, `BYSETPOS`, `BYMONTH`, an ordinal `BYDAY`
such as `-1SU` — is **refused with `422` naming the unsupported part**. A rule
accepted and then read as something narrower than what was typed would be a
blackout that does not blackout on the nights somebody was counting on, and
nothing would say so. If you need one of those forms, express it as several
windows.

### Blackout, allowed, and the freeze

- `kind=blackout` — no scan is **admitted** while it is open (see the limit
  below). A blackout beats an open `allowed` window, for the reason deny beats
  allow in the scan scope.
- `kind=allowed` — scans start **only** inside one. A single such window turns
  the whole tenant opt-in, so add one deliberately.
- `PUT /api/change-freeze {"change_freeze": true, "note": "…"}` — refuses every
  scan until an admin lifts it. Use it for the period with no end date yet; use
  a window for the one that repeats. Do **not** deactivate the tenant to stop
  its scans: that takes the customer's own data away from them, and the freeze
  exists so it does not have to be done.
- `scope_kind=asset_group` narrows a window to the CIDRs and domains in
  `scope_targets` (matched by *overlap*, so a `/16` sweep is inside a window
  covering a `/24` of it). A scan with no explicit targets runs on the
  installation defaults and is covered by every window of the tenant.

### What an operator sees when it refuses

A manual start answers `409` with the window's name and, when the block has a
knowable end, `Retry-After`; under a freeze there is no `Retry-After`, because
there is no end to name. Every refusal is a `scan.maintenance_block` row in
`audit_events` with the reason, the window and the retry time — that filter is
the answer to "why did nothing run last night", days later.

**The calendar is checked at admission, not at claim time.** In `agent`
execution mode a job admitted at 21:50 stays queued until a sensor claims it,
and `claim_job` does not consult the calendar — a sensor that was busy or
offline can therefore pick up that job after the blackout has opened. The
control is over what the platform *accepts*, not a kill switch over work
already queued. If a window has to hold in the data plane as well, cancel the
jobs (`POST /api/jobs/{id}/cancel` — since
[#360](https://github.com/onixus/Shapoclyack/issues/360) this also stops a scan
a sensor is already running, through `cancelling`) or stop the sensors for its
duration.
#352 was closed on 2026-09-21 without a claim-time gate, and none is filed:
`claim_job` still does not read the calendar.

A refused **schedule** is deferred rather than skipped: `next_run_at` moves to
the end of the blackout (or the start of the next allowed window), so the
nightly scan runs when the window closes. Under a freeze there is nothing to
defer to, so the schedule advances by its own cadence — which is what keeps the
dispatcher from re-refusing and re-auditing the same tick every 30 seconds for
as long as the freeze lasts. Neither path writes `last_run_at`: no scan ran, and
the schedule's history must not claim one did. Watch `deferred_maintenance` in
the dispatcher stats to tell "nothing was due" from "everything was blacked
out".

### On upgrade

Migration `0048` is **expand only**: the table is new and empty and
`tenants.change_freeze` arrives with a server default of false, so an
installation that writes no calendar behaves exactly as it did on `0043` — no
windows and no freeze admits every scan. There is nothing to backfill and no
contract phase to schedule. The downgrade drops the calendar and the freeze
flags, which loses the windows an operator wrote; they are the feature, not a
cache of something else.

## Scan queue: priority and per-tenant ceilings

[#365](https://github.com/onixus/Shapoclyack/issues/365). The queue is one per
tenant, handed out by `priority` (higher first) and then by age. Two ceilings
share the executors out between tenants; both are unlimited until a platform
admin sets them, and the API reference is
[api-and-rbac.md](api-and-rbac.md#queue-priority-concurrency-and-admission).

**Giving a tenant a ceiling.** `PUT /api/tenants/{id}/queue-limits` with
`max_concurrent_scans` (scans out at once) and `max_queued_scans` (scans
waiting). Start with the concurrency ceiling — it is what keeps one customer's
nightly sweep from occupying every sensor — and add the depth ceiling only for a
tenant whose integration queues faster than the fleet drains: that one refuses
scans (`429`), the concurrency ceiling only makes them wait. The
installation-wide `OCTO_SCAN_QUEUE_MAX_DEPTH` is the backstop against a runaway
client of any tenant ([configuration.md](configuration.md)).

**"Scans sit in `queued` and the sensors are idle."** Check in this order:

1. The tenant is at `max_concurrent_scans`: count its `claimed`, `running` and
   `cancelling` jobs against `GET /api/tenants/{id}/queue-limits`. A scan stuck
   in `cancelling` holds its slot until the sensor confirms or the grace period
   ends — stop it, do not raise the ceiling. `octo_scan_queue_throttled_total{reason="concurrency_limit"}`
   rising means claims are being answered with nothing for this reason.
2. Under NATS, an offer burned while the tenant was at its ceiling is picked up
   by the sensor's HTTP fallback claim, within `NATS_FALLBACK_CLAIM_SECONDS`
   (60 s) of a slot freeing — a minute's delay is expected, not a fault.
3. The ordinary causes: the job's agent group has no sensor online, or no
   sensor declares what the job needs (`agent_group_unavailable` /
   `sensor_unavailable` on the job).

**Local scans** (`OCTO_JOB_EXECUTION_MODE=local`) wait in their thread and ask
again every `OCTO_SCAN_QUEUE_LOCAL_POLL_SECONDS`. Priority between them holds
within one replica; a local scan can only ever be started by the replica that
accepted it. Asking keeps a waiting mark on the job fresh (`claimed_until`,
one `OCTO_JOB_LEASE_SECONDS`, at least three polls; rewritten only once half of
it is spent, so a waiting scan costs a row update per half lease rather than
per poll). When the replica goes away —
a crash, or a rollout, which brings the pod back under a new
`OCTO_INSTANCE_ID` so its startup never reconciles the old pod's rows — nobody
renews it, and the job reaper of any replica fails the scan once the mark
lapses ("Waited for a scan slot on replica …, which stopped reporting"). Until
then it still counts against `max_queued_scans` and
`OCTO_SCAN_QUEUE_MAX_DEPTH`: allow one lease plus `OCTO_JOB_REAPER_INTERVAL_SECONDS`
after a rollout before reading a `429` as a real backlog. A live replica's
waiting scans are not reaped however long they wait, as long as it can reach
the database: the mark is no stronger than a running job's lease. A replica cut
off from the database for longer than what is left of the mark — between half
a lease and a whole one — has its waiting scans failed by another replica's
reaper, with the same "stopped reporting" error, and logs `Not starting job …`
at WARNING when it reconnects; those scans have to be started again. A waiting
scan does not queue on the tenant's claim lock — it tries it and asks again at
the next poll — so it holds a database connection only while it asks, not
while it waits; each one is still a thread of its own, so a tenant that queues
thousands of local scans against a small ceiling costs that many idle threads.

**Who may jump the queue.** `scan.priority.raise` — tenant `admin` and platform
admin; grant it on a custom role to an on-call who has to push a re-scan ahead.
Operators can lower their own scans to make room. Every move is a
`scan.priority` audit row.

**Watching it.** `octo_scan_queue_throttled_total{reason}` (`tenant_queue_full`,
`global_queue_full`, `concurrency_limit`) and, with
`OCTO_METRICS_TENANT_TOP_N` set, `octo_tenant_jobs_queued{tenant}` — the depth
`max_queued_scans` is measured against. A tenant whose
`octo_tenant_jobs_queued` keeps climbing while its concurrency throttle rate is
steady is a tenant that queues faster than its ceiling lets it scan. A
schedule that meets a full queue is deferred by `Retry-After`, not skipped:
`deferred_queue_full` in the dispatcher stats, apart from `skipped_quota`. The
deferral stops at the schedule's next occurrence: once the back-off would reach
it, the occurrence is skipped (`skipped_queue_full`, one per lost occurrence,
logged at WARNING) and the schedule resumes on its cadence. A
`skipped_queue_full` that keeps growing is a queue that does not drain at all —
in agent mode, usually no sensor for the tenant — not a busy minute.

### On upgrade

Migration `0074_scan_queue_admission` is **expand only**: `jobs.priority` arrives
`NOT NULL DEFAULT 0`, so every existing job reads 0 and the claim order over a
queue of zeroes is the old `queued_at` order; the two tenant ceilings arrive
`NULL` (unlimited). During a rolling update an old replica claims FIFO and
inserts with the default — nothing is lost or handed out twice. The downgrade
drops the columns and the `scan.priority.raise` grants, and with them any
priorities and ceilings that were set.

## Alerts and exports

Supported integrations include Slack/Telegram summary alerts, SMTP, DefectDojo,
and report artifacts. Configure credentials only through secrets or environment
injection. Test notification delivery with non-sensitive data before enabling
production findings.

## Sizing

CPU, memory and volume sizes for N assets, M sensors and K scans a day — the
model, a table for 1k / 10k / 50k assets, the measured coefficients behind it
and how to re-measure them on your own stand — are in [sizing.md](sizing.md)
([#337](https://github.com/onixus/Shapoclyack/issues/337)). Read it before
choosing volume sizes: two Postgres tables grow with every scan and have no
retention (`vulnerability_events`, `jobs`), and the JetStream volume has to
hold what the streams *reserve*, not what they currently contain.

## Retention

Retention must cover all stateful layers:

| Layer | Retain/backup |
|---|---|
| Artifact store (PVC or object storage) | Raw artifacts, reports, checkpoints |
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory, risk snapshots, the append-only audit trail. `idempotency_records` is the one table that needs *no* retention decision — it self-expires in 24h, see below |
| ClickHouse | Analytical vulnerability and port history |
| NATS | Pending jobs and ingest messages |

Set retention according to legal, operational, and privacy requirements. Scan
artifacts can contain internal hostnames, IPs, software versions, and
vulnerability evidence.

Every window below is the platform default. Since #332 a tenant may keep each
category longer or shorter within bounds the platform configures, a platform
admin may place a tenant on **legal hold** (no sweep deletes its data, and the
tenant cannot be deleted), and console users' personal data can be exported
and erased with the username kept as a pseudonym. What is kept, for how long,
by which mechanism, and what the DPA annex should say about it:
[data-retention.md](data-retention.md).

Offboarding a customer is not a retention window: a platform admin suspends a
tenant (its members' sessions, its tokens, keys and agents cut at once, its
running agent scans told to stop), or deletes it
in two steps with a grace period, after which a worker purges it from
Postgres, ClickHouse, the artifact store and JetStream and keeps a tombstone.
A restore from a backup taken before the purge brings the tenant back; the
deletion journal is what to re-apply:
[tenant-lifecycle.md](tenant-lifecycle.md).

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

Scan artifacts accumulate over time on whatever they are stored on. An
in-process retention worker runs every `OCTO_RUN_RETENTION_INTERVAL_SECONDS`
(1h) and deletes runs older than `OCTO_RUN_RETENTION_DAYS` (30) through the
artifact store, so the same setting bounds a persistent volume and an
object-storage bucket.

- Age comes from `run_meta.json`'s own timestamps (`finished_at`, `started_at`,
  `created_at`) where it has them — they say when the *scan* happened, whereas a
  storage timestamp says when the bytes were last written, and a restored backup
  would otherwise look like this morning's work. Failing that, when
  `run_meta.json` itself was written; failing that, the newest object anywhere
  in the run.
- `0` days disables the reaper.
- Safe across multiple API replicas (removal is idempotent and fail-soft).
- **Do not add a bucket lifecycle rule as well.** This worker knows which runs
  the console still lists; a lifecycle policy does not, and the two would be two
  retention policies in two places disagreeing about the same objects.

### Idempotency records (#346)

`idempotency_records` remembers which `Idempotency-Key` a bulk write has already
answered, so a retry after a timeout replays the first report instead of
applying two hundred transitions twice. One row per key per endpoint per
**caller** — the principal the audit trail records — holding the request digest
and the report.

**On upgrade to migration `0055`.** Expand only, and nothing is rewritten: the
`actor` column arrives nullable with no default, so every row written before it
is marked by construction as "reserved when a key was a tenant-wide namespace",
and `reserve` still honours those rows for the 24 hours they survive. The
tenant-wide unique index is not dropped but *narrowed* to exactly those rows
(`WHERE actor IS NULL`), so a replica still running the previous release keeps
the uniqueness that decides which of two racing replicas holds a key.

The two indexes cannot see each other, though — one covers rows with an owner
and one covers rows without — so the rollout is also given a trigger,
`idempotency_records_cross_generation`, which refuses an insert whose owner-ness
disagrees with a row already holding the key and raises `unique_violation`, the
error both releases already handle by reading the row that won. Without it the
*reverse* direction of a rolling deploy is open: a batch answered by a new
replica and retried against one the deploy has not reached yet would be applied
a second time. It takes a transaction advisory lock on the key, so the cost is
one lock per bulk request that carries one.

**The contract step is tracked** in [ROADMAP.md](../ROADMAP.md#track-a--what-is-actually-left)
("Idempotency key `actor` — contract step") and in a `TODO` on
`api/services/idempotency.py`, so it is scheduled rather than prose. One release
later, once no row without an actor
can exist (the bound is the 24h `RETENTION_SECONDS`), drop the narrowed index,
the trigger and the fallback read in `idempotency.reserve`. While they are in
place a legacy row is still read tenant-wide, which is the thing this change
exists to end.

During the rolling deploy itself a key reserved by an old replica is still
tenant-wide: a member of the same tenant who guesses it and sends a matching
body is handed that report as a replay, with no audit row of their own. One
deploy window plus the 24-hour life of the rows it wrote, not a standing
property.

**Nothing operational to schedule.** Rows expire 24 hours after they are
written (`RETENTION_SECONDS` in `api/services/idempotency.py`) and are deleted
by a sweep the write path itself runs, at most once every five minutes per API
process — the same shape as the login trail being pruned on the login path. A
failed sweep is logged at WARNING and retried by the next request; it never
fails the write it was riding on.

The table is therefore bounded by *bulk request volume in the last day*, not by
history: on a console-only installation it is tens of rows. It holds no secrets
and no findings — the key, a digest, and the per-id report — and it is safe to
truncate at any time. The only consequence is that a client mid-retry
re-executes its batch, so prefer letting the sweep do it.

The scan-start and results-upload paths are **not** in this table and are
unchanged: they hang their key on the `jobs` row the request produced.

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
It goes into `network-scan` beside Postgres. It also carries a NetworkPolicy that
admits its pods to Postgres, which otherwise admits only the API and the backup
job (`base/networkpolicy-datastores.yaml`).

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

Migration `0065` (#332) adds a second function, `audit_events_prune_tenant`,
for tenants with an audit window of their own, and makes both skip a tenant on
legal hold; the retention role then also needs `SELECT` on the policy and hold
tables. The four extra statements are in
[data-retention.md](data-retention.md#7-operating-it).

**Before upgrading to `0065` with this layout applied:** the migration
replaces `audit_events_prune`, which only its owner may do, and the migration
role is no longer it. `0065` checks first and stops without changing anything,
naming the statement to run. Run that one upgrade as a superuser or a member of
`shapoclyack_audit_owner`, or hand the function to the migration role
beforehand (`ALTER FUNCTION audit_events_prune(timestamp without time zone)
OWNER TO shapoclyack_api;`) and give both functions back afterwards with the
statements in [data-retention.md, section 7](data-retention.md#7-operating-it).

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

### Audit events to SIEM (#328)

The trail is a table first: every row is written in the same transaction as the
change it describes and is readable through `GET /api/audit`. On top of that,
three ways out.

**1. The event bus.** With `OCTO_NATS_URL` set, each committed row is published
to `events.audit.{tenant}` on stream `EVENTS` — after the commit, never before
it, so a change that rolled back announces nothing. A row with no tenant (a
platform-level act: creating a console account, changing installation-wide
config) goes to the reserved subject `events.audit._platform`; a tenant id must
start with an alphanumeric, so no real tenant can claim it. A legacy id that is
not a valid subject token is hashed into `h_<sha256[:32]>`, exactly as the job
and asset subjects do it.

Publication is best-effort. A broker that is down loses the *notification*, not
the row: the failure is logged at WARNING and counted on
`octo_audit_events_published_total{outcome="error"|"skipped"}`. **With
`OCTO_NATS_URL` unset nothing is published at all** — such an installation has
the API endpoint and the `db`-source forwarder below, and nothing else.

**2. Webhooks.** A subscription may name the kind `audit.*` (every action) or
one exact `audit.<action>`, e.g. `audit.user.role_change`. The console offers
the wildcard as a checkbox; an exact action is set over the API and shown as it
is stored. Signing, retries, the DLQ and the tenant filter are unchanged — an
audit event is a normal delivery. `min_severity` does not apply to them: it is
a statement about vulnerabilities. Platform-level rows (no tenant) reach no
webhook, because a subscription belongs to a tenant; use the forwarder for
those.

**The trail is opt-in.** A subscription with an empty `event_kinds` keeps
meaning "every asset event" and does *not* silently grow to include the audit
trail on upgrade: those subscriptions were created when the trail could not
leave the platform at all, often pointing at a shared chat channel, and posting
who reset whose password and from which address into one would be a disclosure
caused by a version bump. Name `audit.*` explicitly. A second durable consumer `octo-webhook-audit-fanout` on
`events.audit.>` does the fan-out, alongside `octo-webhook-fanout` on
`events.asset.>`; both are created with `DeliverPolicy.NEW`.

**3. The syslog/CEF forwarder.** A worker of its own:

```bash
python -m api.services.audit_syslog_forwarder
```

`k8s/shapoclyack/examples/audit-syslog-forwarder.example.yaml` has the
Deployment and its Secret, all in `network-scan` beside the NATS credential it
reads. It also has an egress NetworkPolicy allowing only DNS, the SIEM port and
whichever of NATS or Postgres the source reads. Two more policies admit the
forwarder to NATS and to Postgres, which otherwise admit only the API
(`base/networkpolicy-datastores.yaml`); keep the one your source needs. Run one
replica. Configuration is in
[configuration.md](configuration.md) under `OCTO_AUDIT_SYSLOG_*`; the shape is
`OCTO_AUDIT_SYSLOG_URL=tls://siem.example:6514` plus `_CA` (and `_CERT`/`_KEY`
when the collector wants a client certificate). `tcp://` works and warns on
every connect. **UDP is not implemented** — it carries no delivery signal, so
there would be nothing to decide an acknowledgement on.

Two sources:

| `OCTO_AUDIT_SYSLOG_SOURCE` | Reads | Position kept in | Boundary |
| --- | --- | --- | --- |
| `nats` (default) | `events.audit.>`, durable `octo-audit-syslog`, `DeliverPolicy.ALL`, `max_deliver` unlimited | JetStream consumer | First start replays what the stream retains (30d by default). At-least-once. Redelivery is not capped: any finite ceiling would be a number of minutes of SIEM downtime after which events are dropped silently, so the stream's retention is the bound. |
| `db` | `audit_events` in `(occurred_at, id)` order | `audit_forward_cursors` (migration 0042) | For installations with no broker. Reads `OCTO_AUDIT_SYSLOG_DB_LAG_SECONDS` (15) behind the present: `occurred_at` is stamped when the change is recorded but the row appears only at COMMIT, so a reader at the present moment would pass a row about to appear behind it. A transaction that takes longer than the lag between recording and committing can still have its row skipped. |

A message is acknowledged only after its bytes reached the socket, so a
receiver that goes away leaves the rest of the batch un-acked and it comes
back. Both sources are therefore at-least-once: a SIEM may see one event twice
after a reconnect, and the `cs6`/`eventId` extension is what deduplicates it.
Reconnects back off 1s → 30s.

#### Wire format

CEF inside RFC 5424, framed with RFC 6587 octet counting (`<byte length> SP
<message>`):

```
476 <108>1 2026-09-10T09:41:43.549Z shapoclyack shapoclyack - audit - CEF:0|Shapoclyack|api|0.44-0907|user.role_change|user.role_change|8|rt=1789034400000 externalId=42 act=user.role_change outcome=success suser=admin src=10.0.0.1 requestClientApplication=curl/8.6.0 cs1Label=tenant cs1=acme cs2Label=resourceType cs2=user cs3Label=resourceId cs3=amy cs4Label=actorType cs4=user cs5Label=requestId cs5=req-1 cs6Label=eventId cs6=1f2e… msg={"before":{"role":"viewer"},"after":{"role":"admin"}}
```

PRI is facility 13 (`log audit`) × 8 + a syslog severity derived from the CEF
one: ≥ 8 → warning (4), ≥ 5 → notice (5), else informational (6). Values are
escaped as CEF requires — `\` and `|` in the header, `\` and `=` in the
extensions, and every line break as `\n` — so a username or user agent someone
controls cannot end the message early.

Field mapping, CEF ↔ `audit_events`:

| CEF field | Column / source | Note |
| --- | --- | --- |
| `deviceEventClassId` (5th header) | `action` | e.g. `user.role_change` |
| `name` (6th header) | `action` | Same value: ArcSight wants a `name` with no variable content, and a friendly label belongs in the SIEM's own lookup |
| severity (7th header) | derived from `action` | 0–10; 8 for privilege/credential changes and deletions, 6–7 for lifecycle, 3 for `report.download`, 5 for an unknown action |
| `rt` | `occurred_at` | epoch milliseconds |
| `externalId` | `id` | the row's primary key |
| `act` | `action` | |
| `outcome` | — | always `success`: a *refused* action is an `auth_events` row, a different stream |
| `suser` | `actor` | console username, service-token name, sensor id (`actor_type = agent`) or `system` |
| `src` | `client_ip` | resolved through the trusted-proxy chain, never a raw `X-Forwarded-For` |
| `requestClientApplication` | `user_agent` | |
| `cs1` / `cs1Label=tenant` | `tenant_id` | `_platform` for a platform-level act |
| `cs2` / `cs2Label=resourceType` | `resource_type` | |
| `cs3` / `cs3Label=resourceId` | `resource_id` | |
| `cs4` / `cs4Label=actorType` | `actor_type` | `user`, `service_token`, `agent`, `system` |
| `cs5` / `cs5Label=requestId` | `request_id` | `X-Request-Id` when the caller sent one; the key is omitted when it did not |
| `cs6` / `cs6Label=eventId` | derived | stable per row — the deduplication key |
| `msg` | `before` + `after` | compact JSON, already redacted; replaced by `{"truncated":true,"bytes":N}` past 1024 characters. The full documents stay in `GET /api/audit` |

A key whose value is empty is omitted entirely, label included — an emitted
`cs5Label` with no `cs5` reads to a SIEM as an empty column rather than an
absent optional field.

#### Parsers

**Splunk.** `props.conf`/`transforms.conf` on the indexer or heavy forwarder;
Splunk's CIM add-on for CEF handles the extraction, this only names the source
type and maps the custom strings:

```ini
# props.conf
[shapoclyack:audit]
SHOULD_LINEMERGE = false
TIME_PREFIX = rt=
TIME_FORMAT = %s%3N
KV_MODE = none
REPORT-cef = cef_header, cef_extensions
FIELDALIAS-tenant = cs1 AS tenant
FIELDALIAS-resource_type = cs2 AS resource_type
FIELDALIAS-resource_id = cs3 AS resource_id
FIELDALIAS-actor_type = cs4 AS actor_type
FIELDALIAS-request_id = cs5 AS request_id
FIELDALIAS-event_id = cs6 AS event_id
EVAL-user = suser
```

Point a TCP-TLS input at 6514 with `sourcetype = shapoclyack:audit`. Dedupe on
`event_id` (`| dedup event_id`) when reporting across a forwarder restart.

**QRadar.** Add a log source of type *Universal CEF* with protocol *Syslog*,
listening on the TLS port. The RFC 5424 header carries the time of the *event*,
not of the send, so a replayed backlog keeps its own timeline whether QRadar
reads the header or `rt`. QRadar parses the CEF header itself; the six custom
strings need a custom property each, or a DSM Editor mapping from
`cs1`…`cs6` to Tenant / Resource Type / Resource ID / Actor Type / Request ID /
Event ID. Map `deviceEventClassId` to the QID so that `user.role_change` and
`membership.grant` land in *Authentication → Privilege escalation* rather than
in *Unknown*.

**MaxPatrol SIEM.** Use the built-in CEF normalizer (`cef_syslog`) and a
normalization rule keyed on `DeviceVendor = Shapoclyack`. Suggested mapping to
the taxonomy: `suser` → `subject.account.name`, `src` → `subject.ip`, `act` →
`action`, `cs3` → `object.name`, `cs2` → `object.type`, `cs1` →
`subject.domain`, `cs6` → `external_id`. Correlation on `object.name` plus
`action in (user.role_change, membership.grant, service_token.create)` is the
rule an audit review usually asks for first.

### Workflow events and the SLA escalation worker (#349)

Eight event kinds describe the remediation *workflow* rather than discovery:
`sla_due_soon`, `sla_breached`, `exception_expiring`, `vuln_state_changed`,
`vuln_assigned`, `scan_failed`, `report_generated`, `agent_offline`. Four are
emitted at the write that causes them; the other four are derived by a
leader-locked worker started with the API
(`OCTO_SLA_ESCALATION_ENABLED`, tick `OCTO_SLA_ESCALATION_INTERVAL_SECONDS`).

**They reach webhooks without a broker.** Unlike an asset event, which is built
by the scanner and travels JetStream, a workflow event is produced inside the
API and its emitter writes `webhook_deliveries` directly — so an installation
with `OCTO_NATS_URL` unset still gets these notifications. The bus copy is
published to `events.workflow.{tenant}.{kind}` for consumers that are not
webhooks, and there is deliberately **no third fan-out consumer to deploy**:
widening `octo-webhook-fanout`'s filter subject would mean deleting it and
resetting its cursor, which replays retained events at every receiver (#152).

**Opt-in.** A subscription with an empty `event_kinds` does not start taking
these on upgrade, for the same reason the audit trail does not (above). Name
the kinds.

**Announced once, by a marker.** `sla_breached` is a predicate over `due_at`
and the clock, true again on every tick, so the worker claims each occurrence
in `workflow_event_markers` before announcing it. The claim key carries the
deadline: a reopen recomputes `due_at` and is announced again, the same
deadline is not. The unique constraint is the claim, so a brief double-leader
(the advisory lock is not fenced) sends one notification between the two
replicas.

A claim covers work that happened. If the fan-out into `webhook_deliveries`
fails — a database hiccup, an unconfigured webhook service — the claim is
**released** and the occurrence is announced by the next tick; the only hole
left is a process killed between the claim and the fan-out, which costs one
notification. What is *not* retried is the bus copy: it is off the notification
path by design, and an unreachable broker is remembered for 30 seconds rather
than re-dialled per event (`nats_bus.get_bus` caches only success and spends
its whole connect budget on each attempt, which is ten seconds an operator's
transition cannot afford — the same guard the audit events got in #328).

`OCTO_WORKFLOW_MARKER_RETENTION_DAYS` (365) prunes those markers hourly from
the same thread. Note what that means: **deleting a marker re-arms its event**,
so a finding still breached a year later is raised a second time. `0` disables
both.

**Rolling into it.** Nothing is backfilled — the markers for past breaches were
never written down, and inventing them would suppress the first announcement of
every breach the installation already has. So the ticks after the upgrade
announce the tenant's *current* breaches, once each,
`OCTO_SLA_ESCALATION_MAX_FINDINGS` (500) per tenant per tick: the budget is a
window and the worker keeps a per-tenant cursor, so a 600-finding backlog is
announced over two ticks rather than the first 500 and then silence. On an
estate with a large overdue backlog set `OCTO_SLA_ESCALATION_ENABLED=false`
before the upgrade and turn it on when the receivers are ready. The cursor
lives in the worker's memory: a restart, or the leader lock moving to another
replica, starts the sweep from the oldest deadline again — which the markers
make silent, at the cost of one pass of losing claims.

**Escalation writes rows.** Reassignment and the severity bump happen only for
tenants with an `sla_escalation_policies` row that enables them
(`PUT /api/vulnerabilities/sla-escalation`, tenant admin), and each is recorded
as an `escalated` event in the finding's trail with no actor — the platform did
it, on a policy. It happens **once per missed deadline**, claimed in the marker
table under its own kind (`sla_escalated`): an operator who assigns a breached
finding to themselves keeps it, rather than having the policy move it back to
the escalation address on the next tick. The severity bump does not survive the
next observation of the finding, which re-copies the scanner's severity; the
trail entry is the durable record, and it is not written a second time when the
next scan puts the severity back.

**The owner digest** is one plain-text mail per asset `owner_email` per day
through the report relay (`OCTO_REPORT_SMTP_*`), claimed in the same marker
table keyed on the calendar day, so a 15-minute tick cannot mail somebody
ninety-six times. A relay that refuses is logged and counted
(`digest_failures`), does not stop the tick, and **releases the day's claim**:
a `421` at 00:07 costs the owner a quarter of an hour, not the day. The digest
lists what is overdue for that owner now, not what this tick announced — it is
read separately from the announcement window for exactly that reason.

**`agent_offline` is claimed per episode, not per missed beat.** The event
kind keeps its name, but it is about sensors only (`agents` rows with
`agent_kind = scanner`, #358): an endpoint Agent (Lariska) has its own
staleness measure in hours, `OCTO_ENDPOINT_STALE_HOURS`, and is never announced
through it. The other three derived kinds key their claim on a deadline; a
sensor has none, so the claim is keyed on the sensor itself and held for as long
as the platform believes it is gone. This matters for the sensor that is
*degraded* rather than dead: with `OCTO_AGENT_STALE_SECONDS=120` and a
60-second heartbeat, a sensor reaching the API every other try presents a
different-but-still-stale `last_seen_at` on every tick, and the old
per-timestamp key made every one of them a new occurrence — ninety-six
deliveries a day for one sensor, nineteen thousand across a fleet of two
hundred.

The claim is given back when the sensor comes back, and "comes back" is a run
rather than a beat: an unbroken run of heartbeats, begun after the claim was
taken, of at least twice `OCTO_AGENT_STALE_SECONDS` (`agents.healthy_since`,
added in 0056 and restarted by any gap longer than the stale window). A
flapping link never reaches that, so it stays one episode.

What the release deliberately does *not* ask is whether the sensor is there at
the instant the worker looks. A run is what was **observed**, so a sensor that
was genuinely back for ten minutes and then died for good is released on
whatever tick comes next — and its second, real death is announced as a second
episode rather than left under the first event, which the on-call had already
closed. Asking "seen right now" instead would make closing an episode depend
on a tick landing inside a two-minute window it visits every fifteen.

A sensor that is genuinely back therefore clears its alert on the first tick
that is at least four minutes into its new run: **between four minutes and one
tick later**, so four to nineteen minutes at the defaults, and
`OCTO_SLA_ESCALATION_INTERVAL_SECONDS` is what decides where in that range.
Nothing changes on the announcing side: the first tick after a sensor crosses
the threshold still announces it, with no confirmation window.

**Upgrading past 0056** folds the standing claims: every `agent_offline`
marker under the old per-timestamp key becomes the one `offline` claim for that
sensor, dated from the last time it was announced. Without that, the first tick
would claim every already-quiet sensor afresh and announce it again —
`webhook_deliveries` would de-duplicate that by `event_id`, but the copy
published to NATS would not be, since JetStream's content window is minutes
wide and these sensors have been silent for hours. Nothing to do by hand; a
`SELECT count(*) FROM workflow_event_markers WHERE kind = 'agent_offline' AND
marker <> 'offline'` should answer `0` after the upgrade.

The sweep is bounded by `OCTO_SLA_ESCALATION_MAX_FINDINGS` and cursored like
the finding window above — it was the one query in this worker with neither.
The cursor is fleet-wide rather than per tenant, and lives in the worker's
memory on the same terms: a restart re-reads from the oldest silence, which the
standing claims make quiet.

There is still **no `agent_recovered` event**: the platform closes its own
claim, but a receiver that opened an alert on `agent_offline` has to close it
from the Sensors page (route `/agents`) or from `GET /api/agents`. Until that kind exists, treat
`agent_offline` as "a new episode of silence started", not as a state that will
be retracted.

Worker counters live on `octo_workflow_events_total{kind,outcome}` and
`octo_sla_escalations_total{action}`; `outcome="no_subscription"` is the
ordinary case for a tenant that has not opted in, not a failure. The worker's
own `stats` also counts `agents_offline` and `agents_recovered` — episodes
**announced** and claims released, so a fleet whose two counters climb together
is a fleet that is flapping rather than one that is failing. `agents_offline`
counts an episode only when the event reached the delivery queue or the broker,
as `breached` and `due_soon` do: a claim whose fan-out failed is given back and
retried on the next tick rather than counted here, and a tenant that has
subscribed to nothing and runs no broker counts nothing at all.

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

### Runs accepted but not published (`run_publications`)

An upload from a sensor becomes visible in four places: the object store, the
run directory, `state/latest_run.json` and `ingest.results.{tenant}`. Since the
ingest fencing change, none of that happens before the job's terminal write.
That write records the outcome and, in the same transaction, one
`run_publications` row saying the run is accepted and owed its publication;
everything visible is then done from that row — first in the request that
accepted the upload, then by a reconciler in every replica.

A **local** scan (`OCTO_JOB_EXECUTION_MODE=local`) gets the same row since
[#454](https://github.com/onixus/Shapoclyack/issues/454), named
`local-<job_id>`, with no `agent_id` and no `archive_path`. Its "staging tree" is
the directory the scanner wrote, `<output_dir>/runs/<run_id>`, on the replica
that ran the scan; everything below applies to it unchanged, except that a local
row is never sent to `ingest.results` and never rewrites `latest_run.json`. A
local run the store refused used to say `; run not filed under its tenant: …` on
the job and was not retried; it now says `; run not published (publication
local-<job_id>): …` once its attempts are spent, and requeue works on it. Notes
of the old form already on jobs are left as they are.

The assets, findings, service fingerprints, asset events, notification and
scope-denial journal entry a run feeds are part of the publication: they run
after the run is visible and before the row is closed, by outcome
(`docs/architecture.md`, *After publication*). So a `pending` or `dead` row also
means "not in the asset list or the tracker yet", and a requeue that lands
feeds the run then. A failed or cancelled run — including a late partial
archive — feeds only the scope-denial journal: it is not a gap in the asset
list that a requeue would fill.

Because the feed runs before the row is closed, a replica killed in between —
or a second attempt that took the row after a lapsed lease — feeds it again.
The asset upsert and the vulnerability fold each mark the row as fed
(`run_publications.projected`, migration `0072`) in the same transaction as
their writes, so the second pass changes nothing there: no extra
`observation_count`, no second `observed` event, no older run's assessment or
`last_scan_run_id` written over a newer one, no decommissioned asset revived.
The mark is per publication, not per `run_id`: a tenant that submits the same
custom `run_id` every night gets every night counted, and a finding closed in
between is reopened. The channel notification and the scope-denial journal
entry can still repeat on that path.

**Rolling out #454 with local scans on more than one replica.** A replica on
the release before #454 can adopt a `local-<job_id>` row that has been
`pending` for longer than the adoption window (five minutes, or ten reconciler
intervals if longer) and whose directory it can see — a shared
`OCTO_OUTPUT_DIR`. It publishes the run, then looks for the sensor archive a
local row does not have, and ends the row `dead` with `the uploaded archive is
no longer on disk …`: the run is readable, nothing was fed. The console offers
**requeue** for such a row (a sensor row with that reason offers discard);
requeue it once the rollout has finished and the run is fed then. To avoid it
altogether, let `octo_run_publication_backlog{status="pending"}` reach zero
before the rollout, or run local scans on one replica during it. The agent
execution mode the shipped manifests use has no local rows.

So a store outage, an unreachable broker or a replica killed mid-publication no
longer costs the scan. It costs its *visibility*, for as long as the row says
`pending`. What an operator has to act on is a row that says `dead`:

- `/api/health` reports `run_publications: error` (advisory — `/readyz` and the
  replica's place in the Service are unaffected);
- `octo_run_publication_backlog{status="dead"}` is non-zero;
- the job itself carries `; run not published (publication <id>): <reason>` in
  its `error`, which is what the console shows on a scan that says it succeeded
  and has no artifacts.

What is owed, and where it is: the job's card in the console (**Publication**
section of the job drawer on `/scans`), or the same thing from the API
([#425](https://github.com/onixus/Shapoclyack/issues/425)):

```bash
curl -H "Authorization: Bearer $TOKEN" https://<api>/api/jobs/<job_id>/publications
```

Each row says its `state` (`publishing` — an attempt is running right now;
`retrying`; `dead`), `attempts` of `max_attempts`, `last_error`, `stored_at`,
`lease_lapses` and a `resolution` — what is worth doing about it (`wait`,
`requeue`, `rescan`, `discard`), derived from the reason the row died.
`replica`, `staging_path` and `archive_path` — what the manual load below needs
— are filled in for a platform admin only. The fleet-wide count is still
`octo_run_publication_backlog` and `/api/health`.

`stored_at` says the run's whole tree reached the object store: a row that
carries it is owed only `latest_run.json` and the message on
`ingest.results.{tenant}`, so the scan is readable in the console and it is the
analytical projection that is behind. It is also half of the fence that keeps a
publication which loses a race from taking the winner's keys back off; `claims`
is the other half, because the stamp goes on only once the winner's whole tree
is up and the race is lost long before that. Since #425 there is a third,
`fence`, which every claim and every requeue moves forward and nothing moves
back. `claims` itself no longer starts over either: the claim budget counts
from `claims_base`, which an outcome, a requeue and an unworked hand-back move
up to `claims`. The reset used to hand a stale attempt its own number back —
and a replica on the release before `0062` fences on `claims` alone. (Such a
replica still resets it when *it* records an outcome, and still counts its
budget from 0, so during a rollout it may end a row that new replicas have
claimed many times as *claimed far more often than it may be attempted*: a
false `dead`, which a requeue answers.)

`staging_path` is on `replica`'s disk — a remote backend caches per pod — so a
row is normally finished by the replica that accepted the upload. A peer picks
one up only after that replica has been silent for ten reconciler ticks, and
gives it back untouched if it cannot see the tree. Silence means the row has
not been touched: a publication in flight renews its hold every few seconds,
and a recorded failure writes the row too, so a replica that is alive and
retrying keeps its own rows.

That giving back is bounded, which is the other way a row reaches `dead`: with
the artifact cache on an `emptyDir` — the HA overlay's default — the staging
tree dies with its pod, so a row left by a pod the autoscaler removed is one no
replica can ever publish. After `OCTO_RUN_PUBLICATION_ORPHAN_DEADLINE_SECONDS`
(1h) of that silence it is `dead` with *the replica that accepted this upload
is gone* on it. Usually that means a re-scan and nothing to load by hand —
usually, not always: **check `staging_path` before you believe it**. In an
installation that runs the reconciler in only some replicas
(`OCTO_RUN_PUBLICATION_WORKER_ENABLED=false` elsewhere), or where the cache is
a volume that outlived the pod, the extracted tree can still be on a disk you
can reach, and then the manual load below applies. A deployment that wants
those rows adopted rather than condemned needs the cache on an RWX volume, not
a longer deadline.

The console does not wait out that hour to say so. A `pending` row that nobody
holds and nobody has touched for longer than its own replica's next retry plus
a peer's adoption window is shown with `silent: true` and the moment it will be
declared dead (`orphan_deadline_at`); on the HA overlay that is almost always a
pod the autoscaler removed, and the answer is a re-scan. Once dead, such a row
reads `resolution: rescan` — a requeue walks it back to `dead` an hour later
unless the tree has turned up on a disk some replica can see.

A third reason, rarer: *claimed far more often than it may be attempted*. The
publication keeps killing the replica that takes it — a tree large enough to
reach the pod's memory limit is the case this was written for — so no attempt
ever records an outcome. Check the API pods for OOM kills before re-scanning;
the tree is on the accepting replica's disk and can be loaded by hand.

One more thing a `dead` row can say: *the keys already written could not be
taken back*. The store refused the upload halfway and then refused the cleanup
as well, so the run **is** listed by every replica, short the files that never
arrived. Remove `runs/_tenants/<tenant>/<run_id>/` from the bucket by hand (or finish the upload
from `staging_path`) before deciding between a manual load and a re-scan —
until then an operator reading that run cannot tell it from a scan that found
nothing.

The extracted run and the archive beside it are kept for up to 24 hours **from
the upload's acceptance** — not from the last attempt: the sweep reads the
staging directory's modification time, which only its first entry sets — and
are removed by the next ingest on that replica after that. The job's card shows
the moment as `tree_kept_until`, and a `dead` row the store never took whole
reads `resolution: rescan` once it has passed, because a requeue would only
find the tree gone and die again. Inside that window there are three ways out,
and all of them are decisions rather than retries:

- **Requeue it** once whatever refused it is fixed — the store, the broker, the
  pod's memory limit. The row goes back to `pending` with a full set of
  attempts, and the next reconciler tick publishes it. When it lands, the
  *run not published* note leaves the job's `error` as well.
- **Publish it by hand.** Copy `staging_path` into the run directory
  (`OCTO_OUTPUT_DIR/runs/_tenants/<tenant>/<run_id>` on the local backend) or
  upload it under `runs/_tenants/<tenant>/<run_id>/` in the bucket, then discard
  the row. The analytical
  projection stays behind for that run unless the archive is replayed as well.
- **Re-scan.** Discard the row and start the scan again; the run id will be a
  new one.

Both actions are buttons on the job's card and `admin` routes, each written to
the audit trail (`run_publication.requeue`, `run_publication.discard`):

```bash
curl -X POST   -H "Authorization: Bearer $TOKEN" https://<api>/api/jobs/<job_id>/publications/<publication_id>/requeue
curl -X DELETE -H "Authorization: Bearer $TOKEN" https://<api>/api/jobs/<job_id>/publications/<publication_id>
```

`run_publisher.discard_publication(settings, "<publication_id>")` from
`python -c` still works for an installation without the console, with the same
checks. Discarding is the only thing that clears the health check for a row
nobody will requeue — nothing else deletes these rows. The row is all that
goes: the extracted tree and the archive beside it stay until the ordinary
sweep takes them — until `tree_kept_until` at most, a day from the acceptance —
and the note on the job stays too, because the run was not published.

Both are refused with `409` for a row that is not `dead` and, with a
`Retry-After`, while **an attempt at it is still running**. `dead` is one
attempt giving up, not every attempt having stopped: a second attempt that took
the row while the first one's hold had lapsed may still be uploading. A requeue
beside it would be a second live publication of the same keys; a discard would
delete the row that attempt reads its rollback fence from. Every running
attempt stamps `leased_until` on the row as it renews its hold, whatever the
status, so the refusal lasts at most one hold (`max(60s,
OCTO_RUN_PUBLICATION_INTERVAL_SECONDS)`) after the last attempt stops. It is
stamped and compared on the database's clock, not the pods': the pod running
the attempt and the pod serving the button are not the same one, and a skew
between them past one hold used to read a live attempt as a lease long gone.
(The SQLite dev fallback is one process with one clock and uses that.)

When a requeued publication lands, the *run not published* note comes off the
job in the same transaction that closes the row. If that fails — the job row
refused the write — the run is still closed out and projected, and
`octo_run_publication_stale_notes_total` goes up with a warning naming the job:
that job's `error` says the run was not published although it was, and can be
edited by hand. Notes written by the previous release (or a replica still on it
during the rollout) carry their reason's `;` and are removed whole too. An
attempt that has stopped renewing without stopping — a paused process — cannot
be seen this way; what protects the requeued publication from it is that a
requeue moves the row's `fence`, so the stale attempt no longer takes back the
keys it wrote. During a rolling upgrade to the release that added this, an
attempt on a replica still running the old code stamps nothing: finish the
rollout before acting on a row that went `dead` during it.

A publication's hold is renewed every few seconds while it runs, and a renewal
that fails or lands late is what lets a second attempt start beside it — the
precondition of every race above. It is counted
([#426](https://github.com/onixus/Shapoclyack/issues/426)):
`octo_run_publication_lease_renewal_total{outcome}` with `renewed`, `late` (the
previous hold had already run out), `superseded` (another attempt or a requeue
has taken the row since) and `failed` (the database did not answer). Anything
but `renewed` rising is worth an alert on its own — database latency, a paused
or CPU-starved pod, clock skew between nodes — and the row it happened to
carries it in `lease_lapses`, so a post-mortem can tell which publication ran
unprotected.

A `pending` row that is not draining is the same problem one step earlier:
check the store and the broker first (`/api/health`), because the reconciler is
retrying something that is still refusing.

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
submission, bounded per endpoint Agent by
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

Sensor results upload rejected: an archive over
`OCTO_AGENT_RESULTS_MAX_BODY_BYTES` is refused with `413` from the
`Content-Length` header alone, before the multipart body is read; an upload
without `Content-Length` gets `411`. An archive that passes the transport cap
but whose tar headers add up to more than 512 MiB expanded is refused as
`archive expands to more than ... bytes` — the job stays in flight and the run
directory is not created, so the sensor may retry with a smaller archive. Raise
the transport cap for a legitimately large run; the expansion ceiling is a
constant (`api/services/results_ingest.MAX_UNCOMPRESSED_BYTES`) because the
shared `output_dir` is what it protects.

Sensor results upload answered `503`: the replica is at its ingest ceiling.
Ingestion is synchronous work — SQL, the NATS publish, archive extraction,
artifact writes that are network calls when the store is S3, projection updates
— and runs on a worker thread, bounded by
`OCTO_AGENT_RESULTS_MAX_CONCURRENT_INGESTS` with a queue bounded by
`OCTO_AGENT_RESULTS_INGEST_MAX_WAITING`. `octo_agent_ingest_rejected_total`
separates `queue_full` (refused at the door) from `timeout` (queued, never got
a slot within `OCTO_AGENT_RESULTS_INGEST_WAIT_SECONDS`), and
`octo_agent_ingest_in_flight` / `octo_agent_ingest_waiting` show which of the
two numbers is the binding one. The sensor retries `503` with backoff and its
upload carries a derived idempotency key, so a retry that lands is answered as
a replay rather than ingesting the run twice — a steady trickle here costs
bandwidth, not results. Sustained rejections mean the fleet uploads faster than
this installation ingests: add API replicas, or raise the concurrency after
checking the database pool (`OCTO_DB_POOL_SIZE` + `OCTO_DB_MAX_OVERFLOW`) can
serve the extra ingests. Raising the *queue* instead only buys memory time —
redo the `(concurrent + waiting) × OCTO_AGENT_RESULTS_MAX_BODY_BYTES`
arithmetic before doing it.

Tenant offboarding: endpoint data has no bespoke delete/export flow and follows
whatever general tenant-deletion mechanism the platform adopts. The endpoint FK
chain cascades from `tenants` (migration `0006_endpoint_fk_cascade`), so
deleting a tenant row removes its devices, identifiers, snapshots, software
rows, and change events; a linked asset being deleted only nulls the device's
`asset_id`.

### Inbound ticket sync ([#347](https://github.com/onixus/Shapoclyack/issues/347))

The poller that reads Jira / ServiceNow / DefectDojo back onto the findings
runs in-process, is leader-locked, and is described in
[vulnerability-lifecycle.md](vulnerability-lifecycle.md#inbound-ticket-sync).
It polls one `GET` per linked finding per subscription per cadence, so the load
it puts on somebody else's tracker is roughly `linked_findings / interval` —
worth sizing before enabling it on an estate with thousands of tickets. It is
**on by default**, so the first tick after the upgrade to migration `0045` has
every linked ticket due at once: pace it with the per-subscription
`sync_interval_seconds`, or set `OCTO_TICKET_SYNC_ENABLED=false` and enable it
deliberately.

Runbook:

- **A tracker's status is not reaching findings** — read
  `octo_ticket_sync_is_leader`. If it sums to 0 across the replicas, nothing is
  polling: `OCTO_TICKET_SYNC_ENABLED` is off everywhere, or every replica lost
  the advisory lock evaluation (a Postgres outage leaves everyone a follower by
  design). If it sums to 1, read `octo_ticket_sync_lag_seconds{transport}`.
- **`octo_ticket_sync_lag_seconds` climbing** — three causes, in order of
  likelihood. The tracker is refusing: `octo_ticket_sync_polls_total{outcome="failed"}`
  is rising and the log carries `subscription … held off Ns`. One tick cannot
  drain the estate: `failed` is flat, `unchanged` is rising, and the fix is
  `OCTO_TICKET_SYNC_BATCH_SIZE`. Or the cadence is simply longer than the
  alert threshold — a subscription with `sync_interval_seconds: 3600` will sit
  at a lag near an hour and that is correct.
- **One finding stuck** — its `ticket_sync_error` says why (`HTTP 404` for a
  renamed or deleted issue, `HTTP 401` for a credential the tracker no longer
  accepts). A 404 is fixed by re-linking or clearing the ticket
  (`DELETE /api/vulnerabilities/{id}/ticket`); a 401 across a whole
  subscription usually means Jira Cloud with `auth_mode` left at `bearer` —
  set it to `basic` and store the secret as `email:api_token`.
- **The tracker is being hammered** — raise that subscription's
  `transport_config.sync_interval_seconds`, which takes effect on the next
  tick without a restart. `OCTO_TICKET_SYNC_ENABLED=false` on every replica is
  the stop button; the manual sync route and the outbound reflection keep
  working.
- **A ticket-driven closure was wrong** — the closure is `ticket_resolved` and
  never `machine_verified`, so it is distinguishable from a verified fix in
  `vulnerability_events` and in the adoption metrics. Reopen it through
  `POST /api/vulnerabilities/{id}/transition` and it stays reopened: the worker
  applies a suggestion only when the tracker's own status string changes, which
  it has not (the issue is still `Done`, and the outbound push could not move
  it because the workflow has no reopen step). The **Sync** button is the
  exception and will re-close it — it exists to take the tracker's current word
  on request.
- **A finding is not moving and there is no error** — compare its
  `ticket_remote_status` with the tracker. Equal means the poller is
  deliberately holding still, per the rule above. A `null` there with a
  non-null `ticket_synced_at` means the tracker answered with a status this
  build has no mapping for; the last `ticket_synced` event's
  `detail.remote_status` names it.

Backoff state lives in the worker's memory, so a restart re-learns an outage
at the cost of one request per subscription. That is deliberate: persisting it
would mean a table whose only reader is a thread that already has to handle a
cold start.

## Sensor installation and upgrade

This section is about **sensors** — the scanning nodes that run `agent/worker.py`,
claim jobs and upload results (API resource `agents`, `agent_kind = scanner`).
The endpoint Agent (Lariska) is installed on managed hosts by its own
installer and only submits inventory to `POST /api/endpoint/inventory`;
nothing below applies to it.

A sensor can be installed three ways: by hand from the snippets on the Agents
page (sensors; route `/agents` — systemd, Docker, Kubernetes; press
**Generate key** there first, since the snippets open with a
`<PROVISIONING_KEY>` placeholder), by running the installer directly, or by
letting the API push it over SSH.

```bash
curl -sSL https://<api-host>/api/agent/install.sh | sudo bash -s -- --server https://<api-host> --key <provisioning-key> --tenant <tenant-id>
```

`scripts/install-agent.sh` covers Ubuntu/Debian, RHEL/Rocky/Alma/Fedora, Alpine
and Arch, and takes `--agent-id`, `--install-dir`, `--docker`, `--nats-url`,
`--key-stdin` and `--keep-key` as options (`--help` lists them).

`--key-stdin` reads the provisioning key from standard input instead of taking
it as `--key`. Prefer it wherever the caller can write to stdin — an argument is
readable by every local user on that host for as long as the process runs. The
SSH push always uses it.

With `--docker` it is a thin wrapper: it writes `/etc/shapoclyack/agent.env`
(`0600`) and runs the released scanner image, pinned as
`ghcr.io/onixus/shapoclyack-scanner:<release tag>@sha256:<digest>` (override
with `AGENT_IMAGE`; `--help` prints the current default), as the container
`shapoclyack-agent` (`--restart always`, host network, `NET_RAW`/`NET_ADMIN`,
`--env-file` pointing at that file, entrypoint `python -m agent`), then exits.
The credential is in the env file rather than in `-e` arguments, which would be
in the docker client's own argv. The console's `docker run`, Compose and
Kubernetes snippets name the same pinned image (`SENSOR_IMAGE` in
`api/services/agents.py`). Both are re-pinned with the `k8s/` manifests after
each release is published, so an API built from a new tag keeps handing out the
previous release's sensor until that pin lands.

Without it, the native path installs Python and a virtualenv under
`/opt/shapoclyack-agent`, installs the sensor's Python dependencies into it from
`requirements-agent.lock` (`nats-py`, `psutil`, `PyYAML`, and `cryptography` for the
bundle updater; the installer carries a copy)
with `pip install --require-hashes --only-binary :all:` — a file whose sha256 is
not in the lock is refused, and only wheels are taken, which exist for x86_64 and
aarch64 with glibc or musl — creates a `shapoclyack` system account in a
`shapoclyack` group, writes `/etc/shapoclyack/agent.env` (`0600`, owned by that
account), and — where systemd is present — installs and enables
`shapoclyack-agent.service` (`Restart=always`,
`EnvironmentFile=/etc/shapoclyack/agent.env`). Without systemd (Alpine with
OpenRC, containers) the sensor is started in the background with `nohup` as
that account (`runuser`, or BusyBox `su`; `sudo` is not needed). It logs to
`/opt/shapoclyack-agent/agent.log` and is **not** restarted on boot or after a
crash, so supervise it yourself on such a host. The installer fails if that
process has exited three seconds after start. A re-run stops the process the
previous run started before it starts the new one.

**The sensor needs Python 3.11 or newer.** The installer uses `python3` when it
is new enough. If it is older, the installer installs `python3.12` or
`python3.11` from the distribution: AppStream on RHEL/Rocky/Alma 9, whose
`python3` is 3.9, and universe on Ubuntu 22.04, whose `python3` is 3.10. Where
no such package exists (Ubuntu 20.04, Debian 11), it stops before creating the
account and names the version it found. Install a 3.11+ interpreter with its
`venv` module yourself, or use `--docker`. A virtualenv left by an earlier run
on an older interpreter is rebuilt.

**If the `shapoclyack` account already exists**, its primary group must be
`shapoclyack`, or the installer stops and says so. Installers before this fix
created it in `nogroup` on Alpine and then failed at `chown`. Remove that
account (`deluser shapoclyack`) and re-run.

**The native path does not ship the sensor source.** The installer takes the
package from somewhere explicit: pass `--bundle-url <URL>` with a tarball
containing the `agent` package, or stage that package in the install directory
beforehand. This first install is not signature-checked — the operator running
it is the one vouching for the tarball. Every later update can be, see
[Sensor bundle updates](#sensor-bundle-updates). With neither, the installer
**fails** and says why — it will not leave systemd restarting a sensor that
cannot import its own module. Before starting the service it runs
`import agent.worker` and checks the unit is still active three seconds after
start, because `Type=simple` means "started" on its own proves nothing. Use
`--docker` (or the Kubernetes snippet) for a host that has no checkout.

**Where the provisioning key ends up.** On the target it lives in
`/etc/shapoclyack/agent.env` (`0600`, owned by the `shapoclyack` account) and
nowhere else: the systemd unit is `ExecStart=…/venv/bin/python -m agent` with a
mandatory `EnvironmentFile`, so the key is not in the sensor's argv for the life
of the process. It is still on the command line if you invoke the installer
with `--key` yourself — use `--key-stdin`, or accept that the key is in your
shell history and in the host's process list while the installer runs. Rotate
the key if the host is shared.

A sensor can read its key from a file instead —
`OCTO_AGENT_PROVISIONING_KEY_FILE`, read again on every exchange, which is what
the Kubernetes scanner-executor does ([k8s-hardening.md](k8s-hardening.md#key-expiry-and-rotation)).

The variables in `agent.env` are `OCTO_API_URL`, `OCTO_AGENT_PROVISIONING_KEY`,
`OCTO_AGENT_ID`, `OCTO_TENANT_ID` and `OCTO_NATS_URL`. All but one are what
`agent/worker.py` reads; `OCTO_TENANT_ID` is written for the operator's
benefit only — the sensor learns its tenant from the `tenant_id` claim of the
JWT the provisioning key is exchanged for, not from the environment. Earlier versions of the installer wrote
`OCTO_SERVER_URL` / `OCTO_PROVISIONING_KEY` and passed `--server` / `--key` /
`--tenant` to `python -m agent.worker`; the worker accepts none of those flags,
and `agent/worker.py` had no `__main__` guard, so that unit started a process
that did nothing and exited 0 — forever, under `Restart=always`. The guard is
there now, so both `python -m agent` and `python -m agent.worker` run the
sensor, but the flags in an old unit are still wrong: **a sensor installed by an
older installer needs a re-run of this one.**

**A re-run keeps the sensor's ID.** An upgrade is a re-run of the installer,
and without `--agent-id` the re-run takes `OCTO_AGENT_ID` from the existing
`/etc/shapoclyack/agent.env` and says so (`Keeping agent ID …`), on the native
and the `--docker` path alike. The file is parsed, never sourced: it holds the
provisioning key and the installer runs as root. Installers before this one
generated a fresh `agent-<host>-<random>` on every run, so every upgrade
registered a second sensor. The old row stayed in the fleet view, went `stale`,
was counted in `stale_agents` and was announced as `agent_offline`; its sensor
group and any quarantine stayed with it, so the host came back as an
ungrouped, `active` sensor that no longer took its group's jobs. Delete such
leftovers with `DELETE /api/agents/{id}`, and leave `revoke_key` off unless you
mean to retire that key: the sensor that replaced the row may hold the same one.

Two cases do not reuse the ID. `--agent-id` always wins. An `agent.env`
written for a different `--tenant` is ignored and a new ID is generated,
because an ID stays bound to its tenant and revoking a key does not release it
across tenants. A re-run with a *different provisioning key* keeps the ID and
warns: see "Revoke before you re-provision" under
[Sensor lifecycle](#sensor-lifecycle-disable-quarantine-deregister).

`--keep-key`, in place of `--key` or `--key-stdin`, reinstalls the sensor that
`agent.env` describes with the key it already holds, so no key is needed. It is
refused unless the file has both an agent ID and a key, was written for the
same `--tenant`, and names the same ID as `--agent-id` when that is given: a
key that is not the sensor's own would be refused its ID. The SSH push uses it
for a host that already runs one of the tenant's sensors.

### Sensor groups: which sensor may execute which scan

Until [#361](https://github.com/onixus/Shapoclyack/issues/361) a sensor job was
claimable by *any* sensor of the tenant. If you run one sensor inside a
customer's card-data segment and another in their office network, that was the
whole of the control: the queue was flat and the first sensor to poll won, so a
scan of the card segment could be executed from the office network and the
office sensor was handed the card segment's target list.

A **sensor group** (`agent_group` in the API and the schema) is a name inside
one tenant (`pci-segment`, `ops-eu`), and three things refer to it by that
name:

- the sensor an operator put in it — `PUT /api/agents/{id}/group`, permission
  `agent.group.manage`. A sensor's own `labels` are never consulted: a sensor
  that could declare its own group would be granting itself the jobs of a
  segment it does not sit in;
- the job it is addressed to — `agent_group` on `POST /api/jobs` and on a
  schedule. A job addressed to a group is claimable only from that group; a job
  addressed to none is claimable by anybody in the tenant;
- the allow entry of the approved scan scope that requires it (`agent_groups`,
  see "Approved scan scope per tenant" above). That is the rule that does not
  depend on the operator remembering: the scope decides which groups may reach
  which networks, and a request naming anything else is refused.

**Nothing changes on upgrade.** Every existing sensor is in no group, every
existing job and schedule is addressed to none, and every existing scope entry
permits any sensor. Groups only start constraining anything once you create one
and put a sensor in it. A sensor that is in a group still serves the ungrouped
queue, so moving one sensor into a group does not fence it off from the work it
already did.

A few edges worth knowing before you rely on it:

- **Names are immutable.** The name is the reference, so there is no rename —
  create the new group, move the sensors, delete the old one, each visible in
  the audit trail. Deleting a group is refused (`409`) while a sensor, an
  unfinished job, a **scan schedule** or a scope entry still names it: a
  cascade would turn the deletion into a silent widening of a restricted scope
  entry back to "any sensor", and a schedule left pointing at a deleted group
  would fail at 02:00 every night without moving its next run, so the only
  symptom would be that the nightly scans stopped appearing.
- **The requirement follows the targets you asked for.** Promoted related
  domains are scanned along with them, but they do not contribute to which
  group is required: otherwise an ordinary external scan would inherit the
  restriction of a promoted domain that happens to sit in a restricted range
  and go out from there, and two promoted domains restricted to different
  groups would have made every scan of the tenant impossible.
- **A job addressed to an empty group waits, visibly.** If the group has no
  active sensor with a recent heartbeat when the scan is queued, the job is
  still accepted — a sensor that is restarting is back in seconds — and the API
  logs a warning naming the group. It is not auto-failed: a timeout would be a
  transition on the job state machine, and a restart must not cost you a scan.
  While such a job is still `queued`, `agent_group_unavailable: true` on it
  says so, and the console shows an amber marker on the row and a line in the
  job drawer. The flag is **recomputed on every read** rather than stored, so
  it disappears by itself the moment a sensor of that group heartbeats — it
  never claims a job cannot run because nothing was listening an hour ago. The
  fix is to register a sensor into the group (or re-address the scan).
- **A job addressed to no group** answers the same question as
  `sensor_unavailable` ([#338](https://github.com/onixus/Shapoclyack/issues/338)):
  `true` while it is queued for agent execution and no active scanner sensor
  of its tenant with a recent heartbeat would be handed it — no executor
  enrolled yet, one enrolled with another tenant's key (a sensor claims only
  its own tenant's jobs), one whose provisioning key has expired, or only
  sensors below the version floor or without the capability the job's policy
  or config overlay needs. Recomputed on every read
  like the group flag; the scan start logs a warning instead of refusing, and
  the start response already carries it. `GET /api/agents/summary` reports
  `scan_ready_agents` (online, active, scanner kind, not below the version
  floor, declaring every capability a job may need; always for the caller's own
  tenant, even when a platform admin's other counts are fleet-wide) for the
  same purpose: the
  console shows a banner above the scan launcher and "no sensor online" on the
  System page when it is `0` in agent mode.
- **With NATS, each group has its own subject.** A job addressed to a group is
  offered on `jobs.scan.{tenant}.{group}` (durable consumer
  `octo-agents-{tenant}-{group}`), and a sensor binds only the subjects it is
  entitled to: the tenant's ungrouped `jobs.scan.{tenant}` always, plus its own
  group's if it is in one. A NATS ACL can be written per group on that shape.
  Offers carry a job id and never the scan's targets — those come back in the
  claim response, to the one sensor the API bound the job to. A sensor that is
  moved between groups rebinds on its next heartbeat; nothing has to be
  restarted.
- **Local execution has no groups.** The API container is in no group, so a
  scan that resolves to a group under `OCTO_JOB_EXECUTION_MODE=local` is
  refused rather than quietly run from the control plane.

### Sensor lifecycle: disable, quarantine, deregister

The lifecycle state lives on the `agents` row and so applies to both kinds of
node registered there — a sensor (`agent_kind = scanner`) and an endpoint Agent
(Lariska, `agent_kind = endpoint`). Everything about jobs, claims and results
below is the sensor's side; the one thing the Agent loses when disabled or
quarantined is its inventory submissions.

A registered node has two states at once, and they answer different questions
([#308](https://github.com/onixus/Shapoclyack/issues/308)):

- **What it reports** — `idle` / `busy` / `error`, with `stale` derived from
  `last_seen_at` against `OCTO_AGENT_STALE_SECONDS`. Written by the sensor.
- **What you decided** — `lifecycle_status`: `active`, `disabled` or
  `quarantined`. Written only by a tenant **admin**, through
  `PATCH /api/agents/{id}` or the **Agent State** controls in the node's
  drawer on the Sensors page (route `/agents`).

A `disabled` or `quarantined` node is refused job claims, result uploads and
inventory submissions with `403` and the reason you typed. Its **heartbeat is
still accepted**: the heartbeat response is the only channel that reaches a
running sensor, so it is where the sensor learns why it is being refused, and
refusing it too would drop the sensor out of the fleet view at the moment you
are watching it. The sensor logs the reason once and backs off to one poll every
five minutes rather than one per second — over NATS as well as over HTTP, and
at start-up as well as mid-run.

The state survives re-registration *and* a re-exchange of the provisioning key:
the exchange reads the lifecycle state too, so a restarted host is refused a
fresh token rather than coming back under a new id. Only `PATCH … {"status":
"active"}` puts it back, and that clears the reason.

**What quarantine does not stop.** A job the sensor claimed *before* you
quarantined it keeps running on the host — nothing on the target is killed —
and its results upload is then refused, so the archive is lost and the job
stays `running` until its lease expires and it is requeued for another sensor.
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
| The key itself is compromised | `POST /api/tenants/{tenant_id}/provisioning-keys/{key_id}/revoke` — every sensor that registered with it is refused on its next request |

The delete response says which of these happened, and both it and `GET
/api/agents/{id}` carry `other_agents_on_key` — how many *other* sensors hold
the same key, which is exactly what `revoke_key=true` would strand. The sensor
drawer shows that number the moment the checkbox is ticked, before the delete. `provisioning_key_id: null,
key_revoked: false` means there was no key on record to revoke: a sensor that
registered before this was tracked, or a legacy `OCTO_AGENT_TOKEN` one, which
has no per-sensor credential at all. Those sensors record a key the first time
they re-register.

**Rotating provisioning keys.** Keys minted from now on expire after
`OCTO_PROVISIONING_KEY_TTL_DAYS` (90 by default). `GET
/api/tenants/{tenant_id}/provisioning-keys` reports `expires_at` and
`expires_soon` (within 14 days), which is the list to work from. **Keys minted
before this feature have `expires_at: null` and never expire** — nothing
back-dates them, because stranding a fleet on a deadline nobody was told about
is worse than a key that outlives its usefulness. Find them in that list,
revoke the old one, then re-install the sensors against a fresh key.

**Revoke before you re-provision, not after.** An `agent_id` is bound to the
key it first registered with, so an exchange asking for that id under a
*different* key answers `403` while the old key is still active — that refusal
is what stops one key's holder impersonating another key's sensor. Revoking the
old key releases the id (and stops its live JWTs in the same move), after which
the new key adopts the host under its own name. Re-provisioning first leaves
the sensor unable to authenticate until you get to the revocation; it retries
on its own and recovers once the old key is revoked. The installer keeps the
sensor's ID across a re-run, so it warns when the key it is given differs from
the one in `agent.env`. Pass `--agent-id` with a new value instead if the host
should register as a new sensor under the new key. The SSH push handles this
order itself, and refuses where revoking would stop other sensors; see
[SSH push deployment](#ssh-push-deployment).

### Sensor client certificates

A sensor (or a Lariska Agent) can present a client certificate next to its
token, and the API then requires the two to name the same sensor
([#309](https://github.com/onixus/Shapoclyack/issues/309)). The switches are in
[configuration.md](configuration.md#sensor-and-agent-client-certificates-mtls);
this is how to get a fleet onto them without stopping it.

**Where TLS ends decides the wiring.**

- *Behind ingress-nginx* (every shipped Kubernetes layout): the ingress
  verifies the certificate and forwards it in `ssl-client-*` headers —
  `examples/ingress-agent-mtls.example.yaml`. Set
  `OCTO_AGENT_MTLS_TRUSTED_PROXIES` to the controller's addresses and nothing
  else — a pod range only the controller gets (a Calico IPPool / Cilium pool
  bound to its namespace) — **never the cluster's pod CIDR**: the
  scanner-executor and Prometheus may open the API port too, and from a
  trusted address any pod can forward a "verified" certificate. Apply
  `examples/networkpolicy-api-ingress.example.yaml` with it, so that of the
  pod network only the controller pods reach port 8080.
  *A hostNetwork controller* (common on bare metal) connects from its nodes'
  addresses, so those are what the list has to hold — and every hostNetwork
  pod on those nodes connects from the same addresses: the scanner-executor
  of `overlays/prod` (`hostNetwork: true`), node-exporter, the CNI's own
  agents. Any of them can then forward a "verified" certificate, and no
  NetworkPolicy tells them apart (Calico and Cilium let host traffic through
  by default). Under `required` that makes the floor "whatever runs with host
  networking on an ingress node"; prefer the API's own TLS listener (below)
  or a controller on the pod network, or at least keep the ingress nodes free
  of other hostNetwork workloads (a dedicated node pool with a taint).
  `OCTO_AGENT_MTLS_CLIENT_CA` is mandatory with the list (the API refuses to
  start without it, and an entry that is not an IP or CIDR): every forwarded
  certificate is checked against it. Every Ingress host that routes to the API
  must carry the `auth-tls-*` annotations, with
  `auth-tls-pass-certificate-to-upstream: "true"` — on a host without them the
  headers are whatever the client wrote, and the controller is still a trusted
  peer. The trusted address is the socket's own: uvicorn's
  `FORWARDED_ALLOW_IPS` (which rewrites the client address from
  `X-Forwarded-For`) does not enter into it, so setting it to `*` behind the
  ingress does not let a pod name the controller's address, and setting it to
  the controller's does not hide the controller.
- *On the API's own listener* (`OCTO_API_TLS_CERT`, a lab stand, an appliance,
  or a TLS-passthrough / L4 path to the API): set `OCTO_AGENT_MTLS_CLIENT_CA`;
  the handshake verifies the certificate itself. The listener asks for a
  certificate whenever it has a client CA (or an issuer), whatever the mode —
  optional per connection, so the console is unaffected, but a browser holding
  a certificate from that CA may offer it.

**What the header path proves, and what it does not.** The ingress checked
that the client held the key; the API sees only the certificate the ingress
says it was, and cannot check possession itself. So behind an ingress, a
sensor's identity is as good as two things outside the API: that every host
routing to it verifies (`auth-tls-*`), and that nothing but the controller
reaches the API port from a trusted address — anything that does needs only a
sensor's *public* certificate and its token. For `required` where that
matters, prefer the API's own listener (it makes the handshake), or a
dedicated sensor host on the ingress with `auth-tls-verify-client: "on"`, so
no request on that host gets through without a verified certificate. The
subject the ingress forwards (`ssl-client-subject-dn`) is compared with the
certificate's as a name, not as a string: nginx writes it in OpenSSL's
RFC 2253 form (`emailAddress=`, `\D0\9E…` for non-ASCII, `INN=`/`OGRN=`),
which a corporate subject in Cyrillic, with an e-mail address or a
multi-valued RDN reaches exactly. nginx older than 1.11.6 writes the legacy
`/C=…/O=…` form, which is not read — upgrade it.

**Where certificates come from.**

- *cert-manager*: a CA that signs sensor certificates only, and a
  `ClusterIssuer` around it — `examples/agent-mtls-cert-manager.example.yaml`.
  In-cluster sensors get a certificate per pod from the CSI driver
  (`examples/agent-mtls-patch.yaml`), with the sensor's SPIFFE URI in it;
  cert-manager renews it, and the sensor re-reads it within a minute. The
  first request with it records it (`source: observed`), so it is listed and
  revocable like any other.
- *The API*: give it `OCTO_AGENT_MTLS_ISSUER_CERT`/`_KEY` (an intermediate for
  this and nothing else) and set `OCTO_AGENT_MTLS_ENROLL=true` with the two
  file paths on the sensor. With `OCTO_AGENT_MTLS_CLIENT_CA` set too, the
  issuer must be in it or signed by a CA in it — start-up refuses an issuer
  the client CA would not accept, since every certificate it signs would be
  cut off in the handshake. The sensor writes the issuer after its leaf and
  presents both, so a terminator that trusts only the root (an
  `auth-tls-secret` holding the root, with `auth-tls-verify-depth: "2"`) can
  build the chain; the API's own listener also takes the issuer as an anchor
  for sensors that still present the leaf alone. A cert-manager issuer that is
  an intermediate belongs in `OCTO_AGENT_MTLS_CLIENT_CA` itself: the ingress
  forwards only the leaf, and the API links a leaf to a root only through its
  own issuer. The sensor sends a CSR to
  `POST /api/agent/certificate`, gets a certificate naming its token's agent —
  whatever the CSR asked for — and renews at two thirds of the lifetime. The
  first enrolment needs only the token; **every later one must present the
  current certificate**, so a stolen token cannot enrol a second certificate
  next to the real sensor's.
- *An enterprise PKI* that issues by host name: pin each certificate to its
  sensor, `POST /api/agents/{id}/certificates` with the PEM (tenant admin).

**Rollout, for a fleet that is already running.**

1. Deploy the release (migration `0077`); `OCTO_AGENT_MTLS_MODE` stays `off`
   and nothing changes. Finish the rollout before the next step — a replica
   still on the previous release ignores the mode entirely.
2. Wire the certificate path (ingress or listener) and the issuance (either
   of the two above). Enrolment works under `off` already: sensors with
   `OCTO_AGENT_MTLS_ENROLL=true` get their certificates now. Its renewals do
   need the certificate path — a renewal must present the current
   certificate whatever the mode, and without `OCTO_AGENT_MTLS_TRUSTED_PROXIES`
   (or the listener's client CA) the API never sees one. The API's own
   listener asks for it under `off` as well, as soon as it has a client CA or
   an issuer.
3. `OCTO_AGENT_MTLS_MODE=optional`. Sensors without a certificate keep
   working; one that presents a wrong one is refused and shows up as
   `agent.certificate_refused` in the audit trail — investigate those, they are
   a host holding two sensors' credentials or a mis-mounted Secret.
4. Watch `GET /api/agents/summary`: `client_cert_agents` should reach the
   number of sensors, and `client_certs_expired` stay at zero.
5. `OCTO_AGENT_MTLS_MODE=required`. A sensor without a certificate is now
   refused with `403` and `X-Client-Cert-Error: missing`; the sensor logs it
   once and backs off. The legacy shared `OCTO_AGENT_TOKEN` is refused
   outright — it names no sensor to bind a certificate to. Rolling back is
   setting the mode back; nothing is lost.

**Rotation** overlaps: a renewal leaves the previous certificate valid until
its own expiry, so a sensor that has written the new files but not yet reloaded
is not cut off. The API keeps two live certificates per sensor it issued for —
the newest and the one before — and revokes older ones as `superseded`.
cert-manager's renewals overlap the same way (`renewBefore`).

**Revocation** is immediate — the table is read on every request that
presents a certificate, and a renewal already in flight when the revocation
commits is refused rather than issued (issuance and revocation of one sensor
are serialised on its enrolment record):

```bash
# a stolen or copied host: first the provisioning key it holds (see below),
# then everything this sensor holds
curl -X POST "$API/api/tenants/$TENANT/provisioning-keys/$KEY_ID/revoke" -H "$AUTH"
curl -X POST "$API/api/agents/edge-01/certificates/revoke" -H "$AUTH" \
  -d '{"all": true, "reason": "laptop stolen"}'
# one certificate, by fingerprint (colons optional) or serial
curl -X POST "$API/api/agents/edge-01/certificates/revoke" -H "$AUTH" \
  -d '{"fingerprint": "ab12…", "reason": "old key found on a share"}'
curl -X POST "$API/api/agents/edge-01/certificates/revoke" -H "$AUTH" \
  -d '{"serial": "4f2a…"}'
```

**Revoking a certificate the sensor held also locks the sensor.** Without
that, revoking would undo itself: with nothing live left on record, the
host's token would enrol a new certificate on its next poll (the review of
#509 timed it at five seconds). "Held" means a certificate on record for this
sensor that was not revoked yet — live, or already expired. After such a
revocation, until an operator resets it, the sensor:

- cannot enrol by token alone (`403`, `X-Client-Cert-Error: enrolment-locked`) —
  in every mode, `off` included, since enrolment does not depend on the mode;
- cannot call anything without a certificate under `optional` as under
  `required` (the same `enrolment-locked`), so *this sensor's token* does not
  simply fall back to working without one;
- still works with a certificate that is live and its own *and on record* —
  revoking one old certificate after a rotation does not stop the sensor
  holding the new one. A certificate the platform has never seen is refused
  `enrolment-locked`, however valid: cert-manager reissuing to the stolen host
  (the CSI driver on a pod restart, a renewal that external-secrets delivers
  to a VM) does not bring it back. For a stolen host revoke `{"all": true}`, so
  it holds nothing live; the CA can keep issuing, the API keeps refusing, and
  deleting the `Certificate` (or the pod's CSI volume) stops the noise.

A tombstone (below) and a certificate that was already revoked — a
`superseded` one, say — lock nothing: the sensor never held the first, and
revoking the second again changes nothing it holds. So revoking a leaked
certificate before its first use does not shut out a sensor still working
without a certificate under `optional`, and tidying up an old certificate
does not turn the next expiry into an operator's job. The `revoke` audit row
says whether the sensor is locked (`enrolment_locked`).

**The lock stops an identity, not a host.** It is keyed by the agent id. A
stolen host that still holds the provisioning key exchanges it for a token
under any other agent id (or none: the API then picks one) and enrols that
from scratch — so for a stolen host, revoke the provisioning key *first*
(`docs/api-and-rbac.md`), then the certificates, as above. A key shared by a
fleet means a new key for every sensor on it (`other_agents_on_key` on the
agent says how many). The lock is what keeps the certificate revocation from
being undone by the token in the meantime. The sensor logs the refusal and
retries every five minutes. `client_cert_locked` in `GET /api/agents/summary`
counts locked sensors.

**Deleting the sensor lifts its lock only when its token is dead.** Deleting
an agent alone is a pause, not a revocation — a host with its token registers
again under the same id — so while its provisioning key is still active (or
there is none on record: a legacy shared token), the lock stays with the id,
`client_cert_locked` keeps counting it, and `client_cert_locked_agents` in
`GET /api/agents/summary` names it (the first 50 ids; the Sensors page shows
them). A host re-installed under that id is refused `enrolment-locked` until
the enrolment is reset; the reset below works by id for a deleted sensor too.

Delete it with `?revoke_key=true`, or after revoking its key (the order for a
stolen host, above), and the lock goes with it: every request with that token
is already refused, so the lock would protect nothing and only keep "1 locked"
on the Sensors page until somebody reset the stolen sensor to clear it. The
delete answers `client_cert_lock_lifted: true` and records an
`agent.certificate_enrolment_reset` row with the reason `agent deleted; its
provisioning key is revoked` (or `expired`). The sensor's certificates stay on
record, revoked; a host later given a new key under the same id enrols from
scratch.

**Resetting the enrolment** is the separate, deliberate act that lets the
sensor enrol from scratch by its token — tenant admin, behind the same
multi-factor step-up as minting a provisioning key, audited as
`agent.certificate_enrolment_reset`:

```bash
curl -X POST "$API/api/agents/edge-01/certificates/reset-enrolment" -H "$AUTH" \
  -d '{"reason": "host re-imaged, new key"}'
```

It revokes whatever of the sensor's certificates is still live ("from
scratch" means the old key stops working too), lifts the lock, and allows
exactly one enrolment without a certificate — two arriving at once get one
certificate between them, and the other is refused `missing` and recorded as
a conflict (below). The next one is a renewal again. Whoever enrols first
after a reset wins it, so if the token may be elsewhere, revoke the
provisioning key and give the host a new one *before* resetting.

A fingerprint the platform has never seen is recorded as a revocation all the
same (`source: tombstone`), so a certificate can be revoked before its first
use; it does not lock the sensor (above). A serial has to match one on
record: a serial alone does not say which CA issued it. The ingress does not consult this list — the API does — so revoke
here, not by editing the ingress CA.

**A sensor that lost its key** (re-imaged host, an emptyDir that went with its
pod) cannot enrol again while its old certificate is live, because that rule
is what stops a stolen token. Reset its enrolment (above); the sensor's next
enrolment then succeeds without a certificate. A sensor whose certificate ran
out while it was offline needs nothing: it stops presenting a certificate
five minutes before `not_after` (the handshake — the API's, or
ingress-nginx's with a `400` — refuses an expired one before any route runs),
expiry is not revocation, nothing locks, and with no live certificate left
it enrols from scratch by its token. Until then it is a sensor without a
certificate: working under `optional`, refused `missing` under `required`. A
*mounted* certificate that runs out is the same, except that nothing on the
sensor can renew it: the sensor logs that the file has run out, and under
`required` is refused until cert-manager (or the host's PKI agent) replaces
it.

**An enrolled sensor's key and certificate change together.** The new pair is
staged as `<file>.next` and moved in after both are on disk; a crash in
between is completed at the next start. A pair that still does not match —
left by a release before this — is deleted and the sensor enrols again; if
the API holds the certificate the lost key belonged to as live, that
enrolment is refused `missing` and needs the reset above.

**A sensor shut out by somebody else's enrolment.** The first enrolment of a
sensor needs only its token, so whoever holds a copy of the token and enrols
first gets the certificate; the real sensor is then refused with `missing` on
every poll. That refusal — nothing presented while a live certificate of the
same sensor is on record — is the one event that says the token is somewhere
else, so it is recorded: `agent.certificate_refused` with
`agent_holds_live_certificate: true`, at most once per sensor per hour, and
`client_cert_conflicts` in `GET /api/agents/summary` counts the sensors with
one in the last day (the Sensors page raises it). The same event fires for a
sensor that lost its key or whose certificate the ingress stopped forwarding,
so check the host first. If the certificate on record is not the host's:
revoke the provisioning key, revoke `{"all": true}` on the sensor (which
locks it), install a new key on the real host, then reset the enrolment.
A cert-manager certificate the API has not seen yet does not count as live
here — the first request with it records it.

**Expiry** shows in the fleet summary: `client_certs_expiring` counts sensors
whose newest certificate runs out within `OCTO_AGENT_MTLS_EXPIRY_WARN_DAYS`,
`client_certs_expired` those whose certificates all have. Each sensor's list
(`GET /api/agents/{id}/certificates`) says which is which.

**Lariska does not support client certificates yet.** Until it does,
`required` — an installation-wide mode — refuses every Agent: stay at
`optional` while Agents are deployed, or pin certificates an MDM puts on the
endpoints. The contract it is to implement, in this order (the API side is in
place and tested):

1. Exchange the provisioning key for a token, as today.
2. Enrol **before** registering — under `required`, register needs a
   certificate: `POST /api/v1/agent/certificate` with
   `{"csr": "<PEM>", "agent_kind": "endpoint"}` and no certificate. The answer
   names `spiffe://<domain>/tenant/<tenant_id>/agent/<agent_id>`; without
   `agent_kind` an agent not on record yet enrols as a sensor (`/sensor/`),
   which binds the same but reads wrong. Once the agent is registered its
   recorded kind wins.
3. Present that certificate on every request from then on, `register` first.
4. Renew at `renew_after`, presenting the current certificate.
5. On `403` with `X-Client-Cert-Error`: `missing`/`revoked`/`expired` mean
   "enrol again" — one attempt, then back off for minutes, because
   `enrolment-locked` (a revocation, until an operator resets it) and
   `missing` for an agent that already holds a live certificate do not clear
   by retrying. `mismatch`, `unbound` and `no-identity` are an operator's
   problem.

### SSH push deployment

`POST /api/agent/deploy/ssh` (tenant **admin** since
[#231](https://github.com/onixus/Shapoclyack/issues/231), plus
`tenant.credential.manage` and a recent step-up since #504, and the **Deploy
agent** dialog in the UI) installs a sensor by running the same installer from
the API: verify the target's host key → connect → read the target's
`/etc/shapoclyack/agent.env` to see which sensor, if any, it already runs →
mint a tenant provisioning key, unless the host keeps the one it has → run the
installer on the target, feeding it the new key, if any, on stdin → revoke the sensor's
previous key if the run moved it (below) → wait up to 30 s for the sensor's
first heartbeat. The API runs the OpenSSH client (`ssh`,
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
  so the deployer never lets it prompt. Reading `agent.env` (`0600`) is the
  first thing that needs root, so on a host where `sudo` asks, the run fails at
  `Host check failed` with `sudo: a password is required`, before any key has
  been minted. Root over SSH needs no sudo.
- The installer needs a sensor package (the `agent` Python package). The API
  serves none, so a native
  (systemd) install through this route ends with `No agent package available`
  unless an `agent` directory is already staged in `/opt/shapoclyack-agent`;
  `use_docker: true` avoids that by running the published
  `shapoclyack-scanner` image (`AGENT_IMAGE` overrides it), which is the
  shape this route can complete unattended today.

**Redeploying a host that already runs a sensor.** Every push used to mint a
key and pass a fresh `--agent-id`, so a second push to the same host registered
a second sensor. The first went `stale`, was counted in `stale_agents`, was
announced as `agent_offline`, and kept its sensor group and any quarantine,
while the host came back ungrouped and `active`. Now the run reads the host's
`agent.env` through `sudo -n` before anything is minted. It reads the agent ID,
the tenant, and a SHA-256 prefix of the key. The key itself stays on the host.
The prefix is the non-secret `key_lookup` the API indexes keys by, so the API
can tell whether the host holds the key the sensor is bound to. Then:

| The host, and the request's `agent_id` | What the run does |
|---|---|
| Runs sensor X of this tenant and holds the key X is bound to; `agent_id` empty or X | Reinstalls X with `--keep-key`. Same ID and same key, nothing minted or revoked, and group and lifecycle state stay. This is the Deploy dialog's case, since it sends no `agent_id` |
| X is registered, but its key is revoked or expired, or none is on record | Mints a key, and X takes it over on registration. Nothing to revoke. To rotate a sensor's key through the push, revoke the old key first |
| X is registered with an active key the host does not hold (a rebuilt host named in `agent_id`, or a hand re-run that left another key behind) | Mints a key and, **once the installer has succeeded**, revokes X's previous key, because the exchange refuses the ID to a new key while that one is active. This is re-checked just before revoking |
| … and X is online | **Refused** before anything is minted or installed. Revoking would take the ID from a running sensor. Stop it first, or send a new `agent_id` |
| … and other sensors hold X's key | **Refused**. Revoking a fleet key would stop them all. Revoke it yourself if you mean to (the next push then mints a key), or send a new `agent_id` |
| No `agent.env`, no `agent_id` | New sensor `agent-<host>-<random>` with a new key |
| `agent.env` is for another tenant, or its ID is not a printable token of at most 128 characters | Not reused. New sensor, new key |
| `agent_id` names no registered sensor | New sensor under that ID. If the host ran another sensor, that one stays in the fleet until you delete it, and the log says so |
| `agent_id` is registered in another tenant | **Refused**. The exchange would refuse it forever |

The run's log says which of these happened, before the key step, and ends
with either `sensor X redeployed with its identity kept` or `new sensor X`. A
revocation gets its own line. A `disabled` or `quarantined` sensor keeps that
state. The reinstalled sensor is refused a token until an admin re-activates
it, so the run says so and does not wait for a heartbeat. The key the run mints
and any key it revokes are recorded in the audit trail under the admin who
started it. Before this change they were recorded as `system`.

Sensors that earlier pushes duplicated are not merged. Delete the stale rows
with `DELETE /api/agents/{id}`, and leave `revoke_key` off: the sensor that
replaced a row may hold the same key.

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
required database access — a privilege an order of magnitude above running a
sensor fleet — so the predictable substitute was to pass whatever fingerprint
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
It is not the webhook policy: sensors live inside private networks, so RFC1918
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
  a warning, not a failure: the install may still be fine, so check the Agents
  page (sensors; route `/agents`);
- a run that fails at the installer leaves the key it minted active and unused
  (label `SSH Remote Deploy on <host>`). Revoke it from the key list. A
  previous key that was due to be revoked is left alone, so the sensor that
  holds it keeps working.

### Upgrade

`POST /api/agents/{id}/upgrade` (the drawer's **Upgrade** button) sets
`upgrade_requested` on the `agents` record. For a sensor that is a marker for
the operator surface — no channel carries it to the host, and the sensor does
not act on it.
The upgrade itself runs on the host. On a native sensor that is
`scripts/update-agent.sh` (not installed by the installer — copy it to the
target) run as root, which installs the **signed sensor bundle**; see
[Sensor bundle updates](#sensor-bundle-updates). `--restart-only` restarts the
sensor without touching the package. There is no self-update: the sensor
process never replaces itself, and nothing polls the server for a new version
unless you install a timer for it. For a Docker install, pull the new image and
re-run the installer with `--docker` (or roll the Kubernetes deployment).

**Removing a sensor** from the Sensors page (`DELETE /api/agents/{id}`) only
forgets the registration. Stop `shapoclyack-agent.service` (or the container)
on the host first, otherwise the next heartbeat registers it again.

### Sensor bundle updates

A native sensor updates from a **signed bundle**
([#363](https://github.com/onixus/Shapoclyack/issues/363)): the `agent` package
as a tarball, and a manifest naming its version, sha256 and size, signed with
the **release key** — the cosign key pair that signs the images
([supply-chain.md](supply-chain.md)). The publish job builds and signs it in its
`Sensor bundle` stage (`scripts/build-sensor-bundle.sh`) and archives three
files: `sensor-bundle.json`, `sensor-bundle.json.sig` and
`shapoclyack-sensor-<version>.tar.gz`. A `DRY_RUN` builds them unsigned, and no
sensor will install that. So does a **prerelease** tag (`-alpha<N>`, `-beta<N>`,
`-rc<N>`): one `OCTO_AGENT_BUNDLE_DIR` serves every sensor that updates with
`--auto`, and a beta signed with the release key would reach all of them. To
try a prerelease on a test sensor, sign its bundle by hand as for a key
rotation ([supply-chain.md](supply-chain.md)) and install it with
`--bundle-dir`. The sensor orders a prerelease below the release it precedes
(`0.47-1005-beta1` < `0.47-1005`), so the final release replaces it as an
upgrade.

**Publishing it.** Put the three files in a directory every API replica can
read and point `OCTO_AGENT_BUNDLE_DIR` at it. The API reads them on each
request, so replacing them publishes a new bundle without a restart. Check what
the sensors will be offered:

```bash
cosign verify-blob --key cosign.pub --insecure-ignore-tlog \
  --signature sensor-bundle.json.sig sensor-bundle.json
```

(`--insecure-ignore-tlog` because the signature is not in Rekor: sensors verify
offline against the pinned key, so a transparency-log entry is nothing they
would look at.)

**Updating a sensor.** Copy `scripts/update-agent.sh` somewhere only root can
write — it is what runs as root — and run it there:

```bash
sudo install -m 0755 -o root -g root update-agent.sh /usr/local/sbin/shapoclyack-update-agent
sudo shapoclyack-update-agent            # fetch from the API this sensor reports to
sudo shapoclyack-update-agent --check    # verify and report, change nothing
sudo shapoclyack-update-agent --bundle-dir /media/usb/sensor-bundle   # air-gapped
```

`--bundle-dir` may be relative to where the script is run; the files in it are
read by the sensor's account, not by root, so a directory under `/root` or files
copied with `umask 077` are refused with that reason.

**Root does two things and nothing else**: it runs the verifier *as the
sensor's account* (`runuser -u shapoclyack`, BusyBox `su` on Alpine) and it
restarts the unit. The install directory belongs to that account, so root
running the venv's interpreter or the `agent` package would hand the account a
way to root; as the account, the updater changes nothing the account could not
already change. The account's process is also cut off from the terminal root
ran the script from: it runs under `setsid` (which the script requires; the
BusyBox one without `-w` will do), with stdin from `/dev/null` and its output
read back through a FIFO by root, so a planted interpreter cannot push
keystrokes into root's shell with `TIOCSTI` (the CVE-2016-2779 class; kernels
before 6.2 allow it by default). What it prints reaches the terminal as
printable ASCII, tabs and newlines only: control characters are dropped, so no
escape sequence gets a terminal that answers one (a title report, `DECRQSS`)
to type into root's input either. Started by hand
as root over a tree another account owns, `python -m agent.update` stops with
an error — a guard against that accident, **not a boundary**: by the time the
check runs, root is already executing code that account can rewrite. Only the
script keeps root out of that code.

The verifier is `python -m agent.update` from the **installed** package — the
one already on the host, never the one arriving. It reads the URL and the
credential from `/etc/shapoclyack/agent.env`, and only those, the proxy/CA
variables and the sensor's client certificate (`OCTO_AGENT_TLS_CLIENT_CERT`/`_KEY`,
presented as the sensor presents it, so the update works under
`OCTO_AGENT_MTLS_MODE=required`; enrolling and renewing stay the sensor's):
`OCTO_AGENT_BUNDLE_PUBKEY_FILE` and `OCTO_AGENT_PROVISIONING_KEY_FILE`
written into that file are ignored. What it refuses, before anything on disk
changes:

- a manifest whose signature does not verify against the key pinned in
  `agent/update.py` (the repository's `cosign.pub`; `OCTO_AGENT_BUNDLE_PUBKEY_FILE`
  replaces it for an installation that signs its own). **The API being the
  configured server counts for nothing**: a compromised API cannot get code onto
  a sensor without the release key;
- a signed document that is not a sensor bundle manifest (the release key also
  signs image payloads);
- an archive whose size or sha256 differs from the signed manifest, or a server
  that streams more than the signed size;
- a **downgrade**: a version below the installed one, by the signed version and
  in the `dpkg` ordering `OCTO_AGENT_MIN_VERSION` uses. A replayed old bundle has
  a genuine signature, so this check is what stops it. The installed version is
  "nothing to do", not an error;
- a version below `OCTO_AGENT_MIN_VERSION` — the API's (served as `min_version`)
  or one set in the sensor's own `agent.env`, whichever is higher;
- an archive holding anything but regular files and directories under `agent/`,
  or an `agent` package whose `__version__` is not the signed version.

**How it installs.** Each release is unpacked under
`/opt/shapoclyack-agent/releases/<version>-<random>/agent`, and
`/opt/shapoclyack-agent/agent` — what the unit imports, since it runs from that
directory — becomes a symlink to it, replaced with an atomic `rename(2)`. The
first update moves the installer's plain `agent` directory under `releases/`
as `legacy-<version>-…`. In order:

1. **stage** — unpack, check the version, import `agent.worker` and
   `agent.update` from the staged tree in a fresh isolated interpreter of the
   sensor's venv. A release that does not import never goes live — including
   one whose service would run but whose updater would not, which would
   otherwise be kept and leave the host with nothing to install the fix with;
2. **swap** — journal the previous release to `.sensor-update.json`, then swap
   the link;
3. **health check** — the script, as root, runs
   `systemctl restart shapoclyack-agent.service`, and the unit must stay active
   **as the same process** for 20 seconds (`HEALTH_SECONDS`). `Restart=always`
   brings a crashing sensor back every five seconds and calls it active, so a
   changing main PID is what fails it;
4. **keep or revert** — healthy: `--commit` drops the journal. Not: `--rollback`
   points the link back at the previous release, the unit is restarted onto it
   and the script exits `1` with the reason. If the script is killed between
   swap and verdict (an SSH session dropped mid-check), the next run finds the
   journal and puts the previous release back **before** asking whether there
   is anything to install, so the same version still being offered cannot
   leave the unverified release live. The verifier then stops (exit `4`) and
   the script **restarts the unit onto the release put back** — the process
   still runs the one taken out — before it fetches and judges the bundle
   again, so a bundle refused or an API unreachable at that point no longer
   leaves the unit on code that is not live. `--check` changes nothing, this
   included: it reports the interrupted update and exits `1`.

**Interrupting the script** — `^C`, an SSH session that drops, `SIGTERM` —
does not leave an unchecked release live. The verifier runs in a session of
its own, so the terminal's `SIGINT` does not reach it; the script sends it
`SIGTERM`, waits for it to go, puts back whatever this run swapped in
(`python -m agent.update --abort`, which unlike `--rollback` does not record
the release as failed: it was not judged), restarts the unit onto it if
anything was put back — or if an earlier run's recovery had put a release back
and the unit had not been restarted onto it yet — and exits `130`/`129`/`143`.
Interrupted during `--check`, or before it has started changing anything, it
only stops; interrupted after `--commit` kept the release, it says that nothing
was waiting for a verdict and leaves the release live. A second `^C`, `SIGTERM`
or hangup during that clean-up is ignored: the verifier putting the release
back and the restart that follows run in sessions of their own, so the
terminal's `SIGINT` reaches neither; it takes a moment. A verifier that ignores
`SIGTERM` has its whole process group killed after `STOP_SECONDS` (10), and a
process it left behind still holding its output is no reason to wait: the
script reads that output for `DRAIN_SECONDS` (5) more, or until the next
signal, and goes on.

**One update runs at a time, for the whole run.** The script takes an
exclusive `flock` on `/run/shapoclyack-update-agent.lock` (`LOCK_FILE`) — root's
file, outside every directory the sensor's account can write, mode `0600` (an
existing file is tightened to it: `flock` needs only read access, so a file
other accounts could open would let any of them hold the lock and keep every
update out) — before its first look at the journal and holds it to the verdict;
nothing it runs as the account inherits the descriptor. A second run started meanwhile, a timer tick
during a manual run's health check included, stops with "Another sensor update
is running" and changes nothing. (Held only per call of the verifier, as
before, a timer could take a manual run's journal in the middle of its health
check, and the manual run's rollback then recorded the timer's healthy release
as failed.) "kept" is logged only when `--commit` kept a release; one that found
nothing pending exits `3` and the script reports an error.

After an update that is kept, the live release and the one before it stay
and older ones are removed. After one that is put back, the live release
stays, and so does the one taken out for as long as the unit may still run
from it — a running Python imports lazily — while everything else goes, so
failed attempts do not pile up between updates that are kept. If the restart
onto the previous release fails, the tree the unit is left on is not removed;
the error is logged.

**The bundle is the `agent` package and nothing else.** The worker starts
`python -m scanner.main` from the install directory; a `scanner/` tree staged
there next to `agent`, and the venv, are not in the bundle and stay as they
are. The log says "Sensor agent package updated to …" for that reason.
Without systemd (OpenRC hosts) the health check is the import of the swapped-in
tree, and the sensor process has to be restarted by hand.

Limits worth knowing:

- **the restart interrupts a running scan**. The job's lease runs out and it is
  handed out again, but update an idle sensor where you can;
- **a release that failed its health check here is not retried by `--auto`.**
  Its signed digest is recorded in `.sensor-update-failed.json` in the install
  directory; the timer logs that it skips it instead of installing it, crashing
  and rolling back on every tick, and does so from the signed manifest, before
  downloading the archive (a bundle already installed is not downloaded
  either). A run without `--auto` tries it again, and an update that is kept
  clears the record;
- **dependencies are not updated.** A bundle whose service or updater needs a
  Python package the venv lacks fails the pre-swap import and is refused, safely; such a release
  is installed by re-running `install-agent.sh`, which reinstalls the venv from
  the hash-locked list;
- **a sensor installed before this release has no verifier.** `update-agent.sh`
  says so and stops; upgrade such a host once by re-running the installer;
- `update-agent.sh --bundle-url` is **gone**: it installed an unsigned tarball
  from whatever the URL served. It now stops and points here;
- **no freshness, no revocation.** A signature does not expire, so an API in an
  attacker's hands cannot install anything unsigned or older, but it chooses
  which genuine newer release to offer — or offers none and keeps the fleet
  where it is. Watch the fleet's versions (`GET /api/agents/summary`) rather
  than assume a published fix arrived;
- **redirects are not followed.** Nothing the sensor calls on the API
  redirects, so a `3xx` — to `GET /api/agent/bundle`, the download, the key
  exchange or any other call — is an error: the bearer token is never sent on
  to the `Location`, and the `3xx` body is read with the same limit as any other
  error body, the `Location` logged. An API behind a proxy that redirects (to
  HTTPS, to another path) has to be configured with the URL it ends at. This is
  the sensor's calls to the API only: feed downloads (`scripts/feed_fetch.py`,
  not on the update path) still follow redirects by design, refusing one from
  `https` to anything weaker ([air-gap](air-gap.md));
- the install directory and its code stay owned by the sensor's account, as the
  installer leaves them: the updater does not make the sensor's own account any
  less able to change its own code, it only keeps root from running it.

**Automatic updates are off, and stay off unless you turn them on twice.** The
sensor never updates itself, and nothing runs the updater on a schedule. To opt
in, set `OCTO_AGENT_AUTO_UPDATE=true` in `agent.env` **and** install a timer
that runs the root-owned script with `--auto` (without the variable, `--auto`
exits doing nothing):

```ini
# /etc/systemd/system/shapoclyack-agent-update.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/shapoclyack-update-agent --auto

# /etc/systemd/system/shapoclyack-agent-update.timer
[Timer]
OnCalendar=Sun 03:00
RandomizedDelaySec=2h
[Install]
WantedBy=timers.target
```

The timer runs the script as root, and the script runs the verifier as the
sensor's account, exactly as by hand. The same checks apply, and a refused or
failed update leaves the running release in place.

### Endpoint Agent (Lariska) builds

Unlike a sensor, the endpoint Agent (Lariska) is upgraded by the API: a tenant's
policy names a version (`PUT /api/endpoint/agent/policy`, `desired_version`),
the heartbeat hands the agent that build's sha256 and URL, and the agent
downloads it with its own token and refuses bytes that do not match. The
builds themselves are stored once for the installation, one per
`(version, platform)`, so:

- **Uploading and deleting a build is the platform admin's**
  (`platform.endpoint_agent_release.manage`, behind a step-up, #510). A
  re-upload of the same pair replaces the bytes every tenant's endpoints are
  handed; a delete stops every tenant's upgrade to it.
- **A tenant admin** (`endpoint_agent.manage`) lists the builds and decides
  which one its own endpoints run. It cannot upload, replace or delete one, and
  the list it reads carries no `uploaded_by`.

```bash
curl -sS -X POST https://<api-host>/api/endpoint/agent/releases \
  -H "Authorization: Bearer <platform-admin token, recently re-verified>" \
  -F version=0.3.0 -F platform=x86_64-pc-windows-msvc \
  -F binary=@lariska.exe -F notes="release notes or build id"
```

Compare the `sha256` in the response with the digest of the build you meant to
publish before any tenant names that version.

**On upgrade to the release that made this platform-only.** Builds already
stored stay as they are and stay downloadable — nothing is migrated or
re-hashed. Before it, any tenant's admin could have uploaded one, and the row
would be served to every tenant. Check this once, as the platform admin, and
check it **from the audit trail, not from the current rows**: the rows show
only the last write, so a build a tenant replaced, that endpoints downloaded,
and that it then re-uploaded with the official bytes looks clean; and a build
a tenant uploaded and then deleted is not there at all. Before this release a
delete was not audited either, so for a deleted build the upload event is the
only trace left.

Run it **after the last replica on the previous release is gone** (`kubectl
rollout status`, or no old pod left in `kubectl get pods`): until then an old
replica still accepts a tenant's upload, and a check made earlier misses it.

1. Export the upload history. `GET /api/audit` lists every tenant for the
   platform admin when no `tenant_id` is named, and `format=ndjson` streams
   all of it rather than one page:

   ```bash
   curl -sS -H "Authorization: Bearer <platform-admin token>" \
     "https://<api-host>/api/audit?action=endpoint_agent.release.upload&format=ndjson" \
     > release-uploads.ndjson
   curl -sS -H "Authorization: Bearer <platform-admin token>" \
     "https://<api-host>/api/audit?action=endpoint_agent.release.delete&format=ndjson" \
     > release-deletes.ndjson
   ```

2. Every upload event **with a `tenant_id`** was made before the change — this
   release records uploads and deletes with none. The `tenant_id` is the tenant
   the console was looking at, not proof a tenant did it: the platform admin's
   own uploads from before carry one too, so `actor` says who it was. List them:

   ```bash
   jq -c 'select(.tenant_id != null)
          | {occurred_at, tenant_id, actor, build: .resource_id, sha256: .after.sha256}' \
     release-uploads.ndjson
   ```

3. Compare each one's `sha256` with the build you published. Put your digests
   in `official-builds.json` as `{"<version>/<platform>": "<sha256>", ...}`;
   this prints every pre-change upload that was not one of them, including a
   version you never published:

   ```bash
   jq -c --slurpfile official official-builds.json \
     'select(.tenant_id != null and .after.sha256 != $official[0][.resource_id])
      | {occurred_at, tenant_id, actor, build: .resource_id, sha256: .after.sha256}' \
     release-uploads.ndjson
   ```

   Any line here is a binary you did not publish that was served to every
   tenant whose policy named that version, **whatever the build holds now**.
   That covers both cases the current rows hide: *replaced then restored* (a
   foreign digest followed later by yours under the same `build`) and
   *uploaded then deleted* (a `build` with no row left in
   `GET /api/endpoint/agent/releases`).

4. For each `build` printed, read its whole history, oldest first, to get the
   window during which the foreign bytes were the ones handed out — from that
   event to the next upload of that build, or to now if the build is still
   stored. Deletes from this release on carry the removed row in `before`:

   ```bash
   cat release-uploads.ndjson release-deletes.ndjson \
     | jq -s -c --arg build "0.3.0/x86_64-pc-windows-msvc" \
         'map(select(.resource_id == $build)) | sort_by(.occurred_at) | .[]
          | {occurred_at, tenant_id, actor, action, sha256: (.after.sha256 // .before.sha256)}'
   ```

5. Find the endpoints that may have run it. The server keeps **no** record of
   which bytes an endpoint installed: the heartbeat reports only the running
   version (`GET /api/agents`, `version` on endpoint Agents), and a download is
   not audited (the only server-side trace is the access-log line for
   `GET /api/endpoint/agent/releases/<version>/<platform>/download`, with client
   IP and time, if your logs reach back that far). So treat every endpoint
   that reports that version, or reported it during the window, in any tenant
   whose policy named it, as suspect, and settle it on the host. Hash the
   binary the service runs (the default install paths below; use the one your
   service unit or Windows service points at if you installed elsewhere) and
   compare it with your digest:

   ```bash
   sha256sum /usr/bin/lariska                    # Linux
   shasum -a 256 /usr/local/bin/lariska          # macOS
   ```

   ```powershell
   Get-FileHash "C:\Program Files\Lariska\lariska.exe"
   ```

   A managed update keeps the binary it replaced beside the new one, with
   `.old` appended to the full name (`/usr/bin/lariska.old`,
   `/usr/local/bin/lariska.old`, `C:\Program Files\Lariska\lariska.exe.old`),
   until the next update overwrites it. Hash that file too: an endpoint that
   ran the foreign build and was then moved on can still have it there. A
   match on the running binary does not clear a host whose `.old` is foreign.

6. Then fix the build and the endpoints. Re-uploading the official bytes under
   the same version repairs neither: an endpoint already running the foreign
   binary reports that version, and the heartbeat offers no update when
   `desired_version` equals the version the agent reports.

   - **The build.** `DELETE` every row whose current `sha256` is not yours, and
     publish the official build under a **new** version (bump the patch, e.g.
     `0.3.0` -> `0.3.1`). Do not reuse the compromised version number.
   - **Endpoints that never ran the foreign bytes** (the host check in step 5
     came back clean, `.old` included): point their tenant's policy at the new
     version with `desired_version` and let the managed update move them.
   - **Endpoints that ran the foreign binary**, or that you cannot check:
     treat the host as compromised. That binary ran as the agent's service
     account with the agent's token, and nothing it reports is trustworthy —
     not its version, and not whether it applied an update, since it need not
     honour `managed_update` at all. Reinstall the official build on the host
     by hand (Lariska's install procedure) and remove the `.old` file. The
     foreign binary had the host's provisioning key and JWT, so revoke them —
     `DELETE /api/agents/{id}?revoke_key=true` (check `other_agents_on_key`
     first: the revocation stops every agent enrolled with that key) — and
     enrol the reinstalled agent with a fresh key. Handle the host under your
     incident process.

Builds are not signed yet: the API is the endpoint's only source of trust for
what it executes, which is why the write is the platform admin's alone.

## Tenant-defined roles

A tenant can define its own roles and grant them on memberships
([#318](https://github.com/onixus/Shapoclyack/issues/318); the API contract is
[api-and-rbac.md](api-and-rbac.md#tenant-defined-roles)). Three things an
operator of the installation needs to know about them.

**Upgrading.** Migration `0070_tenant_custom_roles` is expand-only: two
nullable columns on `roles`, two check constraints every seeded row already
satisfies, and an index on `user_tenants (tenant_id, role)`. No membership is
rewritten, and built-in role names keep resolving from the code without a
query, so nothing changes for anybody until a tenant defines a role. During a
rolling deploy a replica still on the previous release reads a membership that
names a tenant role as an unknown role and gives it the lowest authority (rank
1, no permissions). It also **cannot list that tenant's members**: the previous
release's member list declares the role as one of the eight built-in names, so
`GET /api/tenants/{id}/members` answers `500` on an old replica for every tenant
in which somebody holds a tenant role — the membership screens (`/users`,
`/access`) fail on whichever request lands there. Do not define or grant tenant
roles until every replica runs this release.

**Rolling back.** The schema half is safe: `0070` downgrades cleanly, keeps the
tenant roles' rows, and the previous release gives their holders the lowest
authority, never a higher one. The API half is not: as above, the previous
release answers `500` on the member list of every tenant where a membership
still names a tenant role, and keeps answering it after the rollback until
those memberships change. So **before** rolling back — not after — move every
holder to a built-in role:

1. List the holders:

   ```sql
   SELECT ut.tenant_id, ut.username, ut.role
   FROM user_tenants ut
   JOIN roles r ON r.role_id = ut.role AND r.tenant_id = ut.tenant_id AND NOT r.builtin;
   ```

2. Regrant each one a built-in role, through the API while this release still
   runs — `PUT /api/tenants/{id}/members/{username}` with `{"role": "<built-in>"}`,
   or `DELETE /api/tenants/{id}/roles/{role}?reassign_to=<built-in>` for all of
   a role's holders at once — so each move is an audited `membership.grant`.
   Choose a built-in that is **not stronger** than the tenant role; when none
   fits, `viewer`, and tell the member.
3. Run the query again; it must return no rows. Only then roll back.

A rollback that skipped this (an emergency one) leaves the member list broken
on the previous release until the same memberships are moved by hand in SQL
(`UPDATE user_tenants SET role = '<built-in>' WHERE …`, recorded in the
incident report, since no audit row is written).

**Deleting a role somebody holds** is refused (`409`) until its holders are
moved: `DELETE /api/tenants/{id}/roles/{role}?reassign_to=<role>` regrants all
of them in one transaction and records each move as a `membership.grant`.

**For whoever adds a built-in role in a later release.** Built-in names
resolve before a tenant's own, so a release that adds a built-in role whose
name some tenant already uses would silently give that tenant's holders the
new built-in authority. Tenant role names are refused only when they collide
with a built-in *today*; the migration that adds the built-in has to rename
the colliding tenant roles (and the memberships naming them) first.

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

**Refresh tokens and the idle timeout** (migration `0060_refresh_tokens`). A
console access token lives `OCTO_ACCESS_TOKEN_EXPIRE_MINUTES` (15) and is renewed
from an httpOnly cookie within a sign-in that ends after
`OCTO_JWT_EXPIRE_MINUTES` (8 hours) or after `OCTO_SESSION_IDLE_MINUTES` (30)
without a refresh, whichever comes first. Each sign-in is one row in
`session_families`, and the row says why it ended:

```sql
SELECT family_id, username, created_at, last_used_at, expires_at, revoked_at, revoked_reason
  FROM session_families WHERE username = 'alice' ORDER BY created_at DESC LIMIT 20;
```

`revoked_reason` is `logout`, `revoked` (revoke-all, disable, demote, password),
`idle`, `expired` — or `reuse`, which is the one to act on: a refresh token was
presented after it had been spent, meaning a second party held a copy. The same
event is in the auth trail as `outcome=denied`, `reason=refresh_token_reuse`
(`GET /api/auth/events?outcome=denied`), with the client address it was
presented from in `client_ip` — behind a proxy, only as good as
`OCTO_TRUSTED_PROXIES` makes it. The session is already ended by then;
what is left is finding out where the copy came from (a shared browser profile,
a synced cookie store, malware on the workstation) and, if in doubt,
`POST /api/users/{username}/sessions/revoke-all` plus a password reset.

Neither table needs a worker: families past their absolute end are deleted at
the next sign-in (their refresh tokens go with them by `ON DELETE CASCADE`), so
the table holds roughly "sign-ins in the last `OCTO_JWT_EXPIRE_MINUTES`", with
about one `refresh_tokens` row per ten minutes of each.

Downgrading past `0060` drops both tables and with them every refresh token:
consoles keep their current access token for at most fifteen minutes and then
sign in again. Nothing needs draining first.

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

**A lost security key** is the same procedure. The reset removes every
registered key along with the authenticator secret and the recovery codes (the
audit row's `before.webauthn_credentials` says how many), so the lost key stops
working the moment the reset lands. Somebody who still holds another key or
their phone does not need an admin: they remove the lost key themselves on the
Security page (`DELETE /api/auth/mfa/webauthn/credentials/{id}`, step-up) —
recorded as `user.webauthn_revoke`.

### Upgrading with an MFA policy: tenant admins are now covered (#504)

An installation running with `OCTO_MFA_REQUIRED_ROLES=admin` (or
`OCTO_MFA_PHISHING_RESISTANT_ROLES=admin`) covers more accounts after this
upgrade: everyone holding `tenant.member.manage`, `tenant.credential.manage`,
`scan_scope.approve`, `vulnerability.exception.approve` or
`endpoint_agent.manage` in **any** tenant — the tenant `admin`, `token-admin`,
`scope-approver`, `risk-approver`, and tenant-defined roles carrying one of
those — and everyone holding a tenant-defined role at the admin rank (3),
whatever their global role
([api-and-rbac.md](api-and-rbac.md#coverage-by-authority-in-a-tenant-504)).
Nobody is locked out: a newly covered account that has not enrolled gets a
session confined to the Security page, **on its open session as well**, from
the first request after the rollout. To see who that will be before upgrading:

```sql
SELECT ut.username, ut.tenant_id, ut.role
  FROM user_tenants ut
  JOIN users u ON u.username = ut.username
 WHERE u.mfa_enabled_at IS NULL
   AND u.role <> 'admin'
   AND (ut.role IN ('admin', 'token-admin', 'scope-approver', 'risk-approver')
        OR EXISTS (SELECT 1 FROM roles r
                    WHERE r.tenant_id = ut.tenant_id AND r.role_id = ut.role
                      AND r.rank >= 3)
        OR EXISTS (SELECT 1 FROM role_permissions rp
                    WHERE rp.tenant_id = ut.tenant_id AND rp.role_id = ut.role
                      AND rp.permission_key IN ('tenant.member.manage',
                          'tenant.credential.manage', 'scan_scope.approve',
                          'vulnerability.exception.approve',
                          'endpoint_agent.manage')))
 ORDER BY ut.tenant_id, ut.username;
```

To stage it — tell those people first, then cover them — deploy with
`OCTO_MFA_REQUIRED_PERMISSIONS=none` (and `OCTO_MFA_PHISHING_RESISTANT_PERMISSIONS=none`
under a key policy), which is exactly the old global-role behaviour, and
remove the override once they have enrolled. Granting and revoking memberships and editing tenant roles
also needs a recent step-up from an enrolled account now, like minting a
credential — and so do the endpoint agent policy and builds, the risk-acceptance
decisions, and disabling, deleting or signing out an account. A typo'd
`OCTO_MFA_REQUIRED_PERMISSIONS` that names no known permission at all now
refuses to start instead of reading as `none`.

Migration `0073` writes `tenant.credential.manage` onto every tenant-defined
role at rank 3, because `POST /api/agent/deployment-command` and the SSH push
now ask for that permission rather than the rank: the roles that minted keys
from the console before the upgrade still can. They also gain the
permission's other routes (listing and revoking provisioning keys, service
tokens up to their own authority). To see which roles the migration touched
before running it:

```sql
SELECT r.tenant_id, r.role_id
  FROM roles r
 WHERE NOT r.builtin AND r.rank >= 3
   AND NOT EXISTS (SELECT 1 FROM role_permissions rp
                    WHERE rp.tenant_id = r.tenant_id AND rp.role_id = r.role_id
                      AND rp.permission_key = 'tenant.credential.manage')
 ORDER BY r.tenant_id, r.role_id;
```

For the rank-3 roles that also hold `tenant.member.manage` the permission
brings **delegation** with it. A member manager may hand out what it holds, so
after the upgrade its holders can define a role carrying
`tenant.credential.manage`, grant it, and grant the built-in `token-admin` —
the credential travels on its own, where before it came only bundled in the
role itself (which such a holder could always grant: passing key minting on is
not new, its narrower shape is). Leaving these roles out would take the
console's **Deploy Agent** button from people who used it the day before, so
the migration does not; review them instead:

```sql
SELECT r.tenant_id, r.role_id
  FROM roles r
 WHERE NOT r.builtin AND r.rank >= 3
   AND EXISTS (SELECT 1 FROM role_permissions rp
                WHERE rp.tenant_id = r.tenant_id AND rp.role_id = r.role_id
                  AND rp.permission_key = 'tenant.member.manage')
 ORDER BY r.tenant_id, r.role_id;
```

After the upgrade this lists every tenant role that may pass the credential
on; before it, adding the first query's `NOT EXISTS` clause narrows it to the
ones the migration gives that power. Where that is not meant, either take
`tenant.credential.manage` off the role (and with it the button) or split it:
one role that manages members, another that mints keys.

A downgrade leaves those rows in place (nothing records which roles had the
permission before); remove it from a role in the role editor if it was not
meant.

### Rolling out security keys

WebAuthn needs a relying party the browser agrees with, and getting it wrong
after keys are registered orphans them, so settle it first:

1. Set `OCTO_WEBAUTHN_RP_ID` to the console's hostname (or a registrable
   parent of it) and `OCTO_WEBAUTHN_ORIGINS` to the exact origin the console is
   served from — `https://shapoclyack.example.com`, not the API's internal URL.
   Both default to `OCTO_PUBLIC_BASE_URL`, which is right when the console and
   the API share it. The console must be on `https` (or `localhost`): browsers
   do not expose WebAuthn anywhere else.
2. Let administrators register keys (Security page → *Security keys and
   passkeys*). Each needs the authenticator app enrolled first and a recent
   verification.
3. Only then set `OCTO_MFA_PHISHING_RESISTANT_ROLES=admin` (and, if wanted,
   `OCTO_MFA_STEPUP_PHISHING_RESISTANT=true`). An admin without a key is not
   locked out: a code-verified session is confined to the Security page, where
   it can register one. Watch `octo_mfa_verifications_total{outcome="webauthn_failure"}`
   in the first days — a spike is usually a wrong origin, and the API log names
   the reason for each refusal.

Changing `OCTO_WEBAUTHN_RP_ID` later invalidates every registered key: the
authenticator binds each credential to the RP ID it was created for. Treat it
like a domain migration — keys have to be registered again, and until then the
authenticator app is the way in.

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

### Making the IdP authoritative, and SCIM

`OCTO_IDP_AUTHORITATIVE=true` makes every SSO login recompute the account's
global role and IdP-granted memberships from its groups, and disable an account
in no mapped group ([api-and-rbac.md](api-and-rbac.md#idp-authoritative-resync),
#316). It changes what people can do at their next login, so turn it on in
this order:

1. **Map before you switch.** `OCTO_OIDC_ROLE_CLAIM` (e.g. `groups`),
   `OCTO_OIDC_ROLE_MAP` with the admin group in it, and `OCTO_IDP_GROUP_MAP` for
   the tenants. An SSO admin whose groups map to nothing is a viewer — or
   disabled — after their next login.
2. **Have the break-glass account in place** (above). It is never resynced, so
   it is how you get back in if the map is wrong.
3. **Know what stays.** Every membership that existed before migration 0076,
   every one a person grants afterwards, and every one JIT provisioning grants
   from `OCTO_OIDC_TENANT_CLAIM` while the mode is off is `source: local` and
   is never removed by the resync (`GET /api/tenants/{id}/members` shows the
   source). Revoke the grants you want the IdP to own, once `OCTO_IDP_GROUP_MAP`
   grants them; the next login re-grants them as `idp`.
4. **Know who will be refused.** With `OCTO_IDP_GROUP_MAP` or
   `OCTO_OIDC_TENANT_CLAIM` set, an account left in no tenant is disabled
   unless it is a platform admin — a group in `OCTO_OIDC_ROLE_MAP` alone no
   longer lets anybody into `default`. If people are meant to work in
   `default`, map it: `{"staff": [{"tenant_id": "default", "role": "viewer"}]}`.
   Before switching, list the SSO accounts whose only membership is one you
   are about to revoke, or that have none.
5. Switch it on and watch the trail:
   `GET /api/audit?action=membership.revoke`, `…?action=user.disable` and
   `…?action=user.role_change` — the resync's rows carry actor `oidc:<issuer>`
   and `"source": "idp"`; a disable's `reason` is `in no mapped IdP group` or
   `in no tenant`.

Rolling it back is setting the variable to `false`: nothing is undone, and
logins go back to deciding nothing after provisioning. An account the resync
disabled stays disabled until an administrator re-enables it
(`PUT /api/users/{u}/disabled`) or a login with the mode on finds a mapped
group again.

**SCIM** needs no switch — `/scim/v2` answers only an `octo_scim_` token, and
there are none until a platform admin issues one. It applies the maps on every
push whatever `OCTO_IDP_AUTHORITATIVE` says; with both maps empty pushes
change no access and only `active` does (lifecycle-only provisioning):

```bash
curl -sS -X POST "$API/api/auth/scim-tokens" -H "Authorization: Bearer $ADMIN_JWT" \
  -H 'Content-Type: application/json' \
  -d '{"name": "okta", "all_tenants": true, "expires_in_days": 365}'
```

Give the directory `https://<console>/scim/v2` as the base URL and the returned
`token` as its bearer token (it is shown once). Bind a token to the tenants a
directory serves (`"tenant_ids": [...]`) rather than `all_tenants` wherever one
directory belongs to one customer; add `"grant_platform_admin": true` only if
the directory is meant to make platform admins. Rotate by issuing a second
token, switching the directory over, then
`POST /api/auth/scim-tokens/{id}/revoke` on the old one. A group grants no
more than the token that created it could, so rotate to a token with the same
binding: groups an old tenant-bound or plain token created keep that token's
limits after the switch, and so do the members an old token added. A `503`
from `/scim/v2` is a push Postgres aborted for a concurrent one on the same
account; nothing was applied and the directory's retry succeeds.

A SCIM user can sign in through SSO once a group has granted it something.
The first login links it by **`externalId` = the ID token's `sub`**, or by an
address the IdP marks verified — never by username. Before connecting, check
that the directory sends the subject as `externalId` (Okta does by default);
otherwise every first login of a SCIM user is refused (JIT off) or provisioned
as a second account (JIT on).

**Map group names before you connect a tenant-bound directory.** A group it
pushes while its name is unmapped stays limited to its tenants even after the
operator maps that name elsewhere, and the name answers `409` to anyone else's
push. To give the name to the right directory: find the group with an
`all_tenants` token (`GET /scim/v2/Groups?filter=displayName eq "…"`),
`DELETE` it, and let the right directory push again. A username a tenant-bound
directory reserved with an account it never granted anything is freed by a
platform admin with `DELETE /api/users/{u}`.

With `OCTO_IDP_AUTHORITATIVE` on, watch `octo_idp_resync_skipped_total` and
the log line `IdP resync … skipped at SSO login: the ID token does not list
the groups`. Those logins change nothing — removals from groups do not take
effect for those accounts — and there are two usual causes:

- **Entra ID's group overage** (more groups than fit in the token): filter
  the groups claim to the groups assigned to the application.
- **An IdP that drops an empty claim** (Okta by default): someone removed
  from their last group gets a token with no claim at all. Either configure
  the claim so it is always sent and set `OCTO_IDP_GROUPS_CLAIM_REQUIRED=true`
  (a missing claim is then "in no group"), or deprovision through SCIM.

At startup, an info line says which reading is in force; a warning says the
mode stayed off because `OCTO_OIDC_ROLE_CLAIM` or both maps are empty.

And for `OCTO_IDP_GROUP_MAP maps group … to role …, which tenant … does not
have`: a typo in the map, or a role renamed while the map did not name it
(a mapped role cannot be renamed or deleted — `409`). Until the map is fixed,
the IdP memberships in that tenant whose role no entry of the map names are left
as they are; everything else is recomputed.

**Revoking a SCIM token** does not remove what its groups grant. When the
token is revoked because it leaked, list its groups with an `all_tenants`
token and delete the ones that should not stand. **Changing `OCTO_OIDC_ISSUER`**
leaves the stored `externalId`s of accounts nobody has signed in to yet
pointing at the old issuer's subjects: they are compared with `sub` alone, so
have the directory re-push them. A **taken address or `externalId`** (a
tenant-bound directory got there first, `409` for the right one) is freed by
re-keying that account with an `all_tenants` + `grant_platform_admin` token
(`PATCH` of `externalId` or `emails`), or by a platform admin's
`DELETE /api/users/{u}`.

The migration (`0076_idp_resync_scim`) is expand-only. Rolling it back drops
the `source` column — every membership is local again — the stored
`externalId`s, and every SCIM token and group; re-issue the token and let the
directory push again.

### Rotating the JWT signing key

`OCTO_JWT_SECRET` used to be unrotatable in practice: changing it invalidated
every console session at the moment of the rollout, and (while
`OCTO_AGENT_JWT_SECRET` is unset, which is the default) every sensor and Agent
token with them. `OCTO_JWT_SECRET_PREVIOUS` makes it a window instead.

1. **Generate the new key** — `openssl rand -hex 32`.
2. **Deploy both.** Set `OCTO_JWT_SECRET` to the new value and
   `OCTO_JWT_SECRET_PREVIOUS` to the old one (comma-separated if you are
   retiring more than one). From this deploy on, new tokens are signed with the
   new key and old ones still verify.
3. **Wait out the window.** `OCTO_ACCESS_TOKEN_EXPIRE_MINUTES` for console
   sessions (default 15 minutes: refresh tokens are not JWTs, and every refresh
   after the deploy signs with the new key — but give it
   `OCTO_JWT_EXPIRE_MINUTES`, 8 hours, if any console may still hold a token
   minted before migration 0060, which has no refresh behind it) and
   `OCTO_AGENT_JWT_EXPIRE_MINUTES` for sensors and
   endpoint Agents (default 2 hours). Every replica must carry the same pair throughout — a replica
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

### When callers start getting 429

The general rate limiter ([#320](https://github.com/onixus/Shapoclyack/issues/320),
settings in [configuration.md](configuration.md#environment-variables)) charges
every authenticated request to a bucket per principal, per tenant for users and
service tokens, and per agent. `octo_rate_limited_total{scope}` says which kind
of bucket ran out; the API's INFO log names the principal or tenant in
`rate limited: <scope> <key>, retry after <n>s (<m> more refusals in the last
60s not logged)` — once a minute per principal, not once per refusal.

1. **`scope="agent"` climbing** is one sensor or endpoint agent calling far
   more often than its cadence — a worker started with a `--poll-interval`
   under a second (an idle sensor makes two requests per poll), or a retry
   loop. Find the key in the log and fix the host; raise
   `OCTO_RATE_LIMIT_AGENT_*` only if the cadence is intended. The size of a
   provisioning-key fleet does not cause this: each of those sensors has a
   bucket of its own and none is pooled per tenant.
2. **`scope="legacy_agent"` climbing** is *not* one sensor. Sensors on the
   legacy shared `OCTO_AGENT_TOKEN` are charged per source address, and one
   address is every sensor behind it: behind an ingress without
   `OCTO_TRUSTED_PROXIES` that is the whole legacy fleet, behind a site's NAT
   the whole site. The key in the log is the address. In order of preference:
   move those sensors to provisioning keys (each gets its own bucket, and the
   legacy token stops being accepted in prod on 2027-03-01 anyway); set
   `OCTO_TRUSTED_PROXIES` to the ingress so each site is its own address; or
   raise `OCTO_RATE_LIMIT_LEGACY_AGENTS_PER_ADDRESS` (default 25 sensors at a
   1 s poll, 125 at the default 5 s) to the fleet behind the busiest address.
   A sensor that is refused waits out `Retry-After` — up to 30 s for a
   heartbeat or a claim, 10 minutes for a results upload, which is never
   charged by an API of this release anyway.
3. **`scope="tenant"`** is one customer's combined console and API traffic.
   Usually an integration polling in a tight loop under a service token; the
   `service_token` scope will often be climbing next to it.
4. **Everyone at once, right after an upgrade** — check that the limits were
   not set in requests per *minute* by mistake. `OCTO_RATE_LIMIT_ENABLED=false`
   and a restart switch the limiter off without touching the login limiter.
5. **`413` on a scan launch or a schedule** is a target list over
   `OCTO_TARGET_LIST_MAX_BODY_BYTES` (16 MiB, about 500 000 domains). Split the
   list across scans, or raise it; `OCTO_MAX_BODY_BYTES` does not apply there.

The buckets are an `UNLOGGED` table: a Postgres crash or failover empties it,
which hands every principal a full bucket — expected, nothing to repair. To
clear a bucket by hand (a principal throttled by a limit you have since
raised): `DELETE FROM rate_limit_buckets WHERE bucket_key = '<scope>:<key>';`.
Rows idle for longer than the slowest refill are pruned by the API itself.

## Logs and observability

### Log format, level, and the request id

`OCTO_LOG_FORMAT=json` puts the API and the sensor on one line-per-object
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
follow it into the sensor's own logs.

### Secret redaction, and what it does not cover

A `logging.Filter` on the process's handler rewrites each record's **rendered**
message before it is formatted, on both the API and the sensor. It renders the
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
curl --fail http://localhost:8080/readyz       # 503 when PostgreSQL or NATS is down
kubectl -n network-scan get pods,jobs,cronjobs
kubectl -n network-scan logs deployment/shapoclyack-api --tail=200
```

The catalogue of every series with the bound on each of its labels, the
Grafana dashboards, the sensor-heartbeat and connection-pool series, and the
opt-in ServiceMonitor / PrometheusRule / dashboard components are in
[observability.md](observability.md) (#334).

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

The full runbook — every store, the order of restore, how restore points of
Postgres, artifacts and ClickHouse are reconciled, the RPO/RTO table and the
drill that measured it — is [disaster-recovery.md](disaster-recovery.md)
([#333](https://github.com/onixus/Shapoclyack/issues/333)). This section keeps
the PostgreSQL backup and its restore script.

> **`overlays/prod-ha` moves this out of the cluster.** That overlay deletes the
> in-cluster PostgreSQL StatefulSet and the `pg_dump` CronJob below along with
> it, because the database is expected to be a managed one (RDS, Cloud SQL,
> CloudNativePG, Patroni). Backups, PITR and the restore drill then belong to
> that provider — everything in this section describes the in-cluster database
> that `base` and `overlays/prod` ship. See
> [high-availability.md](high-availability.md#external-postgres).

### Recovery objectives and verification status

The base deployment takes a logical PostgreSQL backup every day at 02:15 UTC.
That schedule gives a **design RPO of at most 24 hours** for PostgreSQL, assuming
the scheduled backup succeeds and is uploaded. The **RTO target is 60 minutes**
for restoring Postgres + API into an isolated namespace (the path
`scripts/restore-postgres.sh` implements). ClickHouse, the artifacts and
JetStream have their own rows in
[disaster-recovery.md § Recovery objectives](disaster-recovery.md#recovery-objectives).

| Measure | Target | Last measured |
|---|---:|---:|
| PostgreSQL RPO | <= 24 h | 3 min (backup `2026-08-20T09:21:29Z` → recovery `2026-08-20T09:24:32Z` on kind `shapoclyack-dev`; the CronJob still bounds worst-case at 24 h) |
| Full base-stack RTO | <= 60 min | 31 s (`recovery_seconds` from the restore script: `pg_restore` + API migrate rollout) |
| PostgreSQL `pg_restore` duration | n/a | < 1 s (`db_restore_seconds=0` at 1 s resolution; 82 KiB custom dump of the live lab: 5 assets, 10 identifiers, 3 users, 2 jobs) |
| Restore drill date | n/a | 2026-08-20 |

Namespace `shapoclyack-restore`, overlay `k8s/shapoclyack/overlays/kind-restore`.
Row counts after restore matched the source. JetStream was **not** replayed —
Postgres is the durable store; see [disaster-recovery.md § JetStream](disaster-recovery.md#jetstream).
ClickHouse and `scanner-data` were not snapshotted (kind `local-path` has no
`VolumeSnapshotClass`); the 10k-asset drill of all stores is in
[disaster-recovery.md § Drill](disaster-recovery.md#drill).

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
   `shapoclyack-restore`, no NodePort, no NATS, no scan Jobs or backup
   CronJobs; ClickHouse stays, as the target of `scripts/restore-clickhouse.sh`). Elsewhere:
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

### ClickHouse, artifacts and JetStream

These used to be described here in prose only. They now have a backup
CronJob (`base/backup/clickhouse-cronjob.yaml`), a restore script with a
verification step (`scripts/restore-clickhouse.sh`), a CSI snapshot example for
`scanner-data` (`examples/pvc-snapshot.example.yaml`), and a runbook that says
which store wins when their restore points disagree:
[disaster-recovery.md](disaster-recovery.md) —
[ClickHouse](disaster-recovery.md#clickhouse),
[artifacts](disaster-recovery.md#artifacts),
[JetStream](disaster-recovery.md#jetstream),
[reconciling restore points](disaster-recovery.md#reconciling-restore-points).

### NATS outbox

What a broker outage leaves behind, and how to see and drain it.

Since the 2026-09-18 architecture review, NATS is **not** a blocking readiness
check: an API replica whose broker is unreachable stays in its Service and goes
on serving everything that does not need the bus (the matrix is in
[high-availability.md § What a NATS outage costs](high-availability.md#what-a-nats-outage-costs)).
Two things would otherwise be lost silently. One is the `ingest.results.*`
message that feeds the ClickHouse projection: the upload is accepted, the
artifacts are written, the job succeeds — and analytics never hear about the
run. The other is the run's asset events, which are the only source of the
webhook fan-out: with the broker advisory the upload is accepted during the
outage, so a `new_cve` webhook that used merely to arrive late would never be
sent at all. The `nats_outbox` table (migration `0059`) and the reconciler
thread in every API replica hold both (`kind` is `ingest` or `asset_event`) and
republish them.

The writer for `ingest` is `run_publisher._publish_to_bus` — the last step of an
accepted run's publication, after the object store, the run directory and the
pointer. It publishes or records, and either way the publication closes, so a
broker outage costs the analytical projection its latency and costs the run
itself nothing. The writer for `asset_event` is `asset_events.publish_events`,
on the same post-run hook. Rows appear only while the broker is refusing; an
installation with a healthy broker has an empty table.

What an operator sees:

* `/readyz` and `/api/health` carry a `nats_outbox` check next to `nats`.
  It is `error` when any kind has been owed for longer than
  `OCTO_NATS_OUTBOX_BACKLOG_ALERT_SECONDS` (default 300), or when any entry has
  gone `dead`. Both endpoints stay 200 — this degrades the installation, it
  does not unready the replica. `kind=ingest` means the ClickHouse projection
  is behind; `kind=asset_event` means webhook fan-out is behind.
* `octo_nats_outbox_backlog{kind,status}` — a cluster-wide count, so aggregate
  with `max by (kind, status)`, not `sum()`. `status="stale"` or `"dead"` above
  zero identifies both the delayed downstream and whether the reconciler can
  still recover it without an operator.
* `octo_nats_outbox_total{kind,outcome}` — `recorded`, `republished`, `dead`,
  `superseded` (a recorded message a later attempt of the same publication
  delivered anyway, so the row was dropped instead of republished),
  `unreplayable`, `discarded`, and `dropped` for the configuration that writes
  nothing down (`OCTO_NATS_OUTBOX_ENABLED=false`), where a refused ingest
  publish rides on the publication's own retries instead and only an outage
  outliving those loses the run's message.
* `octo_asset_events_published_total{kind,outcome}` — `deferred` is an event
  waiting in this table, `skipped` one that is not waiting anywhere and whose
  webhook is never sent (`ShapoclyackAssetEventsSkipped`).
* `octo_nats_stream_config_drift{stream,setting}` — 1 when a stream runs with a
  setting other than the one the API asked for. **Do not build a panel that
  expects this series to exist.** It is written only on the fail-soft branch of
  the stream setup: nats-server 2.10 treats `STREAM.CREATE` as a
  create-or-update, so an installation whose account may write the stream
  applies `OCTO_NATS_INGEST_DEDUPE_SECONDS` and `OCTO_NATS_STREAM_REPLICAS` on
  every connect and never compares anything — the series is absent, which is
  the healthy case. It appears when the API could neither create nor update an
  existing stream (an account without the rights to change it) and the stream
  kept settings of its own. To check what a stream actually runs with, ask the
  server: `nats stream info INGEST`.
  A stale `duplicate_window` matters here specifically: a republish from this
  table relies on JetStream dropping a copy the broker already stored, and
  JetStream's own default window (2 minutes) is shorter than one backoff.
  Recreate or reconcile the stream — `nats stream edit INGEST
  --dupe-window=24h` from a host with the CLI, or fix the account permissions
  that made `update_stream` fail and restart an API replica.

A `dead` row here is about the *message*, not the run: the scan, its artifacts
and its findings were published when the upload was accepted. A run that is
missing altogether is a `dead` `run_publications` row instead — a different
table, a different check (`run_publications`) and the procedure above this one.

The backlog drains by itself once the broker accepts publishes again: entries
are retried with exponential backoff between
`OCTO_NATS_OUTBOX_RETRY_BASE_SECONDS` and `OCTO_NATS_OUTBOX_RETRY_MAX_SECONDS`,
`OCTO_NATS_OUTBOX_BATCH_SIZE` at a time, from every replica (rows are claimed
`FOR UPDATE SKIP LOCKED`, so the replicas divide the work). An entry that
exhausts `OCTO_NATS_OUTBOX_MAX_ATTEMPTS` goes `dead` and waits for a decision —
close to four hours of retries at the defaults, so a `dead` row means an outage
longer than that, not a flaky publish.

Inspecting and replaying the dead end:

The API image has no `psql` (`Dockerfile.api` installs `openssh-client` and the
DejaVu fonts, nothing else), and `OCTO_POSTGRES_URL` is a SQLAlchemy DSN —
`psql` does not recognise the `postgresql+psycopg://` prefix and reads the whole
string as a database name. So the outbox is inspected the way the rest of this
runbook reaches the database: `python -c` in the API container.

```bash
# What is owed, oldest first. Payloads are megabytes of base64 — never SELECT *.
kubectl -n network-scan exec deploy/shapoclyack-api -- python -c "
from sqlalchemy import func, select
from api.db import models
from api.db.engine import get_session
from api.services import nats_outbox
from api.settings import load_settings
settings = load_settings()
print(nats_outbox.backlog(settings))
with get_session(settings.postgres_url) as session:
    for row in session.execute(
        select(
            models.NatsOutboxEntry.kind,
            models.NatsOutboxEntry.status,
            func.count(),
            func.min(models.NatsOutboxEntry.created_at),
        ).group_by(
            models.NatsOutboxEntry.kind,
            models.NatsOutboxEntry.status,
        )
    ):
        print(row)
"

# Put the dead entries back on the due queue (all tenants, or one).
kubectl -n network-scan exec deploy/shapoclyack-api -- python -c "
from api.services import nats_outbox
from api.settings import load_settings
settings = load_settings()
print(nats_outbox.requeue_dead(settings), 'requeued')
print(nats_outbox.reconcile_once(settings))
"

# Give up on the ones that are not coming back, after re-scanning those runs.
# Only 'dead' rows can be discarded; a pending row is still the reconciler's.
kubectl -n network-scan exec deploy/shapoclyack-api -- python -c "
from api.services import nats_outbox
from api.settings import load_settings
print(nats_outbox.discard_dead(load_settings()), 'discarded')
"
```

Bounds worth knowing before an incident:

* A run archive larger than 4 MB was never published inline in the first place
  (`results_ingest.build_gateway_payload`), so its stored body says
  `archive_inline: false` and replaying it gives ClickHouse nothing to
  transform. That limitation predates the outbox and is unchanged by it: for
  those runs the artifacts are the record, and the analytics gap needs a
  re-scan or a manual load. Such an entry is recorded `dead` immediately rather
  than queued, and `requeue_dead` skips it with a log line. Requeueing one is
  how the health signal gets to lie in the cheerful direction: the broker
  accepts a body-less message, the republish counts as a success, the row is
  deleted and the backlog reads zero over a ClickHouse that received nothing.
* `dead` is the only status that needs a human, and it has exactly two exits:
  `requeue_dead` for entries that failed because the outage outlasted the
  retries, and `discard_dead` for entries an operator has decided against.
  Until one of them is used, `nats_outbox` stays `error` and
  `octo_nats_outbox_backlog{kind,status="dead"}` stays non-zero — the degraded
  signal does not expire on its own, by design.
* Ingest messages and asset-event envelopes are recorded. Job offers are
  not (the job row is in Postgres and a sensor claims over HTTP), and audit
  events are not — their database row is already durable.
* A reconcile batch has two lanes: due `kind=ingest` rows take up to
  `floor(batch/2)` slots, due asset events the rest (`ceil(batch/2)`), each
  lane oldest first, and a lane with nothing due gives its slots to the other.
  Whichever kind is older, both drain in every mixed batch: an asset-event
  burst cannot put the next run's ClickHouse publish behind the whole burst,
  and an ingest backlog cannot hold webhook fan-out (`asset.vulnerability.new`
  included) behind itself. `OCTO_NATS_OUTBOX_BATCH_SIZE=1` cannot be split and
  is plain FIFO across kinds — no priority for ingest, and no starvation of
  either; use at least `2` if ingest should not queue behind asset events.
* The table grows with the outage. Ingest entries hold a run archive; asset
  events hold smaller envelopes. Size Postgres accordingly, or accept the dead
  end: `OCTO_NATS_OUTBOX_ENABLED=false` makes refused publishes a logged loss.

### Per-tenant job stream

Job offers are published on `jobs.scan.{tenant}` (stream `JOBS`, unchanged
subject filter `jobs.>`), and each tenant has its own durable pull consumer
`octo-agents-{tenant}` filtered to that subject. A sensor learns its tenant
from the API — the `tenant_id` in the `POST /api/auth/agent/token` response,
or the registration response for a sensor still on the legacy shared
`OCTO_AGENT_TOKEN` (tenant `default`) — and binds only that consumer.

A tenant id that is not a valid NATS subject token (anything outside
`[A-Za-z0-9_-]`, notably a `.`) is hashed into `h_<sha256[:32]>`, the same
encoding `ingest.results.{tenant}` and `events.asset.{tenant}.{kind}` use. Both
the API and the sensor compute it, so `nats consumer ls JOBS` on an install with
older tenant ids shows `octo-agents-h_…` names; map one back with
`python -c "import hashlib;print(hashlib.sha256(b'<tenant id>').hexdigest()[:32])"`.

Operational consequences:

- **Upgrading.** The API no longer creates the shared `octo-agents` consumer,
  but does not delete one that exists — a sensor on an older build keeps using
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
  offer for that tenant, and by the sensor when it binds — whichever happens
  first. Neither is a startup step, so `nats consumer ls JOBS` on a fresh
  install lists nothing until the first sensor job.

- **NATS unavailable.** Unchanged: the offer is not published, the job stays
  queued, and any sensor picks it up over HTTP claim
  (`POST /api/agent/jobs/claim`), which enforces the tenant server-side.

- **Credentials are still shared.** One `agent` NATS user serves every tenant.
  The permission list bounds it to `octo-agents-*` consumers on `JOBS`, which
  is what a sensor needs, but it does not bind a NATS credential to one tenant.
  Per-tenant NATS users are a separate change.

### NATS TLS

The client port runs in the clear in `base/` because the kind stand has no CA
and a `tls {}` block without a key file is a startup error. Apply
`examples/nats-tls-configmap-patch.yaml` anywhere the port is reachable from
outside the cluster: sensors send their NATS password in the connection
URL, and every job offer — ranges, domains, the approved scope — crosses that
link. That file carries the cert-manager `Certificate` to copy and the
StatefulSet mount.

Clients (API and sensor) read `OCTO_NATS_TLS_CA`, `OCTO_NATS_TLS_CERT`,
`OCTO_NATS_TLS_KEY` and `OCTO_NATS_TLS_HOSTNAME`; see
[configuration.md](configuration.md). A `tls://` URL with none of them set
verifies against the system trust store, which is all a publicly issued
certificate needs. `nats-server` reads the certificate files once at boot, so a
cert-manager renewal takes effect on the next
`kubectl -n network-scan rollout restart sts/shapoclyack-nats` unless a
reloader sidecar is in place.

### Pod disruption and API availability

`k8s/shapoclyack/base/api-pdb.yaml` sets `maxUnavailable: 1`. It used to set
`minAvailable: 1`, which at base's `replicas: 1` blocked every voluntary
eviction outright — `kubectl drain` on the node running the API hung until
someone deleted the PDB by hand. `maxUnavailable: 1` keeps N-1 replicas
available at any N and serialises the drain, and it is what
[`overlays/prod-ha`](high-availability.md) inherits unpatched: at its ceiling of
six replicas, `minAvailable: 1` would have permitted five simultaneous
evictions. A single-replica install still has a moment of downtime during a
drain; two or more replicas is the fix, not a different budget. The scheduler is
separately protected by its PostgreSQL advisory-lock leadership mechanism.

## Retro CVE matching

What it is: [retro-cve-matching.md](retro-cve-matching.md). What an operator does:

**After the upgrade that introduces it** (migration `0064`), once:

```bash
# In an API pod (same image, same environment):
python3 scripts/backfill-asset-services.py
```

It reads the succeeded runs still inside `OCTO_RUN_RETENTION_DAYS` from the
artifact store, oldest first, and records their listeners; `missing` counts runs
already pruned. Safe to re-run, safe beside a live API, exit `1` only if some run
could not be read (the log names it). The worker picks the rows up on its next
tick.

**To make it useful** — the committed dataset is a 23-CVE seed — take the
opt-in and run the full harvest once, then let the daily CronJob merge
increments:

```bash
kubectl apply -k k8s/shapoclyack/overlays/enrichment-nvd-cpe   # or add the component

# The full harvest, once, from a pod that mounts the enrichment volume
# read-write — the enrichment-refresh CronJob's pod template is one (the API
# pods mount it read-only):
OCTO_NVD_CPE_FETCH_ENABLED=true python3 scripts/fetch-nvd-cpe.py --full \
  -o /app/scanner/data/nvd-cpe/nvd-cpe-ranges.json
```

Outside Kubernetes run the same command against whatever `OCTO_NVD_CPE_DATABASE`
points at.

With the `shapoclyack-nvd` Secret the full harvest takes minutes; without it,
hours (NVD's anonymous limit). Take the vendor advisory opt-in as well
(`base/enrichment-advisories`): without real Debian/Ubuntu feeds most hits on
Debian/Ubuntu banners stay `possible` and never become findings.

**Expect a wave.** The first tick after a real dataset lands re-matches every
listener and can create many findings at once. Webhook consumers get at most
`OCTO_RETRO_MATCH_MAX_EVENTS` individual `asset.vulnerability.new` deliveries
per tenant for that dataset version, then one aggregate
(`data.aggregate: true`) per tick for the rest; the findings themselves are all
in `GET /api/vulnerabilities?source=retro_match`. A matcher killed mid-wave
(rolling update) loses no announcement: unannounced findings are published by
the next tick, whichever replica leads it.

**Watching it.** `GET /api/retro-match/status`: `dataset_version` (which file
is being matched), `services_pending` (should drain to 0 within a few ticks of a
refresh), `last_stats.errors` (listeners held off after an exception — each is
retried with a backoff up to 6 h), `possible_matches` (hits waiting on a vendor
answer). `nvd_cpe` on `GET /api/system` shows the file's age and whether it
clears the floor.

**Forcing a re-check** — after replacing the dataset by hand, or to re-derive
verdicts: `POST /api/retro-match/refresh` (operator). A changed dataset or
advisory feed does this by itself; the button is for the cases the marker
cannot see.

**Rollback.** `0064` is expand-only. Rolling the image back leaves the tables
unused and `retro_match` findings in the tracker as ordinary findings with an
unfamiliar `source`; a downgrade of the schema drops the fingerprints (they are
re-derivable by the backfill from runs still on disk) and the two
`vulnerabilities` columns, not the findings.

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

**No egress, or only to internal mirrors?** Every feed has a `*_URL` mirror
override, and an offline bundle (`make enrichment-bundle` on a connected host,
loaded by the `overlays/airgap` CronJob) carries the datasets across; installed
datasets report `origin: bundle`. The procedure — images, pull secret, mirrors,
bundle, what stays unavailable — is [air-gap.md](air-gap.md).

## Upgrade and rollback

> With `base` and `overlays/prod` there is a single API replica, so the probes
> and grace periods below limit the gap in a rollout without closing it. The
> multi-replica profile that turns them into a genuinely non-disruptive rollout
> is [high-availability.md](high-availability.md#rolling-upgrade-without-5xx).

### Probes, and what a rollout costs

Three probes on the API pod, with three different questions (#331):

| Probe | Path | Asks |
|---|---|---|
| `startupProbe` | `/livez` | Has the process finished booting? `create_app()` loads the tenant store and bootstraps accounts, so a cold start against a busy PostgreSQL takes a while; 5s × 30 attempts before the pod is failed, and neither probe below runs until this one passes |
| `livenessProbe` | `/livez` | Is this process wedged? Dependency-free on purpose — a database outage must not restart every replica and put a crash loop on top of the outage |
| `readinessProbe` | `/readyz` | Can this replica serve? PostgreSQL `SELECT 1`, plus a NATS round trip and a ClickHouse query where those URLs are set. Only PostgreSQL and NATS fail the probe — ClickHouse is one pod with no PDB and would otherwise unready every replica at once; it degrades the body instead. Failing it removes the pod from the Service instead of killing it |

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

   Verify the signature of the `tag@sha256:digest` you are about to deploy
   (`cosign verify --key cosign.pub -a release=<tag> …`, see
   [supply-chain.md](supply-chain.md#verify-an-image)); an admission policy
   does this for you if you run one.

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
| `0045_vuln_ticket_sync_cursor` | The ticket-sync poller's cursor and its last error per finding. The old code has no poller, so nothing happens until a re-upgrade — and then every linked ticket is due at once and the first tick re-reads all of them. The load lands on somebody else's Jira rather than on this installation, which is what makes it worth knowing before running this on an estate with thousands of links (raise the subscriptions' `sync_interval_seconds` first, or keep `OCTO_TICKET_SYNC_ENABLED=false` for the first minutes). Nothing about the findings is lost: the reconciliation is idempotent and the `ticket_synced` events stay. |
| `0036_oidc_pending_states` | Every **in-flight** SSO login: the nonce and the PKCE verifier of an authorization request the browser has not come back from yet. Nothing is lost that matters — a row lives for at most `OCTO_OIDC_STATE_TTL_SECONDS` (10 minutes) and a login whose record is gone is refused and retried. The same is true of the *upgrade*: during the rolling deploy in either direction the old and the new code disagree about where a pending login is kept, so logins begun before the switch and finished after it are refused. No account, membership or session is touched. |

### Legacy JSON state import

`api/services/{jobs,agents}.py` still import pre-P1.2 `state/api_{jobs,agents}.json`
once at startup, renaming them `*.imported` afterwards. That code is a one-time
migration aid for installations upgrading from before the Postgres control
plane. It is scheduled for removal in the **second** release after `0.41`: one
release is not enough, since an installation may skip a version, and keeping it
indefinitely means every future start pays for a path nothing has used in years.
An installation older than that must upgrade through `0.41` first, or accept
that the queued jobs and registered sensors in those files are lost — neither is
state that a scan cannot recreate.

### NetworkPolicy decision

`k8s/shapoclyack/examples/networkpolicy-agent.example.yaml` (the sensor's egress,
in `network-scan-executor`) and `networkpolicy-api-ingress.example.yaml` (who
may reach the API, in `network-scan`) deliberately remain examples instead of
base resources. NetworkPolicy enforcement and ingress controller labels vary by
CNI/environment, and the platform can legitimately need environment-specific
egress to DNS, S3-compatible backup storage, NATS, ClickHouse, webhooks,
scanners, vulnerability sources, SMTP, or ticketing systems. Applying a guessed
restrictive policy in base can silently break backup and integrations. The
sensor example shows how that goes wrong: its target rule holds documentation
ranges. Applied unchanged, it lets the sensor reach the API and nothing it is
meant to scan, and the scans come back empty instead of failing.

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
| ClickHouse | 8123 / 9000 | API; 9000 also the ClickHouse backup CronJob (#333) |
| NATS | 4222 | API; sensors outside the cluster (the in-cluster scanner-executor claims over HTTP, [#338](https://github.com/onixus/Shapoclyack/issues/338)) |

That is a closed list, so `k8s/shapoclyack/base/networkpolicy-datastores.yaml`
is a base resource: one `Ingress`-only policy per datastore, default-deny by
omission, allowing exactly the pod labels above. Nothing about it is
environment-specific, and getting it wrong fails loudly (a pod cannot reach its
database) rather than silently, which is the opposite of the egress case.

Workloads that only some installations run, such as the two audit examples
(retention CronJob → Postgres, syslog forwarder → NATS or Postgres), are not in
that list. Each one ships an extra ingress policy for the datastore it uses, in
its own file. NetworkPolicies add up, so applying the example admits it and
deleting the example takes the access away again.

Two things it does not cover, both by design:

- **Sensors outside the cluster.** A pod selector cannot name them. An
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
nothing else; an `agent`-labelled pod (a sensor) reaches NATS and nothing else; the API
pod reaches all three. (Since #338 no in-cluster pod but the API is admitted to NATS;
the script now expects the `agent` label to be refused and probes from the
scanner-executor's namespace too — see [Kubernetes hardening](k8s-hardening.md).) The datastores' kubelet probes kept passing, as the
manifest's note on host traffic predicted. Needs docker, kind and the
locally built aio image (`scripts/dev-up.sh` builds it); `KEEP=1` leaves the
cluster up for inspection.

### Tenant row-level security (#311)

Migration `0067_tenant_rls` creates the NOLOGIN role `shapoclyack_tenant` and a
row-level-security policy on every tenant table; the API switches to that role
for each transaction of a tenant-scoped request (`OCTO_TENANT_RLS=enforce`, the
default). On the stock manifests (`octo`, a superuser) and on managed services
whose master user has `CREATEROLE` there is nothing to do. A migration role
without `CREATEROLE`, an API role separate from the migration role, the
`audit_events` ownership split above, backup roles, the startup check that
refuses a database which cannot enforce it, and how to read a denied row are in
[tenant-isolation.md](tenant-isolation.md#operations). `OCTO_TENANT_RLS=off` and
a restart is the kill switch; it needs no migration rollback.

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
| `shapoclyack-clickhouse-backup` | `password` | ClickHouse StatefulSet (user `shapoclyack_backup`), ClickHouse backup CronJob ([#333](https://github.com/onixus/Shapoclyack/issues/333)) |
| `shapoclyack-nats` | `api_password`, `agent_password` | NATS StatefulSet, API, sensors |

`base/kustomization.yaml` generates dev placeholders for all of these, the same
way it always has for Postgres — a fresh `kubectl apply -k` comes up without
any manual step. The placeholders are published in this repository. Override
them with `examples/api-secrets.example.yaml` (or
`examples/externalsecret.example.yaml` with ExternalSecrets) before any install
that holds real scan data.

### Rotating the agent JWT signing key

Agent JWTs — the tokens both sensors and endpoint Agents (Lariska) present to
the API — are signed with `OCTO_AGENT_JWT_SECRET`, or with a key derived from
`OCTO_JWT_SECRET` when it is unset ([#312](https://github.com/onixus/Shapoclyack/issues/312)).
Rotate it when a sensor or endpoint host is suspected of being compromised, and
rotate it rather than `OCTO_JWT_SECRET` when the console's own sessions should
survive.

1. Set (or change) `OCTO_AGENT_JWT_SECRET` in the API Secret — the same value
   on every replica, or sensors will authenticate against some pods and not
   others — and roll the API.
2. Every agent JWT in the fleet stops verifying at that moment. Nothing else
   has to be done: a sensor that meets a `401` re-exchanges its provisioning
   key on its next pass, and one that somehow does not re-exchanges when its
   token expires, within `OCTO_AGENT_JWT_EXPIRE_MINUTES` (default 2 hours).
   Jobs already claimed keep running; their result upload re-authenticates the
   same way.
3. Confirm with `GET /api/agents` that `last_seen_at` is moving again for every
   sensor. One that is not has lost its **provisioning key**, not its token —
   mint a new one and re-run the installer on that host.

Revoking a provisioning key is the narrower tool and does not need this: it
stops new exchanges for one sensor, while an already-issued token stays valid
until it expires.

NATS has two users rather than one because they are not equally trusted. `api`
owns the whole subject tree. `agent` may open an `octo-agents-*` pull consumer
on the `JOBS` stream, fetch `jobs.scan.{tenant}`, and ack — and nothing else:
it cannot subscribe to `ingest.>` or `events.>`, cannot publish `jobs.scan.*`,
and cannot open a consumer on the `INGEST` stream. A compromised sensor
therefore cannot read other tenants' results or inject work. It remains one
credential for the whole fleet — see
[Per-tenant job stream](#per-tenant-job-stream). Both users share the global
account: the streams are common to both, and JetStream cannot share a stream
across accounts without export/import plumbing on every subject.

Passwords reach the API and the sensors inside the connection URL
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

3. **Update every sensor** that uses NATS job pull. Their
   `OCTO_NATS_URL` needs `agent:<agent_password>@` — a sensor left on the old
   URL logs an authorization violation and falls back to nothing; it does not
   silently switch to the HTTP claim path. Sensors that already use HTTP claim
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
| Sensor / endpoint Agent → API | Yes; mutual when you configure it | HTTPS to `OCTO_PUBLIC_BASE_URL`, outbound-only. A client certificate bound to the sensor's token with `OCTO_AGENT_MTLS_MODE` — see [Sensor client certificates](#sensor-client-certificates) |
| API → Postgres | Only if you ask for it | `?sslmode=verify-full` in `OCTO_POSTGRES_URL`; a `prod` start without any `sslmode=` logs a warning |
| API → ClickHouse | Only if you ask for it | `https://` in `OCTO_CLICKHOUSE_URL`. The scheme decides, not the port |
| API → SMTP relay | Yes, verified | `OCTO_REPORT_SMTP_STARTTLS` (default on) with certificate verification; `OCTO_REPORT_SMTP_VERIFY_TLS=false` downgrades it deliberately |
| API / sensors ↔ NATS | Yes, when you configure it | `tls://` in `OCTO_NATS_URL` plus `OCTO_NATS_TLS_*`; the broker side is `examples/nats-tls-configmap-patch.yaml`. Plain `nats://` is still accepted and still plaintext — do not expose `:4222` across an untrusted segment without `tls://` |

Mutual TLS bound to a sensor's identity exists on one link: sensor and Agent →
API, opt-in ([Sensor client certificates](#sensor-client-certificates)), and
Lariska Agents cannot take part in it yet. NATS can also require a client
certificate (`OCTO_NATS_TLS_CERT`, with `verify_and_map` on the broker), but
that certificate authenticates a NATS user, not a particular sensor. Every other
link in the table is TLS one-way at most.

**Datastore links stay warned about, not enforced** — the decision #309 asked
for. A `prod` start keeps *warning* when `OCTO_POSTGRES_URL` has no `sslmode=`
and does not refuse; ClickHouse and NATS are not checked at all beyond their
scheme. Three reasons, all of which still hold:

1. The shipped layouts run Postgres, ClickHouse and NATS in the cluster,
   reached only from the API's pods (`base/networkpolicy-datastores.yaml`), and
   ship no certificates for them. A refusal would stop every existing
   installation at its next upgrade, with nothing in the repository to fix it
   with.
2. A link without TLS *at the client* is often encrypted anyway — a service
   mesh's sidecars (Istio, Linkerd) do mTLS between pods and hand the
   application plaintext, a Unix socket never leaves the host, a cloud private
   link is the provider's. The API sees the same URL in all of them and cannot
   tell them from the unprotected case.
3. Enforcement is already available where it is meaningful, and is fail-closed
   once chosen: `sslmode=verify-full` makes libpq refuse a server without a
   valid certificate, `https://` for ClickHouse and `tls://` for NATS do the
   same for theirs. The operator who writes the URL is the one who knows which
   of the cases above applies.

What would change it: in-cluster datastore TLS shipped in the `prod-ha`
overlay (cert-manager certificates for the three StatefulSets). Once that
exists, `prod` can refuse a plaintext URL that points at those Services.

Which ports have to be open for any of it, how egress goes through a corporate
proxy (`OCTO_HTTPS_PROXY`, `OCTO_NO_PROXY`), and where an internal root goes
(`OCTO_CA_BUNDLE`) are in
[network-requirements.md](network-requirements.md) — including why NATS is the
one link a proxy cannot carry, and what a sensor does instead
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
   in-cluster sensor Deployment (`overlays/agents`).
4. Re-key sensors outside the cluster.

There is no overlap window: between steps 2 and 3 the old clients are rejected.
Schedule it like a short maintenance window rather than expecting a seamless
rotation.

## Secrets at rest

The credentials this installation holds *for other systems* — a webhook's HMAC
signing key, the header values that carry a Jira / ServiceNow / DefectDojo API
token, and since [#351](https://github.com/onixus/Shapoclyack/issues/351) the
per-tenant Slack / Teams / Mattermost webhook URLs and DefectDojo tokens in
`notification_channels` — are stored in Postgres. Until
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
| Chat webhook URL, DefectDojo token of a notification channel (`notification_channels.secret`) | Postgres | Encrypted (#351), under its own GCM context `notification_channels.secret`. A chat incoming-webhook URL is a credential — anyone holding it can post into the channel — which is why it is here and not in a plaintext `url` column |
| A notification channel's recipients and product names (`notification_channels.config`) | Postgres | Plaintext, deliberately: an address list is configuration, and encrypting it would make an installation with no credentials demand a key |
| TOTP shared secret of an enrolled account (`users.mfa_secret`) | Postgres | Encrypted (#315), under its own GCM context `users.mfa_secret`, and covered by the same `python -m api.db.reencrypt_secrets` passes |
| Recovery codes (`users.mfa_recovery_codes`) | Postgres | bcrypt hashes — a recovery code is a password |
| Console passwords, service tokens, provisioning keys (sensor and endpoint Agent) | Postgres | bcrypt / SHA-256 hashes — never reversible, so nothing to encrypt |
| SSH host keys pinned for sensor deployment | Postgres | Public keys; not secret |
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
   SELECT key_id, count(*) FROM notification_channels
    WHERE secret IS NOT NULL GROUP BY key_id;
   ```

   One row each, with the current `kek_id`, means the rotation is complete. A
   `NULL` `key_id` means those rows are still plaintext — run the pass without
   `--rotate` first. Both queries matter: one pass covers
   `webhook_subscriptions`, `users.mfa_secret` and `notification_channels`, so
   an old key is only retired when every table agrees.

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
`alembic downgrade 0039_agent_status_key_expiry`, which reverts
`0040_encrypted_secrets` — the revision that added the `key_id` column. That
only works on an installation whose head is still `0040`: Alembic undoes every
later revision on the way down, so on a current schema this path is closed and
the expand/contract rule above is the answer.

### Vault Transit and cloud KMS

`OCTO_MASTER_KEY_PROVIDER` selects where the KEK lives. Only `local` (the
default, `OCTO_MASTER_KEY`) is implemented; `vault-transit`, `aws-kms` and
`gcp-kms` are **named but not built** — setting one refuses at startup with a
message saying so, rather than silently falling back to a local key. What
exists is the interface (`KeyProvider` in `api/services/crypto/envelope.py`):
two methods, wrap and unwrap, which a Transit or KMS client fills in without
any call site changing. Do not plan a deployment around them until an issue
says they ship.
