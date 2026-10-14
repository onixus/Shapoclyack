# Nuclei directed planning (issue #450)

The default remains `nuclei.planner_mode: legacy`. Opt in with:

```yaml
nuclei:
  planner_mode: directed
  planner_min_confidence: 90
  planner_max_templates: 20000
  planner_max_processes: 64
  max_targets: 1000
```

Rollback is `planner_mode: legacy`; existing explicit `template_ids` verification
runs always retain their original contract. Tenant/profile severity, tags and
excluded tags remain effective. Intrusive/fuzz/dos are excluded by default.

Directed planning intersects observations with the supplied open TCP endpoints.
It does not add a host or port. A finite numeric confidence between the configured
threshold and 100 plus an explicit HTTP/HTTPS service selects one scheme.
Conflicting or absent confidence retains HTTP and HTTPS, including custom ports.
The current canonical service artifact does not carry confidence; ordinary runs
therefore retain that fallback until an evidence-producing upstream contract is
available. A bare product/version or a Pulse CVE hypothesis never removes a CVE
check. Explicit technology mappings annotate nginx/apache/wordpress/tomcat/jenkins;
this first policy keeps **all eligible HTTP templates** as the safe fallback, so
it makes no claim of validated technology-based template reduction.

The directed catalog admits root-relative `{{BaseURL}}/` or `{{RootURL}}/` HTTP
paths only. Raw requests, literal external URLs, Host overrides, mixed engines
and flow templates are scope-unproven or unsupported and explicitly excluded in
the plan. This conservative restriction can exclude otherwise useful CVE checks;
compare `excluded_templates` before enabling it. Redirect following is disabled.
Custom templates follow the same checks and retain origin/path/content hashes.
The existing independently curated network pass is unchanged.

Forward input names from `dns_resolution.json` produce separate virtual-host
checks, with an IP URL, a per-process Host authority and HTTPS SNI. PTR,
certificate SANs and service banners cannot add virtual hosts. The explicit IP
dial avoids a second DNS lookup moving a virtual host beyond the authorized
address. IPv6 URL authorities stay bracketed. Each virtual host has its own
process so a global Host/SNI override cannot leak to another endpoint.

`nuclei_plan.json` (also `coverage.plan`) stores targets, reasons, catalog hashes,
versions, shared template sets, exclusion reasons, planned check count, processes
attempted, return code, templates actually loaded and completion status. It does
not store a targets × templates product. `executed_checks` stays null: Nuclei
reports template loading, not evidence of every HTTP request having executed.
A zero exit plus expected loaded count and no dropped targets can count completed
target invocations. Submission alone, missing engine/catalog, timeout, disabled
stage and truncation cannot count as completed coverage. Verification by explicit
IDs remains governed by the existing verification coverage consumer.

Catalog parsing is cached for two content identities. Bounds are 1 MiB per file,
100 MiB total and `planner_max_templates`; missing directories, ambiguous IDs and
malformed metadata fail closed. Execution uses a private snapshot of selected
bytes, verified against planned hashes, rather than the mutable source directory.
Targets and processes are capped separately. One overall deadline covers every
web process, per-request retries retain the configured bound, and no timed-out
process is automatically retried. Artifacts keep at most 1 MiB per raw/error part
and 8 MiB per combined raw/error stream. Truncation remains incomplete. Partial
JSONL matches survive timeout, including in legacy mode.

## Local fixture comparison

`tests/fixtures/nuclei_plan/benchmark.json` records an actual isolated loopback
execution with Nuclei v3.11.1 from local image `shapo-go-tools-check:latest`
(image ID 9c84d15ed039), using Python runtime `shapo-issue448-benchmark:local`
with `--network none`. The archived JSONL is an actual engine record. The template
and CVE-2099-9999 are explicitly synthetic, not proof of a real vulnerability.

| Metric | Full legacy | Directed |
|---|---:|---:|
| Connections accepted by HTTP fixture | 2 | 1 |
| HTTP requests | 1 | 1 |
| Processes / selected templates | 1 / 1 | 1 / 1 |
| Expected synthetic problem matches | 1 | 1 |
| Wall time (seconds) | 0.0921 | 0.0905 |
| Child CPU (seconds) | 0.0951 | 0.1093 |
| Peak child RSS (KiB) | 103580 | 99884 |

This single small fixture demonstrates scheme selection removing one failed TLS
connection while preserving the expected match; it does **not** establish a
statistically meaningful performance improvement or full pinned-catalog CVE
acceptance. Directed mode starts one process per authority/endpoint and can cost
more startup CPU than batching. The script `scripts/benchmark-nuclei-plan.py`
expects `/fixture-bin/nuclei`, `/evidence` and a Python runtime with repository
dependencies; run it in a network-isolated container with this checkout mounted
read-only as `/work` and `PYTHONPATH=/work`.

Default enablement requires broader expected-real-finding acceptance, actual
HTTP/HTTPS IPv6 and Host/SNI capture, representative full-catalog benchmarks,
confidence provenance from Pulse, and measured process-startup overhead. These
remain unverified by this synthetic HTTP fixture. The mode stays opt-in.
