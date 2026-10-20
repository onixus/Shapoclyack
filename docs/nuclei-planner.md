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
The current canonical service artifact does not carry confidence. Production
planning instead joins canonical Pulse endpoints to bounded `pulse/raw.json`
observations: an actively probed HTTP status response establishes HTTP; an
actively probed HTTPS service plus `pulse-tls` negotiated TLS and an HTTP Server
response establishes HTTPS. The plan retains raw SHA-256 and JSON pointer receipts.
Port labels, product/version, OS confidence and JARM alone cannot establish a
scheme. Missing, stale/mismatched or unsupported raw evidence retains both. A bare product/version or a Pulse CVE hypothesis never removes a CVE
check. Explicit technology mappings annotate nginx/apache/wordpress/tomcat/jenkins;
this first policy keeps **all eligible HTTP templates** as the safe fallback, so
it makes no claim of validated technology-based template reduction.

The directed catalog admits root-relative `{{BaseURL}}/` or `{{RootURL}}/` HTTP
paths only. Raw requests, literal external URLs, constants/variables/payloads/internal extractors, self-contained templates, Host overrides, mixed engines
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
(image ID 9c84d15ed039), using hash-pinned Python scanner runtime `shapo-issue450-benchmark:local`
with `--network none`. The archived JSONL is an actual engine record. The additional
`pulse-production-protocol.json` fixture is extracted from issue #448's immutable
`raw-outputs.tar.gz`, member `heterogeneous-0-after/pulse/raw.json`; a regression
runs it through the actual canonical producer and planner. The template
and CVE-2099-9999 are explicitly synthetic, not proof of a real vulnerability.

| Metric | Full legacy | Directed |
|---|---:|---:|
| Connections accepted by HTTP fixture | 2 | 1 |
| HTTP requests | 1 | 1 |
| Processes / selected templates | 1 / 1 | 1 / 1 |
| Expected synthetic problem matches | 1 | 1 |
| Wall time (seconds) | 0.0710 | 0.0735 |
| Child CPU (seconds) | 0.0884 | 0.1052 |
| Peak child RSS (KiB) | 105364 | 104364 |

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
broader protocol-provenance variants from Pulse, and measured process-startup overhead. These
remain unverified by this synthetic HTTP fixture. The mode stays opt-in.

The per-process raw JSONL retains exact engine bytes. The combined
`nuclei_raw.jsonl` adds a bounded adapter-owned `shapoclyack_input` envelope
(`octo.nuclei_input.v1`) containing dial IP/port and actual Host authority/SNI.
It is invocation metadata rather than a field emitted by Nuclei, and prevents
multiple virtual hosts on the same IP/path from losing their distinct subjects.

The final receipt records the executed binary SHA-256, architecture, scanner
source content digest, instrumentation digest, and observed/active interfaces.
The active interface preflight confirmed only loopback. The controlled
`scope_override_fixture` added a template overriding BaseURL to a second
loopback listener; it was explicitly excluded and that listener accepted zero
connections/requests. Runtime comparison uses the same safe template as before.
`benchmark-historical.json` retains the earlier exploratory measurement without
exact source/binary provenance; use `benchmark.json` for the final source receipt.

## Completion acceptance: pinned upstream catalog

The plan now gives every eligible template an explicit set membership:
`safe_http_base` (generic checks, every eligible CVE and custom template), five
`technology:<name>` sets derived from the documented tag mapping, and
`safe_http_technology_fallback` for all remaining technology checks. Each target
names the base, applicable technology sets and fallback. Their union is the
executed `safe_http_fallback` set. The fallback is bounded by the same catalog
count/byte policy rather than truncated independently: exceeding the bound
fails closed. Unknown and incorrect fingerprints therefore retain the same
eligible checks. Technology mapping is explainable classification; this policy
explicitly sets `template_reduction_claimed: false`. Only reliable protocol
selection reduces connections. Future template pruning requires independent
coverage acceptance and must change this policy explicitly.

`planner_per_host_max_processes` (default 16) and
`planner_per_host_timeout_seconds` (default 1800) bound all ports and virtual
hosts of one dial IP. Host time is cumulative actual invocation duration;
another host's time does not consume it. Each invocation's timeout is the
smaller remaining host/stage budget. Host exhaustion records target indices
and reasons and permits later hosts to use remaining global budget. Global
process limits count processes actually attempted, including failed processes;
skipping a host does not consume a process slot. Receipts retain the timeout,
actual duration and remaining host budget. Any skipped target keeps the plan
incomplete. Catalog parsing now treats upstream `profiles/*.yml` without
`id`/`info` as metadata; actual templates in that directory retain normal
validation. This fixes whole-catalog parsing of the repository-pinned v9.9.4.

`scripts/benchmark-nuclei-catalog.py` executes unmodified signed upstream
checks from v9.9.4 (`f4251b06c100067f230c4f54a1679de59802c7a4`) with actual
Nuclei v3.11.1 in a `--network none` container. Its reference HTTP and IPv6
HTTPS response fixtures implement four upstream matcher contracts:
`apache-server-status`, `nginx-status`, `public-tomcat-manager`, and
`CVE-2000-0114`. Every expected ID must be observed on **each** endpoint.
These are controlled response fixtures, not deployed vulnerable appliances;
in particular the FrontPage detector match does not prove exploitation of a
FrontPage vulnerability. Known, unknown and intentionally wrong technology
cases retain all expected matches. Unknown protocol runs retain both schemes.
Separate actual HTTPS capture verifies distinct Host authorities and TLS SNI
for `a.fixture.example` and `b.fixture.example` on IPv6.

The same script with `FULL_CATALOG=1` compares the full **policy-eligible,
scope-proven HTTP subset** of the pinned catalog on one HTTP fixture. It does
not equate unsupported raw/other-engine templates with checked templates.
Reports retain every selected template hash, engine/source/script hashes,
connections, requests, wall/CPU time, child peak RSS and endpoint-specific
expected IDs. These are single local samples, not a performance SLA. Child RSS
includes inherited Python catalog memory after fork. The complete fallback
intentionally does not reduce template counts, and process startup can cost
more CPU/wall time on small targets. Legacy broad-sweep `checked_count` remains
zero because it lacks explicit per-template coverage receipts.

Final capture evidence is under
`tests/fixtures/nuclei_plan/catalog_v9_9_4/` (separate reports and raw archives,
with SHA256SUMS; private TLS keys are excluded):

| Final single sample | Full eligible legacy | Directed |
|---|---:|---:|
| Full catalog: templates / expected detector IDs | 2887 / 4 | 2887 / 4 |
| Full catalog: accepted connections / HTTP requests | 6637 / 3318 | 3318 / 3318 |
| Full catalog: wall / child CPU seconds | 6.274 / 5.104 | 8.228 / 5.149 |
| Full catalog: peak child RSS KiB | 257692 | 237992 |
| Full catalog: processes / coverage ran | 1 / true | 1 / true |
| Representative known HTTP+IPv6 HTTPS: connections / requests | 26 / 12 | 12 / 12 |
| Representative known: processes / expected IDs per endpoint | 1 / 4 | 2 / 4 |
| Representative known: wall / child CPU seconds | 0.116 / 0.139 | 0.219 / 0.254 |

The unknown protocol representative uses four directed invocations and retains
26 connections / 12 requests and all four expected IDs on each endpoint.
The incorrect WordPress fingerprint preserves the Apache/Nginx/Tomcat and CVE
checks: 12 directed connections / 12 requests with all expected IDs per endpoint.
The full directed receipt loaded 2887 templates, returned zero, reported no
dropped targets and completed one target invocation. `executed_checks` remains
null because these receipts do not establish execution of each HTTP request.

Reproduction uses Python 3.12 with PyYAML 6.0.3 and pydantic 2.12.3. Mount the
pinned upstream checkout read-only at `/catalog`, this checkout read-only at
`/work`, the Nuclei binary read-only at `/fixture-bin/nuclei`, and an empty
writable directory at `/evidence`; run from `/work` with `PYTHONPATH=/work`:

```sh
# Runtime must have only loopback active; the script rejects other interfaces.
python scripts/benchmark-nuclei-catalog.py
# Repeat in a separate empty /evidence directory:
FULL_CATALOG=1 python scripts/benchmark-nuclei-catalog.py
```

Use Docker `--network none` for both commands. The captured local runtime image
ID is `sha256:88923371befdc8bf51239069388714cd4d9aff16b3ea575ccb63cdaec8371e56`.
The benchmark proves parity for the declared local matcher contracts, protocol
variants and pinned eligible catalog only. Real vulnerable-application coverage,
other upstream releases, hostile-target behavior and fleet performance remain
default-enable gates; this change does not enable directed mode by default.

A fresh reproducible runtime can be built without any pre-existing local image:

```sh
# From this repository root; download sources only, never scan a remote target.
git clone --depth 1 --branch v9.9.4 https://github.com/projectdiscovery/nuclei-templates.git /tmp/nuclei-450-catalog
# This must print f4251b06c100067f230c4f54a1679de59802c7a4:
git -C /tmp/nuclei-450-catalog rev-parse HEAD
docker build -f scripts/nuclei-catalog-benchmark.Dockerfile -t nuclei-450-benchmark .
mkdir -p /tmp/nuclei-450-representative /tmp/nuclei-450-full
docker run --rm --network none \
  -v "$PWD:/work:ro" -v /tmp/nuclei-450-catalog:/catalog:ro \
  -v /tmp/nuclei-450-representative:/evidence nuclei-450-benchmark
docker run --rm --network none -e FULL_CATALOG=1 \
  -v "$PWD:/work:ro" -v /tmp/nuclei-450-catalog:/catalog:ro \
  -v /tmp/nuclei-450-full:/evidence nuclei-450-benchmark
```

The build pins Nuclei v3.11.1, Python 3.12, PyYAML 6.0.3 and pydantic 2.12.3;
reports record the resulting binary hash rather than assuming builds with other
compilers/platforms are byte-identical. Planner settings, including the new host
budgets, remain scanner-file settings like the existing planner settings; they
are not silently added to the API/agent override allowlist or SDK contracts.
