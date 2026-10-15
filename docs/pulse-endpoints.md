# Exact Naabu -> Pulse endpoints (#448)

Companion to [the backend guide](pulse-backend.md). The discovery backend,
Pulse version, service/OS/CVE schemas and load-control flags do not change.

## Planning contract

`pulse_plan.plan_tcp_probe()` consumes normalized, already-approved TCP
endpoints. The adapter groups hosts by their **entire identical port set**,
then applies `chunk_hosts` inside each group. For every pass:

```
union(chunk.hosts x chunk.ports) == pending approved TCP endpoints
```

No endpoint is scheduled twice in the initial plan. Thus `A:22`, `B:443`,
`C:5432` produces three pairs, not nine. Identical signatures still batch
hosts; the implementation does not create a process for every endpoint.
Input order and duplicate ports do not change the plan. UDP is not converted
to TCP. Exclusions and approved scope remain the upstream policy's job;
this helper neither resolves names nor adds ports. Existing content-based
`chunk_key(hosts, ports, mode)` identities and no-Pulse-checkpoint behavior
are retained. Rate, concurrency, host parallelism, SYN opt-in and timeouts
are passed through unchanged.

## Completion and resume

Completion is now per host, not `bool(payload.open)` for the entire group.
A host is checkpointed only on a successful process exit with every expected
TCP endpoint observed open. An unknown service name does not hide its open
endpoint. A missing host/port, a closed result contradicting Naabu, or a
nonzero exit with partial JSON stays unresolved. Available partial evidence
is still written; an incomplete pass is not proof of remediation.

On resume, a checkpoint is honored only when `pulse/raw.json` contains the
corresponding persisted endpoint evidence **and successful processing receipts**. Completed hosts' service/OS/CVE/TLS
evidence is retained when pending hosts are re-probed. An all-completed pass
does not erase the artifacts. Missing/invalid cache or a legacy checkpoint
that incorrectly marked a partial group done causes safe replay of the
still-approved endpoints. Previously overscanned ports and hosts outside the
current input are excluded from retained data. Literal IPv6 forms are
normalized consistently for planning, checkpoint keys and evidence matching;
ports from equivalent literal spellings are unioned. DNS equivalence is not inferred.

The additive `pulse/raw.json.completion` block has schema
`octo.pulse_completion.v1` and a `hosts` mapping. Each successful host receipt
contains `ports` and integer `returncode: 0`. Receipts are issued only after
successful exit, complete endpoint evidence and canonical parsing. They survive
subsequent partial and all-done passes independently of current-pass `chunks`.
A receipt without its matching endpoint evidence is insufficient. Missing,
malformed, unknown-version or non-success receipts cause replay, never an
implicit success. These are local processing receipts, not cryptographic
signatures or proof that a vulnerability has been verified.

**Compatibility:** older endpoint-only artifacts (including earlier revisions
of PR #491) cannot prove the process outcome. Their checkpointed targets are
replayed once within the same approved input. Old artifacts remain readable;
there is no silent promotion of legacy data to the new completion schema.

`scanner.main --resume` always enters the enabled Pulse adapter even when
`stages.pulse` was true. After validating cache, the adapter invokes
`on_resume_validated`; the CLI uses one locked `CheckpointStore.restart_stage`
save to clear coarse completion and replace stale host marks with verified
ones **before any replay**. Other stages' checkpoints are untouched. Failure
to persist this reconciliation aborts before spawn. Successful all-done resume
reconstructs canonical files without invoking the Pulse binary. A disabled
backend or `--skip-nse` still does not enter the adapter.

Partial results retain the existing pipeline exit policy, but never restore
the Pulse stage-complete flag. A later successful attempt can complete it.

This does not make checkpoint and artifact writes transactional. An
interruption between them may cause bounded-per-invocation rework on resume,
rather than silently losing a completed host. Results remain scoped to the
same run output directory; this is not cross-run evidence caching.

## Diagnostics

`pulse/raw.json.adapter` records the current planning pass:

| Field | Meaning |
| --- | --- |
| `input_unique_tcp_endpoints` | Deduplicated valid TCP input, including completed hosts |
| `pending_unique_tcp_endpoints` | Input after validated completed-host removal |
| `planned_tcp_combinations` | Sum of exact chunk products, before retries |
| `planned_chunks` | Number of initial logical groups |
| `chunk_probe_calls` | Adapter calls to `_probe_chunk`, including explicit retries |
| `adapter_retry_calls` | Additional adapter calls for crash, settle or OS fallback |
| `adapter_retry_tcp_combinations` | Planned pair budget repeated by those calls |
| `command_retries` | Configured lower-level `run_command` retry limit |
| `resumed_hosts` | Hosts retained with persisted endpoint evidence |
| `replayed_checkpoint_hosts` | Still-approved checkpointed hosts requiring replay |

These are **not packet counts or exact subprocess counts**. `run_command`
can retry a timeout internally; that does not increment `chunk_probe_calls`.
An OS capability refusal can occur before any packet is sent. Existing raw
Pulse `stats` describe returned payloads, not all failed/timeout attempts.
Cached stats are not re-added to current-pass counters. Each `chunks[]`
entry records ports, unresolved hosts and logical probe calls alongside its
existing key, hosts, exit code and resolution flag. No high-cardinality
Prometheus address/port labels are introduced.

## Extra probes and failure limits

The invariant bounds the adapter's TCP target list, **not all traffic the
Pulse engine may emit**. Existing `--os` fingerprinting can make additional
raw probes; the existing OS capability fallback disables `--os` for the
remaining pass. Explicit SYN requests are never silently downgraded. Pulse's
existing TLS/JARM work may perform multiple handshakes per selected TLS
endpoint; no new TLS/JARM or active-check flags are enabled here. The pinned
engine's packet/handshake budget is not measured by these planner counters.

The immediate crash retry, optional all-closed settle retry, configured
command retries and three-consecutive-crashed-chunks breaker remain bounded
as before. Every retry uses the same exact chunk endpoints. More unique port
signatures can mean more processes, repeated engine initialization, and a
larger aggregate retry/timeout budget over the whole stage. This change does
not add a global deadline or promise a speedup. Measure these costs with the
pinned engine before making a throughput claim or changing profile limits.

## Validation and reproducible local fixture

```
python -m pytest -q tests/test_pulse_probe.py tests/test_pulse_endpoints.py \
  tests/test_pulse_resume.py tests/test_pulse_main_resume.py
python scripts/benchmark-pulse-endpoints.py --repeats 5 --output /tmp/pulse-endpoints.json
```

The unit/contract suite uses mocked processes and no external scans. The
fixture opens only numeric loopback listeners and connections and invokes a
Python connect/banner helper, **not Pulse**. It compares the baseline host
union against the new planner, alternates order over five repetitions, and
asserts the same expected service/banner set every time. Dynamic ports,
Python/platform metadata and individual samples are saved in the JSON.
No external target argument is accepted. Run on a host supporting the
`127.0.0.0/8` loopback range (the recorded run used Linux).

Recorded [raw results](benchmarks/pulse-endpoints-loopback.json), baseline
`eca0cc708e0fde9d9d08bd4dcfafee51a78f028d`:

| Local fixture | Before | After |
| --- | --- | --- |
| Heterogeneous: processes/run | 1 | 3 |
| Heterogeneous: attempted TCP connections/run | 9 | 3 |
| Heterogeneous: established connections/services | 3 / 3 | 3 / 3 |
| Heterogeneous: median duration, ms (min-max) | 563.628 (559.768-576.689) | 1794.820 (1763.740-1891.048) |
| Homogeneous: processes/attempts/services | 1 / 3 / 3 | 1 / 3 / 3 |
| Homogeneous: median duration, ms (min-max) | 575.297 (555.882-641.700) | 558.090 (552.347-702.097) |

The heterogeneous fixture is slower despite fewer attempts: it pays three
Python process startups instead of one. These timings are specific to the
helper/environment, not evidence about Pulse performance. No CPU/RSS,
packet/byte, OS/TLS coverage or cold/warm engine-cache results were collected.

**Real-engine evidence:** the [recovered Pulse 1.1.0 package](benchmarks/pulse-engine-20260929/README.md)
contains all 30 historical samples, original fixture/config, metadata and
recomputable summaries. It is distinct from the Python fixture above.
Historical Jenkins PCAPs/per-pass raw stdout are unavailable in the surviving
export; packet aggregates remain available. The current release pin is
**v1.4.0** (`scripts/pulse-pinned.sha256`), so 1.1.0 results alone cannot establish
current-engine acceptance. See the package for exact source/binary identities.

### Cost acceptance and supported comparison profile

Correctness acceptance requires exact approved pairs, unchanged service/TLS
coverage, and unresolved unavailable endpoints. The closed-service regression
(9.571 → 14.815 s, +54.8%, 236 → 249 packets) is accepted as a **historical
correctness tradeoff**, not a promise that 55% is a production latency ceiling.
It must not be hidden by marking a missing host complete or reducing coverage.

For N pending hosts with signatures s and chunk size H, nominal processes are
`C = sum(ceil(hosts_with_signature_s / H))`, at most N. In the three-host
fixture, different signatures cost 3 processes and 3 command pairs; identical
signatures cost 1 process and 3 pairs. No runtime flag expands exact endpoints.
At most three logical calls per chunk can arise from the initial call, OS
fallback, and one crash **or** settle repeat; command retries multiply process
attempts by at most `R + 1`. Thus `3*C*(R+1)` bounds adapter probe subprocess
attempts, excluding binary/plugin capability checks and other stages. Each
call has its configured process deadline plus any plugin allowance; settling
adds its configured delay once per eligible chunk; lower-level retries also
back off by `min(2 * attempt, 10)` seconds per failed attempt. Three consecutive crashed
or timed-out chunks trigger their respective breakers. These are invocation
bounds, not a global stage deadline, packet cap or bound over repeated resumes.

OS inference may contact additional ports; TLS/JARM may create multiple
connections; optional plugins and cipher enumeration have their own budgets.
Planner pairs and accepted connections are not total packets. Production
profiles with plugins, TLS enumeration, SYN, command retries, larger input,
packet loss, or unavailable remote endpoints need separate measurements.
The controlled profile is Linux isolated loopback, 3 hosts, concurrency 16,
rate 100, host parallel 3, timeout 300 ms, process deadline 90 s, retries 0,
settle 0, adaptive/SYN/CVE/online CVE/explicit plugins/TLS enumeration off,
banners and OS requested. No profile defaults are changed here.

**Current-engine acceptance:** [30 Pulse v1.4.0 arm64 samples](benchmarks/pulse-engine-20261015/README.md)
compare union versus exact planning in the same integrated adapter, with full
raw outputs/PCAP and immutable source/image/binary identities. Known service,
OS-family and TLS endpoint evidence remained identical across each scenario.
This is separate from replaying historical source revisions.

**Remaining acceptance for #448:** full integrated-main CI and release-tarball
provenance/installed-sensor acceptance. Historical and current
engine results are separate evidence. Full Python 3.11/3.12 and one terminal
successful required Jenkins gate are required; targeted tests and old per-stage
rechecks do not replace that gate. The backend decision remains #452.

Rollback is a reviewed revert of the code change. It restores the previous
overscan/resume limitations; there is deliberately no runtime switch that
silently expands the exact endpoint set.

## Optional TLS suite enumeration

Set `tls_posture.enabled: true` and `tls_posture.enumerate_ciphers: true` to
request Pulse `--tls-enum`. The selected binary must support this flag; Pulse
v1.3.0 does not. Raw SSLv2/SSLv3…TLS1.3 ServerHello evidence is fed to the
existing A-F grader with `source: pulse-tls`. `enumeration_evidence` records
`server_hello_selection`, which establishes negotiation selection rather than
a completed or trusted handshake. Missing exchange size retains
`grade_upper_bound`; partial enumeration retains `enumeration_complete: false`.
Enumeration uses a 30-second endpoint budget, with 16 KiB record limits.
Enabling it invalidates certificate-only resume receipts. Certificate probe
fallback remains available independently. GOST and exploit-specific TLS
vulnerability checks are outside this enumeration.

The Pulse 1.4.0 candidate also selects native STARTTLS transports for SMTP
(25/587), IMAP (143), POP3 (110), FTP (21), LDAP (389), PostgreSQL (5432),
and MySQL (3306), or an identified equivalent service on a nonstandard port.
Every raw probe starts a new connection and repeats the bounded upgrade.
Capability or upgrade rejection is inconclusive TLS coverage; no authentication
credentials or database queries are sent. STARTTLS certificate collection
skips direct JARM/HTTP probes. Normal TLS1.3 ServerHello x25519 shares record
the group and its 253-bit curve size; HRR remains unmeasured. TLS1.2 certificate/SKE facts are described below.

`--rate` paces additional connection starts across enumeration endpoints. It
does not enforce a packet limit within multi-message upgrade exchanges, so
`per_host_rate` scan policy disables cipher enumeration. The same restriction
applies to a locally configured per-host packet ceiling. Passive TLS evidence
parsing remains available. Released Pulse 1.3.0 lacks these capabilities; keep
`enumerate_ciphers` off until an approved binary carrying the new engine is
installed. Source, local protocol fixtures, and release acceptance remain
separate gates.

TLS enumeration resume receipts also carry the requested `raw-starttls-v2`
contract. Earlier candidate receipts with v1 or without a marker are re-probed; this marker
records the request and does not attest installed engine capability.

TLS1.2 and earlier raw first flights can report RSA certificate modulus size
(for RSA key transport), authenticated-suite ECDHE named curve/point size, and
DHE modulus size from ServerKeyExchange. `kex_evidence` identifies the observed
source. Fragments share the original timeout, eight-record and 16 KiB limits;
truncated or conflicting parameter messages do not earn measured sizes.
Signatures/chain trust are not authenticated by these raw probes, so findings
retain `requires_confirmation`. HRR, static ECDH/PSK and unavailable exchange
parameters retain upper-bound grading.

The existing grade contract rates a 1024-bit DH exchange B. An explicit
`weak_key_exchange` issue therefore surfaces measured finite-field exchange
sizes below 2048 bits (EC below 224), including B-rated suites, without changing
the established A-F thresholds or claiming exact Nmap letter parity.
