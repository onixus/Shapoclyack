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
corresponding persisted endpoint evidence. Completed hosts' service/OS/CVE/TLS
evidence is retained when pending hosts are re-probed. An all-completed pass
does not erase the artifacts. Missing/invalid cache or a legacy checkpoint
that incorrectly marked a partial group done causes safe replay of the
still-approved endpoints. Previously overscanned ports and hosts outside the
current input are excluded from retained data. Literal IPv6 forms are
normalized for evidence matching; DNS equivalence is not inferred.

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
python -m pytest -q tests/test_pulse_probe.py tests/test_pulse_endpoints.py
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

**Remaining acceptance evidence for #448:** run the controlled comparison
with the actual pinned Pulse binary and record service/OS/TLS coverage,
connections/packets, duration, process overhead and partial failures. This
fixture does not satisfy that full-engine criterion or the backend decision
in #452. No backend replacement or profile-default change is included.

Rollback is a reviewed revert of the code change. It restores the previous
overscan/resume limitations; there is deliberately no runtime switch that
silently expands the exact endpoint set.
