# ADR 0003: Retain Naabu pending discovery-backend acceptance

| | |
|---|---|
| **Status** | **Accepted** — retain Naabu; backend promotion remains gated |
| **Issue** | [#452](https://github.com/onixus/Shapoclyack/issues/452) |
| **Date** | 2026-10-20 |
| **Evidence** | [Pinned-binary loopback experiment](../benchmarks/port-discovery-20261015/README.md), [TLS/Nuclei parity and resume supplement](../benchmarks/port-discovery-20261020/README.md) |

## Context

Naabu currently discovers endpoints and Pulse enriches them. The endpoint planner
already avoids probing a host's union of unrelated ports; [the earlier planner
experiment](../benchmarks/pulse-engine-20261015/README.md) did not execute Naabu.
Replacing discovery is a separate decision from fixing that planner.

The new experiment actually executes Naabu 2.6.1 and Pulse 1.4.0, hashes both
executed binaries, records raw reports, help output, per-command CPU/peak RSS,
traffic captures, accepted connections, return codes and command lines. Five
cold/five warm repetitions compare TCP discovery and three equal-flag CLI
chains: Naabu → union enrichment; Naabu → exact enrichment; combined Pulse
scanning/enrichment with discovery evidence reused. Plans consume actual Naabu
output; missing endpoints are never repaired from fixture truth. The fixture
has unequal ports, known HTTP/SSH banners, closed ports, IPv6, UDP echo/silence,
explicit privilege failures and bounded interruption/resume. A larger fixture
contains 64 approved numeric loopback addresses. Network shaping is attempted
only inside the disposable verified network namespace; unsupported kernel
features remain visible as failed capability checks.

This is a local Linux arm64 Docker microbenchmark, with all traffic restricted
to its own loopback. It does not establish routed sensor behavior, production
pipeline timings, or a deployment gate. The evidence README gives measured
results and every remaining acceptance boundary.

## Decision drivers

- Preserve discovered endpoint coverage under protocol, privilege and network
  variations. A faster run that omits an endpoint cannot qualify for promotion.
- Keep discovery, enrichment and verification evidence separate. An omitted
  endpoint in an open-only report is unknown, not proof it is closed.
- Bound all real probes, including implicit service probes and retries, and
  keep exclusions and cancellation truthful across a resumed run.
- Avoid making the default depend on an unaccepted experiment or on a
  successful process exit alone.

## Options

1. **Retain Naabu.** Ship no discovery change; use the real experiment to
   specify the next acceptance gate. This preserves the current operational
   behavior and allows the exact Pulse planner improvements independently.
2. **Add an opt-in Pulse discovery backend.** Requires an adapter contract,
   coverage merge/reuse rules, budget and scope validation, and integrated
   runtime tests. This experiment alone does not implement that backend.
3. **Replace Naabu.** Remove a component only after complete endpoint and
   downstream evidence parity on supported sensor configurations, including
   routed IPv4/IPv6, UDP, privilege degradation and interruption/resume.

## Decision

The 2026-10-20 supplement executes 30 complete CLI chains with the same real
Nuclei template, HTTP/SSH services and a real TLS fixture. Endpoint, service,
certificate and Pulse/Nuclei finding evidence matches in every chain. Five
cold/five warm repetitions retain per-stage resource and traffic measurements.
This supports reuse as a candidate without accepting a production backend.
The actual OS preflight exceeded its deadline and sent implicit probes to ports
outside the declared grid; root SYN/UDP/filter limitations remain explicit.
These concrete coverage and budget obstacles make retention the accepted
decision rather than leaving default selection undecided.

Retain Naabu as the default. Pulse is a credible alternative worth developing;
small loopback timings cannot establish that it safely replaces the current
chain. The measured combined Pulse chain reuses observations, but the current
CLI also performs implicit service probing in an invocation without `--banner`.
Consequently a nominal discovery invocation is not an independently verified
port-only budget. Naabu's SYN loopback limitations likewise prevent treating
this fixture as a general SYN comparison. See the raw outcomes rather than
interpreting an empty open-event stream as a successful negative scan.

Before implementing option 2, define or request a GenDec release contract with:

- A documented discovery-only profile or an explicit declaration of every
  implicit probe, with rate/concurrency/retry budgets covering those probes.
- Stable per-endpoint transport/state semantics (`tcpsyn` is normalized to
  transport `tcp` here), privilege refusal/degradation policy, and an explicit
  distinction between closed, filtered, unknown and incomplete.
- Reusable versioned service/OS/TLS/plugin observations bound to endpoint,
  scanner binary, profile and source report; the Shapoclyack adapter must reject
  stale or incompatible observations instead of silently claiming parity.
- A checkpoint contract preserving partial coverage, exclusions, budgets and
  scope. Interruption must never mark unvisited hosts or endpoints complete.
- Supported TCP/UDP and IPv4/IPv6 matrices, including no-raw behavior, backed
  by routed-network fixtures with delay, loss, filtering and silent hosts.

The pinned Pulse native resume completed with checkpoint status `done`, but its
`pulse.scan.v2` report used `open` where a fresh report used `results`. The
supplementary experiment now parses both explicitly, and Naabu native resume
succeeds with the original input options. Its incremental results require
merging the cancelled stream. A production reuse adapter still needs an explicit
tested schema and coverage contract. The attempted
TC filtering fixture was unsupported by this kernel (`TC classifier not found`);
netem delay/loss worked. Neither gap is silently counted as accepted coverage.

These are acceptance requirements, not claims that all corresponding Pulse
features are absent. Flags advertised by the pinned CLI are not runtime proof.

## Consequences

No production default, API, UI or persisted scan behavior changes. The
experiment is reproducible and independently auditable. The accepted decision
is to retain Naabu; the remaining work listed in the supplementary README is a
gate for future backend promotion, not evidence of an implemented replacement.
The next backend change must record immutable source/binary provenance and rerun integrated downstream
Nuclei parity with the same templates and budgets. Separate synthetic planner
coverage does not establish that parity.

Rollback for a future opt-in adapter is to select Naabu discovery, discard
incompatible Pulse discovery checkpoints/reuse records, and rerun the affected
scope through the established chain. Historical reports and their provenance
must remain readable; never reinterpret a partial run as a complete baseline.

## Not decided here

Distribution and licensing ([ADR 0001](0001-pulse-distribution-model.md)),
replacing Nmap functionality ([ADR 0002](0002-replacing-nmap-functions.md)),
production backend configuration, signed packages, installed sensor acceptance,
and remote-network or physical-device validation.
