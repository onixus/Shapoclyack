# Issues 448–452: implementation and acceptance map

This map separates delivered contracts and reproducible local evidence from the
final integrated delivery gate. No issue/PR state, deployment or installed-sensor
result is inferred from a local test pass.

| Issue | Delivered contract and local evidence | Acceptance boundary |
| --- | --- | --- |
| [#448](https://github.com/onixus/Shapoclyack/issues/448) | [Exact TCP target planning, per-host receipts/resume and explicit cost acceptance](pulse-endpoints.md); [historical Pulse 1.1.0 kit](benchmarks/pulse-engine-20260929/README.md); [current 1.4.0 adapter comparison](benchmarks/pulse-engine-20261015/README.md), 30 samples with raw output/PCAP | Correctness accepts higher unavailable-service latency. Logical calls/process deadlines are bounded per invocation; whole-engine packets/OS auxiliary ports are not bounded by the planner. Final integrated CI remains pending. |
| [#449](https://github.com/onixus/Shapoclyack/issues/449) | [Additive finding observations](finding-evidence.md), precise subjects, provenance, replay and conservative negative-closure rules across reports/API/tracker/analytics | Legacy remediation container identity/counts remain distinct from precise evidence. Migration 0087 precedes API deployment. The real local Nuclei capture uses a fabricated CVE template to validate output shape; it is not real-world CVE accuracy acceptance. |
| [#450](https://github.com/onixus/Shapoclyack/issues/450) | [Directed Nuclei planning](nuclei-planner.md), exact endpoints, bounded processes/targets and virtual-host Host/SNI; pinned v3.11.1 and v9.9.4 catalog captures under `tests/fixtures/nuclei_plan/catalog_v9_9_4` | Legacy stays default. Directed mode retains the scope-safe eligible HTTP catalog, not unproved product-based template pruning. Unsupported templates are recorded as excluded; the comparison fixture is not production detection recall. |
| [#452](https://github.com/onixus/Shapoclyack/issues/452) | [Accepted ADR: retain Naabu](adr/0003-port-discovery-backend.md); [fresh discovery, native resume, 30 equal-privilege TLS/Nuclei chains and failed OS preflight](benchmarks/port-discovery-20261020/README.md) | No alternative production backend is enabled. Supported loopback results and explicit SYN/UDP/filter/OS-budget failures justify retention. Routed topology, target resource soak and installed-sensor acceptance remain promotion gates. |

The issue execution order was #449/#450/#452, then #448 acceptance. Historical
benchmark identities stay immutable; the final delivery commit will include
these changes together. There is no claim that every historical benchmark ran
at that integrated commit.

## Focused reproducible verification

From the repository root with its Python test dependencies installed:

```sh
python -m pytest -q \
  tests/test_pulse_probe.py tests/test_pulse_endpoints.py \
  tests/test_pulse_resume.py tests/test_pulse_main_resume.py \
  tests/test_pulse_benchmark_evidence.py \
  tests/test_port_discovery_benchmark.py tests/test_discovery_downstream_benchmark.py
```

These checks validate exact endpoint/resume contracts, recomputed measurements,
artifact hashes, PCAP counters and recorded service/TLS/Nuclei parity. They use
mocked subprocesses or saved evidence and do not contact external scan targets.
The linked evidence READMEs give the separate real-binary fixture commands.
They also describe cached-image/build requirements, pinned binaries/templates,
network isolation and the boundaries of each profile.

The #449/#450 document links give their focused suites and local database/UI/
catalog fixtures. This map does not substitute a selected subset for the
repository's authoritative gate.

## Final integrated delivery gate

**Status:** Evidence is recorded against the immutable final PR head in its PR
description; no terminal verdict is asserted by this source document.

At preparation time integrated CI is pending. Source changes are completed
before that gate so the tested head can remain unchanged.

The final gate must name one immutable integrated commit, the Jenkins job/build
URL, the exact checkout SHA, terminal `Finished: SUCCESS`, full Python 3.11 and
3.12 suite outcomes, and required stage/lifecycle outcomes. A superseded head,
queued/running build, targeted repeat, historical green build or synthetic
fixture alone cannot satisfy it. Publish or update only the PR description
with that completed evidence; do not change source files to record the result
and thereby invalidate the tested head. Local review/implementation completion
does not turn this gate green.

Release signing, publishing, production migration/deployment and installed
sensor acceptance are separate operations and are not recorded as completed
by this map. No production default changed to make these local comparisons pass.
