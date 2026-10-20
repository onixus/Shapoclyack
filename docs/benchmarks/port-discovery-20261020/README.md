# Port backend retention decision: supplementary evidence, 2026-10-20

Decision: **retain Naabu**. Pulse remains an experimental candidate; no product
backend selector or automatic fallback is introduced. This extends the
[2026-10-15 experiment](../port-discovery-20261015/README.md) with fresh pinned
binary measurements, native resume and actual downstream TLS/Nuclei parity.
[ADR 0003](../../adr/0003-port-discovery-backend.md) records the decision and the
concrete obstacles to replacing the existing default.

## Reproduce without external probes

With the previously documented benchmark runtime and Go-tools donor cached:

```sh
scripts/run-port-discovery-benchmark.sh /tmp/discovery-fresh
scripts/run-discovery-downstream-benchmark.sh /tmp/downstream-fresh
```

Neither command accepts target arguments. Each scanner process runs inside a
new Docker `--network none` namespace and probes fixed numeric loopback targets.
The downstream wrapper extracts Nuclei from the exact local donor image ID,
mounts source/template read-only and refuses output reuse. It never downloads
binaries or templates. The original wrapper's fresh-image bootstrap requirements
still apply; this is not an offline fresh-machine image build promise.

Runtime `sha256:027c27a08d698850806df0f724fa9fa9dd240f40e840429fe5253e38b2516d0e`;
Go-tools donor `sha256:9c84d15ed0392d9f49842cfa749d0a1d21df991ef93a6778a087cbdd78d367f3`.
Pulse 1.4.0 and Naabu 2.6.1 binary hashes are unchanged from the preceding
experiment. Nuclei 3.11.1 executable SHA-256:
`7a2fb8a51e4aa0e0aefc57bf8865ea32c4e307de8f44e125e532884d6129156d`.
The committed `nginx-status.yaml` is the unmodified upstream template from
nuclei-templates v9.9.4 commit
`f4251b06c100067f230c4f54a1679de59802c7a4`,
`http/misconfiguration/nginx/nginx-status.yaml`; its exact hash is enforced by
the runner. These are executed binary/image identities, not release signature
or installed-sensor acceptance claims.

## Fixture and comparison

The supplementary discovery run repeats the original TCP/UDP/IPv6,
root/no-raw, delay/loss, exclusion, 64-host and cancellation fixtures with five
cold/five warm main repetitions. `discovery-*.json` contains fresh results.

The downstream fixture adds a real self-signed TLS socket at
`127.20.0.2:8443`, HTTP at `127.20.0.1:8080` and an SSH banner at
`127.20.0.3:2222`. Both HTTP fixtures deliberately respond with nginx/1.24.0
and a deterministic nginx status body. These emulate application responses;
they are not deployed nginx/sshd packages. The generated public certificate is
retained; the ephemeral private key is excluded. The expected four Nuclei
matches are the two status paths on HTTP and HTTPS. A match proves that this
real reviewed template executed and recognized the fixture, not that a real
nginx vulnerability or unrelated CVE was validated.

Three actual CLI chains run five times per cache condition:

- Naabu connect discovery, union Pulse enrichment, Nuclei verification.
- Naabu connect discovery, exact host/port Pulse enrichment, Nuclei verification.
- One combined Pulse discovery/enrichment invocation, Nuclei verification.

Every plan consumes actual discovery output; fixture truth never repairs misses.
The third chain does not run Pulse a second time. All three use identical
Pulse banner settings and the identical Nuclei template, target semantics,
concurrency, retries and rate budgets. Every scanner stage uses the same UID/GID 65534, no-new-privs and no raw
capabilities. The parent owns the fixed fixture and packet capture.
`--os` is disabled after the failed preflight below. TLS enumeration and service
probes are implicit in this pinned Pulse, so discovery-only and enrichment time
cannot be separated for its combined invocation.

Cold means fresh HOME; warm reuses HOME. No OS page-cache flush, CPU pinning or
exclusive VM is claimed. Values are sums of CLI stages, not scheduler/product
pipeline latency. Per-stage CPU/RSS/processes, accepted connections, PCAP
frames/bytes, deadlines and return codes are retained. RSS includes fork memory;
loopback captures count both directions. Target CPU/memory is not measured.

## Results

| Cache / chain | Total seconds median [min, max] | Discovery / enrichment / verification median seconds | Processes | Accepted TCP median | Captured frames median |
| --- | --- | --- | --- | --- | --- |
| cold / Naabu union | 1.523 [1.508, 1.544] | 1.070 / 0.346 / 0.110 | 3 | 24 | 534 |
| cold / Naabu exact | 1.545 [1.538, 1.576] | 1.064 / 0.388 / 0.103 | 5 | 24 | 506 |
| cold / Pulse reuse | 0.439 [0.430, 0.444] | combined 0.337 / verification 0.098 | 2 | 21 | 470 |
| warm / Naabu union | 1.495 [1.488, 1.541] | 1.063 / 0.339 / 0.098 | 3 | 24 | 534 |
| warm / Naabu exact | 1.559 [1.539, 1.582] | 1.066 / 0.392 / 0.101 | 5 | 24 | 510 |
| warm / Pulse reuse | 0.439 [0.435, 0.446] | combined 0.340 / verification 0.095 | 2 | 21 | 470 |

All **30/30** chains match three expected endpoints, their services/products/
versions, the TLS endpoint and all four Nuclei path matches. All also match the
corresponding baseline's certificate subject/issuer/validity/protocol fields,
Pulse TLS findings (self-signed and expiring soon) and Nuclei `(template, URL,
matched-at)` sets. This comparison retains port, scheme and path; a host-only
match cannot hide a missing endpoint. Capture drops and command failures are
zero in these 30 chains. Full numerical results are in `chains-summary.json`;
stage raw output and traffic remain auditable.

This small fixture supports a possible benefit from reuse. It does not establish
a production speedup or a safe backend replacement.

## Failures and unsupported acceptance

**OS/scope budget:** the real `--os --os-mode sinfp` preflight did not finish
within its 10-second deadline. Its captured SYNs include ports
21,22,25,80,135,139,443,445,3306,3389,5900, outside the declared discovery grid
2222,8080,8443. The configured port list does not bound implicit OS probes in
this binary. The owned container was stopped after this finding; partial raw
PCAP/metrics survive under `os-preflight/`. These were still owned loopback
addresses, never external scans. OS results in the completed TLS/Nuclei chains
are explicitly disabled after this failure; empty OS arrays are not parity.
A future backend must declare/budget all such ports before OS is accepted.

**Native resume:** Pulse's checkpoint `pulse.scan.v2` report uses `open`, while
fresh reports use `results`. The parser now handles both, rejects unknown or
ambiguous envelopes, and the fresh resumed open set contains all three endpoints.
Naabu succeeds when `-resume` receives the original scope/options. Its resumed
stream is incremental: the cancelled stream contains 8443; resumed output adds
8080 and 2222. Their deduplicated union matches all three expected endpoints.
Discarding the pre-interruption stream would lose evidence. This proves native
CLI open-set reconciliation only, not product checkpoint coverage, unchanged
exclusions/budgets or completion of every planned negative probe.

**Network/privilege:** the fresh discovery results retain Naabu's empty root SYN
loopback outcome as failed coverage. TCP connect IPv4/IPv6 works on this fixture;
Pulse refuses no-raw SYN and Naabu degrades to connect. UDP deadline failures
remain incomplete and open-only absence remains unknown. TC controlled filtering
is unavailable in this kernel (`TC classifier not found`); delay/loss is measured.
No routed Ethernet topology, physical sensor, signed package or installed-device
acceptance is inferred. The original full capability matrix remains applicable.

These explicit failures are reasons to keep the established backend. Promotion
requires routed supported TCP/UDP/IPv6 coverage, declared implicit OS/service
budgets, a versioned reuse/checkpoint adapter, cancellation/resume exclusions
and budgets, target load/soak, and representative production findings parity.
The current change accepts a retention decision, not those future promotion gates.

## Evidence integrity

`raw-outputs.tar.gz` contains all scanner stdout/stderr/metrics/PCAP and native
checkpoint artifacts from discovery, the completed downstream run and the failed
OS preflight. Executed source snapshots are included: the discovery snapshot
matches `discovery-metadata.json`; the downstream source matches `provenance.json`.
The exact imported downstream helper and engine snapshots have their own
provenance hashes. Native resume-union reporting was added after the fresh
discovery run; its archived snapshot remains exact and reconciliation is
independently verified from both raw streams.
`raw-sha256.json` hashes every archive member, and `SHA256SUMS` hashes delivered
files. Hashes detect drift; they do not authenticate a release. Tests recompute
PCAP counters and verify endpoint/service/TLS/finding parity from raw evidence.
