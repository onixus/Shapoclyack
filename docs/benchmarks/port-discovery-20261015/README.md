# Port-discovery backend experiment, 2026-10-15

This is real pinned-binary evidence for [#452](https://github.com/onixus/Shapoclyack/issues/452), not a production backend change. Recommendation: retain Naabu pending the remaining acceptance gates in [ADR 0003](../../adr/0003-port-discovery-backend.md). The broader issue stays open.

## Reproduce

From the repository root, run one command with a fresh output directory:

```sh
scripts/run-port-discovery-benchmark.sh /tmp/shapo-port-discovery-results
```

The wrapper uses its dedicated cached runtime when available. For a fresh runtime it extracts Naabu `/out/naabu` from local `shapo-go-tools-check:latest` (or builds this repository's `go-tools` Docker stage under an experiment-only tag), and Pulse `/pulse` from the immutable image below, then builds [Runtime.Dockerfile](Runtime.Dockerfile). This bootstrap needs the donor images, or network/registry access for their builds/downloads and apt packages. It is not an offline fresh-machine reproduction promise. A binary mismatch fails before any fixture or shaping operation. The dedicated runtime image is local and unpublished; binary copies are not committed.

Executed Naabu 2.6.1 SHA-256: `231b3b89a3695ae874e6f7007c3da37c93cf7bfbf689579eaf0d5d6062b4abb3`, copied from local Go-tools image `sha256:9c84d15ed0392d9f49842cfa749d0a1d21df991ef93a6778a087cbdd78d367f3`. This is Shapoclyack's source build with its security module overrides, not an upstream release-tarball identity claim.

Executed Pulse 1.4.0 SHA-256: `9e825d76783e5bc35ae66d8c485eb083c0725a53ac2e0d05e94c89bbdc9af529`, copied from `ghcr.io/onixus/pulse@sha256:70ab0ef673f1b49a9a52d8648999efb711dc0fa8e8cf81bab461e02dbf751ce2`. Version and image-binary identity do not establish release-tarball or signature verification.

Measured runtime: `sha256:027c27a08d698850806df0f724fa9fa9dd240f40e840429fe5253e38b2516d0e`, Python base `sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1`, Linux arm64 Docker VM, iproute2 6.15.0-1. Apt dependencies are recorded in [run-provenance.json](run-provenance.json); the recipe does not promise a bit-identical rebuild from mutable apt repositories. A prior CI runtime was removed by unrelated cleanup; none of its preflight timings enter these results.

## Scope and measurement

Only numeric owned loopback fixtures run in `--network none`. The runner requires Docker, Linux, pinned binary hashes and no active interface except loopback. It rejects other interfaces even when down, apart from an explicit list of inactive kernel-default tunnel devices. Those defaults appeared in this Docker VM after kernel modules loaded; they are never activated. All traffic shaping targets only this disposable namespace's `lo`. The source mount is read-only. Production files, host routes, host filtering and other containers are untouched.

Three TCP listeners expose HTTP nginx/1.24.0 banners at `127.20.0.1:8080` and `127.20.0.2:8443`, and SSH OpenSSH_9.2 at `127.20.0.3:2222`. These are controlled banners, not real nginx/sshd packages. The 3×4 discovery grid includes nine known closed combinations. Port 8443 deliberately serves plaintext HTTP. Additional cases cover IPv6 loopback, UDP echo 8997, bound-but-silent UDP 8998, closed UDP 8999, an attempted controlled TCP drop rule, 64 approved closed loopback hosts, exclusions, max-host rejection, and native interruption/resume.

Every main group has five alternating repetitions. Cold means a fresh command HOME; warm reuses HOME. The OS page cache is not flushed. Root SYN and UID 65534 connect are separate profiles; no-raw subprocesses set `PR_SET_NO_NEW_PRIVS`, then drop groups/GID/UID so file capabilities cannot restore raw privilege. Capability checks have separate HOME directories. Both discovery commands request 150 ms timeout, 100 probes/s and concurrency 16, but use their native retry semantics (Naabu `-retries 1`, Pulse `--max-retries 0`); actual packet/connection counts expose differences instead of assuming equivalent internal probes. Naabu has a one-second warm-up configured. Pulse performs implicit service probing even without `--banner` in this pin, so its nominal discovery invocation is not a verified port-only phase.

Baseline/fixed/reuse rows are **CLI stage sums**, not elapsed product-pipeline timings: baseline and fixed share each recorded Naabu discovery sample, then execute Pulse with identical `-b` settings. Union uses discovered hosts × their union ports; exact uses only each host's actual discovered ports. Fixture truth never repairs discovery misses. Reuse performs a single Pulse discovery/enrichment invocation over the full approved grid. No production adapter, scheduler, Nuclei stage, OS profile, TLS certificate fixture, plugin or CVE stage is timed. Downstream findings parity is unmeasured, not inferred from empty findings arrays.

CPU and peak RSS come from per-child `wait4`. RSS includes fork/pre-exec Python memory and is not binary-only RSS or total concurrent process memory. Pipeline RSS is the maximum child peak, not a sum. Connection load counts accepted TCP connections on the owned fixture; target CPU and memory are not independently measured. AF_PACKET captures on loopback include outgoing/incoming copies: frames and bytes are captured Ethernet-frame lengths, not physical wire traffic. PCAP headers are excluded. Per-stage raw metrics include frames/bytes/SYNs, CPU/RSS, argv, timeouts and process return codes. Captured traffic is a lower bound whenever `capture_complete=false`; incomplete capture invalidates performance coverage. Capture-drop outcomes in this run: `[]`.

This run contains **133 scanner processes/stages**, 60 discovery/scenario samples and 30 chain samples. The VM is shared and unpinned; these microbenchmarks do not establish universal speedups, production load budgets or routed-network acceptance. All final runner and fixture sources are archived with hashes.

## Discovery and network scenarios

| Profile / cache / variant | Median seconds [min, max] | Median CPU seconds | Peak child RSS KiB, median | Processes | Accepted TCP | Captured frames | Open-set matches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| approved_64_closed / warm / naabu | 1.0693 [1.0639, 1.0743] | 0.0867 | 55204 | 1 | 0 | 256 | 5/5 |
| approved_64_closed / warm / pulse | 0.0236 [0.0228, 0.0254] | 0.0242 | 31052 | 1 | 0 | 256 | 5/5 |
| delay10ms_loss5pct / warm / naabu | 2.1082 [1.0936, 2.1173] | 0.0894 | 55108 | 1 | 3 | 84 | 5/5 |
| delay10ms_loss5pct / warm / pulse | 0.4841 [0.3844, 1.0380] | 0.0318 | 31052 | 1 | 9 | 191 | 5/5 |
| root_syn / cold / naabu | 1.0727 [1.0717, 1.0925] | 0.0856 | 68892 | 1 | 0 | 54 | 0/5 |
| root_syn / cold / pulse | 0.0086 [0.0061, 0.1594] | 0.0081 | 68892 | 1 | 0 | 60 | 4/5 |
| root_syn / warm / naabu | 1.0735 [1.0627, 1.0759] | 0.0807 | 68892 | 1 | 0 | 54 | 0/5 |
| root_syn / warm / pulse | 0.0078 [0.0073, 0.1599] | 0.0078 | 68892 | 1 | 0 | 60 | 4/5 |
| unprivileged / cold / naabu | 1.0735 [1.0683, 1.0747] | 0.0830 | 54980 | 1 | 3 | 76 | 5/5 |
| unprivileged / cold / pulse | 0.0259 [0.0230, 0.0300] | 0.0258 | 30448 | 1 | 9 | 184 | 5/5 |
| unprivileged / warm / naabu | 1.0777 [1.0736, 1.0788] | 0.0889 | 55320 | 1 | 3 | 76 | 5/5 |
| unprivileged / warm / pulse | 0.0261 [0.0252, 0.0294] | 0.0262 | 30448 | 1 | 9 | 180 | 5/5 |

Naabu emits open events only; absence of an endpoint means unknown, never confirmed closed/filtered. Duplicate open events are deduplicated for set comparison and preserved raw. Pulse's raw `tcpsyn` protocol tag is normalized to transport `tcp`, with the original report retained. Root Naabu SYN does not detect these loopback listeners in this fixture: that is a failed fixture coverage result, not proof of a routed-network regression or a usable general SYN comparison. Delay/loss misses remain visible in open-set match counts.

## Equal-flag CLI chain totals

| Profile / cache / variant | Median seconds [min, max] | Median CPU seconds | Peak child RSS KiB, median | Processes | Accepted TCP | Captured frames | Open-set matches |
| --- | --- | --- | --- | --- | --- | --- | --- |
| unprivileged / cold / baseline_union | 1.0988 [1.0930, 1.1004] | 0.1067 | 54980 | 2 | 9 | 218 | 5/5 |
| unprivileged / cold / fixed_exact | 1.1490 [1.1469, 1.1595] | 0.1636 | 54980 | 4 | 9 | 194 | 5/5 |
| unprivileged / cold / pulse_reuse | 0.0288 [0.0248, 0.0289] | 0.0271 | 30456 | 1 | 6 | 154 | 5/5 |
| unprivileged / warm / baseline_union | 1.1022 [1.1002, 1.1048] | 0.1146 | 55320 | 2 | 9 | 218 | 5/5 |
| unprivileged / warm / fixed_exact | 1.1513 [1.1499, 1.1537] | 0.1624 | 55320 | 4 | 9 | 192 | 5/5 |
| unprivileged / warm / pulse_reuse | 0.0270 [0.0241, 0.0285] | 0.0260 | 30624 | 1 | 6 | 154 | 5/5 |

All successful chain samples preserve the three controlled service/product/version observations (HTTP nginx/1.24.0 twice; SSH OpenSSH/9.2 once). Exact planning reduces requested host-port pairs at the cost of more child processes on this tiny fixture; it is not a general latency optimization. Reuse removes a duplicate discovery step, but unmeasured OS/TLS/plugin/Nuclei contracts prevent using this timing to promote a backend.

## Capability and interruption outcomes

| Check | Exit | Deadline exceeded | Observed output / limitation |
| --- | --- | --- | --- |
| pulse_ipv6_connect | 0 | False | ::1:8080/tcp=open; ::1:8999/tcp=closed |
| naabu_ipv6_connect | 0 | False | 2 open-event lines (may contain duplicate events) |
| pulse_no_raw_syn | 1 | False | Explicit raw-socket privilege refusal |
| naabu_no_raw_syn | 0 | False | 2 open-event lines (may contain duplicate events) |
| pulse_udp_closed | 0 | False | 127.20.0.1:8999/udp=closed |
| naabu_udp_closed | 0 | False | No open events; state remains unknown in an open-only report |
| pulse_max_hosts | 1 | False | Host expansion budget rejected |
| pulse_exclusion | 0 | False | 127.20.0.1:2222/tcp=closed; 127.20.0.1:8080/tcp=open; 127.20.0.1:8443/tcp=closed; 127.20.0.3:2222/tcp=open; 127.20.0.3:8080/tcp=closed; 127.20.0.3:8443/tcp=closed |
| naabu_exclusion | 0 | False | 4 open-event lines (may contain duplicate events) |
| pulse_udp_v4_root_syn | 0 | False | 127.20.0.1:8997/udp=open; 127.20.0.1:8998/udp=open\|filtered; 127.20.0.1:8999/udp=open\|filtered |
| naabu_udp_v4_root_syn | 1 | True | INCOMPLETE: terminated at stage deadline; no negative inference from missing events |
| pulse_udp_v4_unprivileged | 0 | False | 127.20.0.1:8997/udp=open; 127.20.0.1:8998/udp=open\|filtered; 127.20.0.1:8999/udp=open\|filtered |
| naabu_udp_v4_unprivileged | 1 | True | INCOMPLETE: terminated at stage deadline; no negative inference from missing events |
| pulse_udp_v6_root_syn | 0 | False | ::1:8997/udp=open; ::1:8998/udp=open\|filtered; ::1:8999/udp=open\|filtered |
| naabu_udp_v6_root_syn | 1 | True | INCOMPLETE: terminated at stage deadline; no negative inference from missing events |
| pulse_udp_v6_unprivileged | 0 | False | ::1:8997/udp=open; ::1:8998/udp=open\|filtered; ::1:8999/udp=open\|filtered |
| naabu_udp_v6_unprivileged | 1 | True | INCOMPLETE: terminated at stage deadline; no negative inference from missing events |
| pulse_ipv6_syn | 0 | False | ::1:8080/tcpsyn=open; ::1:8999/tcpsyn=closed |
| naabu_ipv6_syn | 0 | False | No open events; state remains unknown in an open-only report |
| pulse_cancel | -2 | False | SIGINT requested=True; checkpoint=True |
| pulse_resume | 0 | False | Native resume completed; raw output/checkpoint retained, not product resume acceptance |
| naabu_cancel | 1 | False | SIGINT requested=True; checkpoint=['.config/naabu/resume.cfg'] |
| naabu_resume | 1 | False | Plain -resume rejected without input list; full-scope native resume remains unverified |

Advertised flags are retained in `pulse-help.txt` and `naabu-help.txt`. These readable copies normalize trailing whitespace; byte-exact CLI help remains in the raw archive. Naabu UDP echo/silence cases that exceed the deadline are explicitly incomplete; missing open events cannot become negative coverage. A bound silent UDP socket is not ground-truth firewall filtering: a reported `filtered` state there is a timeout inference. The attempted TC TCP egress-drop rule was unsupported: the kernel returned `TC classifier not found`. Consequently controlled TCP filtered-state truth remains unmeasured in this environment; no successful filtering fixture is claimed. [network-shaping.json](network-shaping.json) retains exact configuration commands, errors, kernel counters and namespace cleanup; unsupported shaping would remain an explicit failed capability, never a simulated successful test.

Cancellation uses a controlled 309-combination TCP scope and SIGINT after 0.3 seconds; a five-second grace precedes forced kill. Every ordinary stage has a ten-second deadline. Pulse native resume completed with checkpoint status `done`, but its raw report uses `open` where a fresh report uses `results`; no downstream resume/reuse schema parity is inferred. Naabu created a resume checkpoint, then plain `-resume` without repeating input flags returned exit 1 (`no input list provided`); completing native resume with the full original scope remains unverified. Native checkpoint/resume artifacts and any missed/incomplete outcomes stay raw. This checks CLI behavior only: production cancellation, report finalization, cancellation during downstream verification, resumed exclusions/budgets, and installed-sensor lifecycle remain separate acceptance gates.

## Evidence and remaining gates

`results.json` and `pipelines.json` retain every measured sample; their summaries include median, min/max, CPU, peak RSS, process/connection counts, frames/bytes and coverage. `raw-outputs.tar.gz` retains per-stage stdout/stderr/PCAP/metrics, checkpoint/config artifacts and the exact executed runner/fixture sources. `raw-sha256.json` hashes every archived file. `SHA256SUMS` hashes the delivered evidence files; hashes detect drift, not authenticity. Regression tests independently recompute summaries, hashes and PCAP counters.

Before closing #452 or exposing a production backend, complete routed IPv4/IPv6 SYN/UDP acceptance with real target topology; production adapter/reuse and checkpoint contracts; services/versions/OS/TLS/plugin and Nuclei findings parity with identical reviewed template hashes; full delayed/loss/filter scenarios across enrichment and verification; silent TCP hosts; large realistic allowlists beyond this 64-host fixture; resume with exclusions, per-stage/global budgets and target churn; cancellation at all product stages; target resource load and soak; signed/release/installed-sensor provenance. These results justify retaining the existing default while those gates stay open.
