# Current-engine loopback acceptance, 2026-10-15

This comparison uses the same integrated adapter from main
`703a9299d14fafee646971240197c81451b1ed2d` for both variants. `before` substitutes
only the old host-union port planner inside the isolated fixture driver;
`after` uses the shipped exact planner. The simulated union never enters the
product. This isolates planning overhead from other changes since #491;
it is not a rerun of the old #491 source revisions.

Pulse is v1.4.0, Linux arm64 Docker VM on macOS, from
`ghcr.io/onixus/pulse@sha256:70ab0ef673f1b49a9a52d8648999efb711dc0fa8e8cf81bab461e02dbf751ce2`.
Executed binary SHA-256:
`9e825d76783e5bc35ae66d8c485eb083c0725a53ac2e0d05e94c89bbdc9af529`.
This digest anchors the actual image binary; no release tarball install record
was present. Matching version does not establish tarball-byte identity or
signature verification. The repository's reviewed release tarball pins remain
in `scripts/pulse-pinned.sha256` and were not changed.

Reproduce from the repository root. Docker builds use the frozen hash-checked
Python requirements; apt tools/platform can change, so the runtime image
identity is recorded separately and is not a bit-for-bit rebuild promise.

```sh
docker build -f docs/benchmarks/pulse-engine-20261015/Runtime.Dockerfile \
  -t shapo-issue448-benchmark:local .
mkdir -p /tmp/pulse-acceptance
chmod 777 /tmp/pulse-acceptance
docker run --rm --network none --cap-add NET_RAW --cap-add NET_ADMIN \
  --user 1000:1000 -e HOME=/tmp -v "$PWD:/source:ro" \
  -v /tmp/pulse-acceptance:/results --entrypoint python \
  shapo-issue448-benchmark:local /source/scripts/benchmark-pulse-engine.py \
  --output /results --before-source /source --after-source /source \
  --legacy-before --repeats 5 \
  --binary-sha256 9e825d76783e5bc35ae66d8c485eb083c0725a53ac2e0d05e94c89bbdc9af529
python scripts/summarize-pulse-engine.py /tmp/pulse-acceptance/results.json
```

Use a fresh results directory. The runner rejects a mismatched binary or any
active interface other than loopback and allows only the fixed fixture targets.
Five alternating repetitions cover heterogeneous HTTP/TLS/SSH, homogeneous
HTTP, and unavailable SSH. Profile matches the historical fixture except that
current adapter source selects its pinned IANA service data and SinFP OS mode.
CVE, SYN, plugins, cipher enumeration and STARTTLS are not exercised.

`results.json` has all measured samples; `summary.json` is reproducible with
`scripts/summarize-pulse-engine.py`; `metadata.json` records platform and binary.
`run-provenance.json` records immutable product source and local runtime image.
`raw-outputs.tar.gz` retains every per-pass raw JSON, canonical outputs, argv
host lists, capture logs, stdout/stderr and PCAP. Fixture private key material
is excluded. `SHA256SUMS` checks accidental artifact drift, not authenticity.

Packet counts include bidirectional loopback traffic and additional OS/TLS
probes, not only planned TCP combinations. Wire bytes exclude PCAP headers.
Listener accept counts omit refused connections. RSS is Linux child maximum,
not total concurrent process memory. Service names/banners and OS confidence
are inferences, not independent identification accuracy. TLS coverage means
certificate evidence, not cipher or vulnerability parity. Cold/warm enrichment,
packet loss, remote latency, unprivileged OS fallback and crash retries remain
outside this profile. This is current arm64 image-binary acceptance only;
release-tarball provenance, installed-sensor acceptance and full integrated CI
remain separate gates. See [endpoint acceptance](../../pulse-endpoints.md).

The fixture supplies approved discovery endpoints directly; Naabu itself is
not timed or executed in this comparison. Full-pipeline acceptance is separate.

## Recorded results

| Scenario | Median seconds before → after | Processes | Command pairs | Median packets |
| --- | --- | --- | --- | --- |
| Heterogeneous | 13.641 → 12.894 | 1 → 3 | 9 → 3 | 270 → 253 |
| Homogeneous | 13.334 → 13.332 | 1 → 1 | 3 → 3 | 120 → 120 |
| Unavailable SSH | 9.620 → 14.899 | 1 → 3 | 9 → 3 | 235 → 249 |

All five samples per variant preserve service/product/version sets, known OS
families and TLS endpoint sets: 3/3/1 heterogeneous, 3/3/0 homogeneous,
2/2/1 unavailable. Exact planning retains only the unavailable host as unresolved. Under the
simulated union plan, the current stricter completion contract leaves all
heterogeneous/partial hosts unresolved because each union chunk demands ports
that are absent on individual hosts. Homogeneous completes all hosts in both
variants. This deliberate benchmark-only contract violation measures overscan
cost without recreating historical false-done behavior; it is not a usable
production rollback. No universal speedup follows from these results.

During collection, runner validation was tightened (fixed endpoint allowlist
and truncated-PCAP rejection). Product adapter/planner source, measured
commands and profile stayed fixed. Every persisted PCAP was then reprocessed
with the final parser and matched its recorded counters. The final runner is
provided for reproduction; no immutable hash of each earlier runner revision
was captured. This limits harness-source provenance, not product-source identity.
