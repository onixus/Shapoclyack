# Recovered real-engine comparison, 2026-09-29

This is historical evidence, not a rerun of current main or Pulse 1.4.0.
Baseline `eca0cc708e0fde9d9d08bd4dcfafee51a78f028d` versus #491 head
`c0352ad72b7b51ac1f25cb895f56e2675db88873`, real Pulse **1.1.0**.

Recovered byte-for-byte from the original local benchmark export:

- `results.json`: all 30 sample records, captured argv/exit/durations, canonical
  services/OS/TLS, done/unresolved hosts, CPU/RSS, traffic aggregates and SYN
  destination counters.
- `summary.json`: original descriptive summary. Its `pcap_bytes_median` is
  actually the sum of captured packet **wire lengths**, not PCAP file size.
- `metadata.json`: original platform, UID, binary hash and install record.
- `fixture.py.txt`: exact original executable fixture source; copy it to
  `pulse_compare.py` to execute. The maintained entry point is now
  `scripts/benchmark-pulse-engine.py` and verifies binary hash and isolation.

`SHA256SUMS` protects the recovered files against accidental edits; it is not
an independent signature attesting their historical authenticity. The saved
Jenkins API export recorded job `shapoclyack-pr-491-pulse-comparison-linux`,
build **2**, result `SUCCESS`, head `c0352ad…`, duration 443726 ms, and an
artifact inventory including per-pass raw JSON, stdout/stderr and PCAPs.
The live job/archive has since expired. Original PCAPs and per-pass raw engine
outputs were not present in the surviving local export and are **not supplied**.
Traffic aggregates cannot replace independent PCAP inspection.

Recompute metrics without Pulse or Jenkins:

```sh
python scripts/summarize-pulse-engine.py docs/benchmarks/pulse-engine-20260929/results.json
```

For historical replay, prepare `/bench/before` and `/bench/after` with `git
archive` of the exact revisions above. Build the latter's Dockerfile with
`INSTALL_NMAP=0` and its reviewed Pulse 1.1.0 tarball pin. Add tcpdump,
libcap2-bin and openssl, grant tcpdump file capabilities, and create a writable
`/bench/results` for UID 1000. Credentials belong only in the build secret.
Then run the maintained harness in that image:

```sh
docker run --rm --network none --cap-add NET_RAW --cap-add NET_ADMIN \
  --user 1000:1000 -e HOME=/tmp -v "$PWD/bench:/bench" \
  --entrypoint python comparison-image /bench/benchmark-pulse-engine.py \
  --output /bench/results --before-source /bench/before --after-source /bench/after \
  --binary-sha256 f2446440b84a7bcbe29e31c5cfbe1901fa84a4a4401774becf91f39669ad5e46 \
  --repeats 5
```

The historical image used Linux x86_64, five alternating orders, HTTP on
127.20.0.1:8080, TLS on 127.20.0.2:8443, SSH banner on 127.20.0.3:2222;
homogeneous used HTTP :8080 on all three; partial_closed did not start SSH.
The generated self-signed TLS key is a fixture secret: do not publish it.
Neither banners nor OS inference authenticate a real OS or vulnerable service.
CVE correlation was disabled; TLS coverage here means certificate collection,
not cipher enumeration, STARTTLS, JARM parity, or exploit verification.

The original profile was concurrency 16, rate 100, host parallel 3, timeout
300 ms, adaptive off, banner/OS on, SYN/CVE/online CVE off, process timeout
90 s, command retries 0 and settle delay 0. It did not exercise retry,
crash, packet loss or cold/warm enrichment variants. No global stage deadline
or universal throughput claim follows from these samples.

The fixture supplies approved discovery endpoints directly; Naabu itself is
not timed or executed in this comparison. Full-pipeline acceptance is separate.
