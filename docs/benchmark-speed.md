# Speed benchmark

How fast the port discovery stage sweeps a network, and how much of it it
finds, compared with masscan, the usual "fastest scanner" reference. The
harness is `scripts/benchmark-speed.py`; `scripts/run-speed-benchmark.sh` runs
the whole matrix. This page is the method. Results are not committed yet: a run
on a dedicated stand comes first, then a decision on what to publish.

## What it measures

For each tool and scenario, five or more repetitions of the same sweep at the
same configured packet rate, with the tool order rotated between repetitions:

- wall time, CPU time and peak RSS of the scanner process (`wait4`);
- recall and precision against the generated ground truth;
- addresses per second and probes per second (swept addresses × ports / wall time).

The summary reports median, minimum and maximum. A run that exits non-zero or
passes its deadline (five times the sweep at the configured rate, plus two
minutes) counts as failed, not as a sample.

## Tools

| Name | Command | Why |
|---|---|---|
| `naabu-syn` | `naabu -s s` | What the product asks for first |
| `naabu-connect` | `naabu -s c` | What the product falls back to when SYN finds nothing (`scanner/pipeline/ports.py`) |
| `masscan` | `masscan --rate` | The usual "fastest" reference |

All three run with no host discovery, one retry and the same rate. A tool that
is not installed is recorded as skipped. The binary path, SHA-256 and version
go into `metadata.json`. Nmap is not in the matrix: no code path in this
repository runs it (#97, [Migrating off Nmap](nmap-migration.md)), and the
benchmark keeps to that rule.

## Farm

Two fresh network namespaces, `shapo-speed-farm` and `shapo-speed-scan`,
joined by one veth pair (198.18.0.1/30 and 198.18.0.2/30). The scanner
namespace has no other interface. Its only route leads to the farm, and the
farm has no other interface either, so nothing a scanner sends can leave the
machine. Both namespaces are removed when the run ends or fails.

Targets come only from a plan generated from a seed inside 198.19.0.0/16
(RFC 2544 benchmarking space). The CLI takes no target arguments, and a plan
outside that range is refused. Live hosts are /32 addresses on the farm's
loopback with real listeners: port 22 sends an SSH banner, other ports send an
HTTP response. The rest of the range is a blackhole route, so a dead host is
silent rather than unreachable. Roughly 60 % of open ports are drawn from common service
ports and the rest uniformly from the scanned range, so a scanner gains
nothing by guessing popular ports.

## Scenarios

| Scenario | Full scale | Small scale | Ports | Open per live host |
|---|---|---|---|---|
| `sparse` | /16, 1 % live | /22, 5 % live | 1–1024 | 1–4 |
| `dense` | /22, all live | /26, all live | 1–1024 | 1–4 |
| `allports` | /26, all live | /30, all live | 1–65535 | 2–8 |
| `--impaired` | any of the above with 50 ms RTT and ~1 % loss (netem on both veth ends) | | | |

Small scale is for smoke runs and CI-sized machines. Full scale is for the
stand. A full `sparse` sweep is 67 M probes, about 11 minutes per repetition
at 100 kpps.

## Running

```bash
sudo SCALE=full RATE=100000 scripts/run-speed-benchmark.sh /srv/bench/speed-$(date +%Y%m%d)
# one scenario:
sudo python3 scripts/benchmark-speed.py run --scenario dense --scale small --output /tmp/speed-dense
# look at the generated ground truth:
python3 scripts/benchmark-speed.py plan --scenario sparse
```

The host needs root, `pyroute2`, `nsenter`, the scanners on `PATH`, libpcap
for `naabu-syn` (see below) and `CONFIG_NET_SCH_NETEM` for `--impaired`. Each
output directory holds `ground-truth.json`, `metadata.json` (host, kernel,
binaries, rate, warnings), `results.json` (every repetition with its argv),
`summary.json`, the raw tool output and stderr, and `SHA256SUMS`.

## Known findings

**naabu SYN needs libpcap at run time.** naabu 2.6.1 built with
`CGO_ENABLED=0` loads `libpcap.so` with `dlopen` for its SYN listener. Without
the library it sends the SYNs, sees no replies, exits 0 and reports nothing.
In the farm with no libpcap, `naabu-syn` had recall 0 in every repetition
while `naabu-connect` had recall 1.0. With libpcap present, `naabu-syn` found
between 0.57 and 0.85 of the open ports at 1–10 kpps, with misses scattered
across hosts. That gap is on the receive side, inside the scanner process:
the farm's TCP counters show every probe arriving and every SYN-ACK sent, and
the scanner namespace's counters show every SYN-ACK arriving (and answered with
a RST), but naabu's debug log shows its transport reader receiving only the
ports it then reports. `-retries 3` brings recall to 0.99–1.0 at three times
the wall time. Those runs used a libpcap build from PyPI, not Debian's
`libpcap0.8`, so the stand has to repeat them with the library the image would
ship before anything is concluded. The harness records whether libpcap was found (`metadata.json` → `host.libpcap`)
and warns when `naabu-syn` runs without it. The 2026-10-15 port discovery
benchmark recorded the same empty root SYN result on loopback.

**naabu reads stdin when it is not a terminal.** Started with an inherited
pipe as stdin, naabu waits for targets on it and sometimes fails with `Could
not run enumeration: Timeout` and no results. The harness gives every tool an
empty stdin.

**netem is not in every kernel.** `--impaired` stops with a clear error when
the kernel has no netem qdisc.
