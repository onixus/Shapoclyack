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
- addresses per second and probes per second (swept addresses × ports / wall time);
- packets sent and packets per second: what the farm's end of the link
  received while the tool ran. That is the tool's probes plus the scanner
  namespace's RSTs to SYN-ACKs and, for masscan, about ten ICMP replies a
  second to the wake-up datagrams (see below).

The summary reports median, minimum and maximum. A run that exits non-zero or
passes its deadline (five times the sweep at the configured rate, plus two
minutes; masscan's sweep is counted five times longer, as it sends that much
more) counts as failed, not as a sample. So does a naabu run whose output has
lines but no JSON at all: that is a changed format, not recall 0. A masscan still running 15 s past
its `--wait` window is killed and counts as failed too. If the farm process
exits mid-scenario the run stops: every later sample would score an empty farm
as a scanner miss.

## Tools

| Name | Command | Why |
|---|---|---|
| `naabu-syn` | `naabu -s s` | What the product asks for first |
| `naabu-connect` | `naabu -s c` | What the product falls back to when SYN finds nothing (`scanner/pipeline/ports.py`) |
| `masscan` | `masscan --rate` | The usual "fastest" reference |

All three are asked for no host discovery, one retry and the same rate. What
they send for it differs: on the stand, masscan sent 3.8–4.5 times as many
packets as naabu for the same sweep (251 000 at 1 000 pps and 297 000 at
10 000 pps against naabu's 65 700 for 65 536 probes), so compare its wall time
with `packets_sent` beside it, not as the same workload. A tool that
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
binaries, rate, warnings; written before the first run), `results.json`
(every repetition with its argv, rewritten after each one so an interrupted
scenario keeps what it scored), `summary.json`, the raw tool output and
stderr, and `SHA256SUMS`. The wrappers' `source-commit.txt` ends in `-dirty`
when the tree had uncommitted changes.

## Stand

The cloud runs cannot install Debian packages or pull the release images, so
SYN with the library the image would ship, masscan, and full scale run on a
test stand. Any Linux host with Docker and root will do:

```bash
scripts/run-speed-benchmark-stand.sh /srv/bench/speed-$(date +%Y%m%d)
# RATES='1000 10000 100000' REPEATS=5 SCALE=small by default
```

It builds `docs/benchmarks/speed/Stand.Dockerfile`: the released scanner image
by digest, plus `libpcap0.8` (the Debian package a SYN fix would add, #594),
`masscan` and `pyroute2`. The image defaults to the unprivileged `scanner`
account. The stand wrapper explicitly selects `--user 0:0` together with
`--network none --privileged` for namespace creation: dense at every rate,
then sparse and all-ports at the
highest one. The container has only loopback, and the harness's two namespaces
are joined to each other and to nothing else.

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

**masscan waits for a packet to notice it is done.** Its receive thread sleeps
in libpcap until a packet arrives and only then sees that its `--wait` window
is over. The farm's link is otherwise silent, so masscan 1.3.2 stayed up 20–130 s
past the window on the stand and was timed for it. While masscan runs, the farm
sends the scanner's end of the link a UDP datagram every 100 ms.

**netem's queue has to hold the delay.** netem keeps delayed packets in a queue
of 1000 by default. naabu sends in bursts, and on the stand that queue dropped
52 537 of its 65 536 SYN probes at 10 000 pps under `--impaired`. The queue now
holds a million packets, and drops measured ~0.5 % per side for every scanner.

**netem is not in every kernel.** `--impaired` stops with a clear error when
the kernel has no netem qdisc.
