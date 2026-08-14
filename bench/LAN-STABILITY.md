# LAN scan stability comparison

Decides one question before any infrastructure is moved: **is the host's network
stack losing scan results, or is the network itself?**

## Why

On the macOS/Docker Desktop lab the pipeline's port stage intermittently reports
zero open ports for hosts that demonstrably have them. Identical commands
repeated minutes apart disagreed: the same four hosts and eight known-open ports
returned `1` on one pass and `8` on the next. Every single-variable explanation
tried so far (scan rate, probe volume, host count, SYN vs CONNECT, capabilities,
conntrack) failed to reproduce on retest.

That leaves two possibilities, and they lead to opposite decisions:

| If | Then |
|---|---|
| A Linux host with a real NIC on the same segment is stable, macOS is not | The host network stack is the cause — moving the scanner is justified |
| Both scatter the same way | The runtime is not the cause — migrating changes nothing, look at the network |

A single measurement cannot tell these apart, because a single measurement is
exactly what has been misleading all along. This harness measures the **spread**
over repeated identical runs.

## Running it

Same targets, same repeat count, once per environment:

```bash
# on the macOS / Docker Desktop host
bench/lan-stability.sh --targets hosts.txt --repeats 5 --label mac-docker

# on a Linux box with a real NIC on the same LAN segment
bench/lan-stability.sh --targets hosts.txt --repeats 5 --label linux-native
```

`hosts.txt` is one IP per line. Keep it to roughly a dozen hosts — ground truth
costs one scan per host per repeat. Pick hosts you know have open ports, and
that you are authorised to scan.

Needs bash, awk and sort, plus either `naabu` on `PATH` or `docker` (it then
runs naabu from the scanner image; override with `--image` or `LANBENCH_IMAGE`).
A local naabu is preferred so that nothing about the measurement runs inside a
container on the host under suspicion.

## Reading the output

Ground truth is built from per-host scans — the one mode that stayed consistent
while everything else scattered — unioned across repeats. `recall%` is the share
of those endpoints each scenario recovered.

```
scenario           recall%  per-repeat recall%
S1_per_host        100      100 100 100 100 100
S2_batch_r2000     37       12 100 25 37 12   <-- unstable
```

| Scenario | What it isolates |
|---|---|
| `S1_per_host` | Control — one host per invocation |
| `S2_batch_r2000` | What the pipeline's port stage actually runs |
| `S3_batch_r500` | Same batch, gentler rate |
| `S4_batch_known` | Batch with tiny probe volume (known-open ports only) |
| `S5_batch_connect` | Same batch, CONNECT instead of SYN |

**Compare the spread between environments, not the medians.** A median of 40%
built from `40 40 40` is a different problem from one built from `0 100 20`: the
first is systematic loss, the second is instability. `<-- unstable` marks any
scenario whose min and max differ by 25 points or more.

Repeats whose naabu invocation exited non-zero are **excluded** and counted as
`(N invalid)` rather than scored as zero recall — a broken runner and a lossy
network are the two things this harness must never conflate. A scenario with no
valid repeats reports `n/a`.

Scenario order rotates by one position each repeat. Running all of S1 before all
of S2 would confound scenario with elapsed time, and on a path that degrades
during the run whatever went last would look worst regardless of technique.

Each run also writes `lan-stability-<label>-<timestamp>.json`, carrying per
scenario `runs`, `invalid`, and the run-wide `failed_runs`, for diffing.

## Interpreting the comparison

- **S1 stable everywhere, S2 unstable only on macOS** — the host stack cannot
  sustain multi-host scanning. Move the scanner to Linux.
- **S2 unstable in both** — not the runtime. Look at the segment: switch, AP
  client isolation, router scan protection, or a VPN policy-routing the LAN.
- **Everything stable on Linux including S2** — migrate, and keep this harness
  as the regression check.
- **Ground truth itself comes back empty** — that host cannot reach the targets
  at all; fix reachability before drawing any conclusion from the rest.

## Known confounders in the current lab

- The Mac's default route is a VPN tunnel (`utun4`) and the Mac itself cannot
  reach the LAN, while the Docker VM can. Re-run with the VPN disconnected
  before trusting a macOS baseline.
- `192.168.68.1` (the router) answers host discovery but stopped answering TCP
  probes from this source partway through testing — consistent with scan
  protection blocking the source. Exclude it from `hosts.txt`, or its zeros will
  be read as host-stack loss.
