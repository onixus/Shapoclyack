# Local acceptance network and resource observations

`scripts/operator-observe.py` runs a bounded metadata collector alongside named
local containers. It first verifies that every attached network is Docker
`internal`, then starts a 64-MiB helper in each container's network namespace.
Helpers use the existing local Python image by immutable image ID, a read-only
root, no Docker socket, and only `NET_RAW`. The controller snapshots its public
collector code into the helper's command arguments and records its SHA-256,
avoiding stale file-bind contents after atomic source edits. Helpers are removed at the
end, including error paths. Operator/model containers retain their own
unprivileged configuration.

```sh
python3 scripts/operator-observe.py --seconds 3600 \
  --container shapo-operator-inference-1 \
  --container shapo-operator-embeddings-1 \
  --image sha256:d0c3811794d5e8ba0ab27e32705c34410ca7e6208c6a34d32a57a9ef6af387bf \
  --output /private/tmp/operator-network-resources.json
```

For a fixed ingress proxy, explicitly use `--ingress-container NAME` instead of
`--container NAME`. This records its non-internal network as such and measures
traffic without claiming network deny for that proxy. Application, worker and
model namespaces use the default strict internal-network check.

The report contains packet counts grouped by IP addresses, protocol and
destination port; DNS packet counts; destinations outside the inspected local
subnets or loopback; Docker memory/CPU/I/O samples; host VM/compressor/swap
statistics; runtime image IDs, restart counters, OOM state and end-of-window
cgroup memory peak/events for running containers. Packet payloads,
HTTP requests, DNS names, credentials and completion text are never written.
Kernel packet-drop counts, receive errors and sampling errors are explicit and invalidate an unqualified
observation claim. A packet count of zero must not be confused with a working
capture: exercise a normal local request during the observation window.

`protocol: 6` means TCP and `17` means UDP. Both packet directions are counted;
the counters are observations, not unique application requests. ARP is counted
separately. IPv6 extension headers are not decoded into transport ports.
Resource collection has finite subprocess deadlines and five-second sampling;
short-lived peaks between samples can be missed. Container cgroup limits and
OOM/restart state supplement, rather than replace, sampled memory.

Run the collector before the measured requests and preserve its report with
the corresponding frozen evaluation and runtime integrity manifest. Runtime
startup logs and internal-network/DNS configuration provide separate startup
evidence: attaching to an already running namespace does not retrospectively
capture cold-start packets. Cold-start acceptance must name its actual capture
window and evidence scope.
