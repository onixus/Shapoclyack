# Kubernetes hardening and Pod Security

What the manifests in `k8s/shapoclyack/` enforce about the pods they run, every
place they deviate from that and why, and how to carry the same exceptions into
Kyverno or Gatekeeper
([#338](https://github.com/onixus/Shapoclyack/issues/338)).

The short version: scanning needs raw sockets, raw sockets need `NET_RAW`, and
`NET_RAW` is outside the Kubernetes Pod Security **baseline** — not only
outside *restricted*. So the pod that scans lives in a namespace of its own,
`network-scan-executor`, and holds nothing but its own provisioning key. Every
other pod — the API, the databases, the backup and enrichment jobs — runs in
`network-scan`, which *enforces* `baseline`, and every one of them passes
`restricted`.

## Contents

- [The baseline every workload meets](#the-baseline-every-workload-meets)
- [Namespaces and Pod Security levels](#namespaces-and-pod-security-levels)
- [Workloads](#workloads)
- [Deviations from restricted](#deviations-from-restricted)
- [The scanner-executor](#the-scanner-executor)
- [Traffic between the executor and the API](#traffic-between-the-executor-and-the-api)
- [Enrolling the scanner-executor](#enrolling-the-scanner-executor)
- [Kyverno and Gatekeeper](#kyverno-and-gatekeeper)
- [Local execution](#local-execution)
- [What changes](#what-changes)
- [Upgrading](#upgrading)
- [Rolling back](#rolling-back)
- [Verifying on a cluster](#verifying-on-a-cluster)
- [How this is checked](#how-this-is-checked)

## The baseline every workload meets

Every pod template in `base/`, `overlays/*` and `examples/` — and every new one
added by any branch — carries:

| Field | Value | Why |
|---|---|---|
| `spec.automountServiceAccountToken` | `false` | Nothing here calls the Kubernetes API: scheduler leadership is a Postgres advisory lock (`api/services/leader_lock.py`), not a Lease. A mounted token is a credential an RCE gets for free. Set on the pod as well as the ServiceAccount, so moving a pod to another account does not bring one back. |
| `spec.securityContext.seccompProfile.type` | `RuntimeDefault` | The container runtime's syscall filter. Required by `restricted`. |
| `spec.securityContext.runAsNonRoot` | `true`, with an explicit non-zero `runAsUser`/`runAsGroup` | The images' own users: 1000 (`octo` in the aio and API images), 999 (Postgres), 101 (ClickHouse). |
| `containers[*].securityContext.allowPrivilegeEscalation` | `false` | Sets `no_new_privs`: no setuid, no file capabilities on exec. |
| `containers[*].securityContext.capabilities` | `drop: [ALL]`, nothing added | A non-root process has no use for the runtime's default set. |
| `containers[*].securityContext.readOnlyRootFilesystem` | `true` | Every path a process writes is a declared volume — listed below — so an attacker cannot drop a binary into the image, and a full disk is a sized `emptyDir` evicting one pod rather than a node filling up. |

`tests/test_k8s_pod_security.py` renders base and every overlay and fails on any
pod that does not meet this table, unless the deviation is in its
`EXCEPTIONS` list — each entry with its reason, each required to still be
needed and to be named in this document.

## Namespaces and Pod Security levels

[Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
is set per namespace, by label:

| Namespace | `enforce` | `audit` / `warn` | Holds |
|---|---|---|---|
| `network-scan` | `baseline` | `restricted` | API, Postgres, NATS, ClickHouse, backup and enrichment CronJobs, every Secret of the control plane |
| `network-scan-executor` | `privileged` | `restricted` | `shapoclyack-scanner-executor` and nothing else |

Three facts from the [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
decide this layout:

1. **`baseline` does not allow `NET_RAW`.** Its capability allow-list is
   `AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD,
   NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT`
   (`check_capabilities_baseline.go` in k8s.io/pod-security-admission).
   `NET_RAW` is in Docker's and containerd's *default* set, which is a common
   source of confusion, but not in this list. `NET_ADMIN` and `hostNetwork`
   are outside it too.
2. **Built-in Pod Security Admission has no per-pod exception.** Exemptions
   exist only in the API server's `AdmissionConfiguration`, by username,
   RuntimeClass or namespace — cluster configuration, not something a manifest
   can carry. A pod that needs more than `baseline` therefore needs a namespace
   whose `enforce` level allows it.
3. **`audit` and `warn` do not have to match `enforce`.** Both namespaces audit
   and warn at `restricted`, so every `kubectl apply` prints — and the audit
   log records — each pod that is not `restricted`, which for a default install
   is exactly the executor, with exactly the deviations listed below.

`network-scan` enforces `baseline` rather than `restricted` although everything
we ship there passes `restricted`: an installation's own additions (a sidecar, a
third-party exporter, `examples/maddy-deployment.example.yaml`) are then warned
about instead of refused on the first apply. Raising it is one label, once
`kubectl label --dry-run=server` says nothing would be rejected:

```bash
kubectl label --dry-run=server --overwrite ns network-scan \
  pod-security.kubernetes.io/enforce=restricted
kubectl label --overwrite ns network-scan pod-security.kubernetes.io/enforce=restricted
```

The level labels carry no `-version`, i.e. `latest` of the cluster's own
Kubernetes version. Pin `pod-security.kubernetes.io/enforce-version` in an
overlay if a cluster upgrade must not change what is admitted.

## Workloads

Where each pod runs, as whom, and every path it may write — the whole list; the
root filesystem is read-only everywhere except where noted.

| Workload | Namespace | Runs as | Writable paths | `restricted`? |
|---|---|---|---|---|
| `Deployment/shapoclyack-api` (+ init `migrate`, `fetch-enrichment`) | `network-scan` | 1000:1000 | `scanner/output`, `scanner/state` (PVC `scanner-data`); `/tmp` (2Gi: request bodies Starlette spools to disk — a sensor's run archive among them — and the SSH deployer's key/known_hosts files); `/home/octo` (nuclei/dnsx, probed for `GET /api/system`, write `~/.config/<tool>` or exit); `scanner/data` (PVC `enrichment-data`, init container only, with base/enrichment) | yes |
| `StatefulSet/shapoclyack-postgres` | `network-scan` | 999:999 | PGDATA (PVC); `/var/run/postgresql` (socket + lock); `/tmp` (the image's entrypoint fakes a passwd entry for uid 999 with nss_wrapper in two `mktemp` files on first init) | yes |
| `StatefulSet/shapoclyack-nats` | `network-scan` | 1000:1000 | `/data` (JetStream store, PVC). The entrypoint only rewrites argv. | yes |
| `StatefulSet/shapoclyack-clickhouse` | `network-scan` | 101:101 | `/var/lib/clickhouse` (PVC: data, tmp, preprocessed configs); `/tmp` (the entrypoint copies users.xml there to diff it); `/etc/clickhouse-server/users.d` (it generates `default-user.xml`). File logging is removed from the config (console only), so `/var/log/clickhouse-server` is not written. | yes |
| `CronJob/shapoclyack-postgres-backup` | `network-scan` | 1000:1000 | `/backup` (emptyDir handed from `pg_dump` to the uploader); `/tmp` (the AWS CLI's `HOME`) | yes |
| `CronJob/shapoclyack-clickhouse-backup` ([#333](https://github.com/onixus/Shapoclyack/issues/333)) | `network-scan` | 101:101 | `/tmp` (16Mi in memory: `clickhouse-client`'s `HOME`/`TMPDIR` and the script's `mktemp -d` for query output; the server itself uploads the backup, so nothing is staged here) | yes |
| `CronJob/enrichment-refresh` (base/enrichment) | `network-scan` | 1000:1000 | `scanner/data` (PVC `enrichment-data`); `/tmp` (the geoip/asn/epss/kev fetchers download into `mktemp -d`) | yes |
| `CronJob/enrichment-bundle-load` (base/enrichment-bundle, [#339](https://github.com/onixus/Shapoclyack/issues/339)) | `network-scan` | 1000:1000 | `scanner/data` (PVC `enrichment-data`: the bundle is staged and installed there, so the swap is a rename on one filesystem); `/tmp`; the inbox PVC is mounted read-only | yes |
| `StatefulSet/shapoclyack-scanner-executor` | `network-scan-executor` | 1000:1000 | `scanner/output`, `scanner/state` (the run and its checkpoints); `/tmp` (the sensor's per-job workdir: target lists and the run archive before upload; the screenshot stage's browser profile); `/home/octo` (nuclei, naabu and dnsx write `~/.config/<tool>/config.yaml` on every start and exit when they cannot — projectdiscovery/goflags) | **no** — see below |
| `Job/network-scan`, `CronJob/network-scan-scheduled`, `Job/network-scan-resume` (base/local-scan only) | `network-scan` | 1000:1000 | as the executor, with `scanner/output`/`state` on the `scanner-data` PVC | **no** — see below |
| `StatefulSet/shapoclyack-agent` (examples, a sensor in another cluster) | yours, not `network-scan` | 1000:1000 | as the executor | **no** — see below |
| `CronJob/shapoclyack-audit-retention`, `Deployment/shapoclyack-audit-syslog-forwarder` (examples) | `network-scan` | 1000:1000 | `/tmp` (retention only) | yes |
| `Pod/enrichment-bundle-inbox` (examples, #339: applied for one copy, then deleted) | `network-scan` | 1000:1000 | `/inbox` (PVC `enrichment-bundle-inbox`, what `kubectl cp` writes); `/tmp` | yes |
| `Deployment/shapoclyack-maddy` (examples, lab only) | `network-scan` | root | not read-only | **no** — see below |

`PYTHONDONTWRITEBYTECODE=1` is set in every Shapoclyack image, so Python does
not try to write bytecode next to the read-only sources.

The API container and its `migrate` init container run the **API image**
(`ghcr.io/onixus/shapoclyack-api`, `Dockerfile.api`): the API, the web console
and the `scanner` package it reads configs and reports with, `openssh-client`
for the SSH deployer — and none of the scanner toolchain. The API does not scan
any more, so naabu, pulse and nmap with their file capabilities were attack
surface in the one pod that holds every credential. `fetch-enrichment` (with
base/enrichment) stays on the all-in-one image because its fetchers need
`curl`; so do the executor, the local-scan topology and the kind stands, which
load one locally built image for everything.

How the third-party paths were established rather than guessed: the Postgres
and ClickHouse image entrypoints were read at the versions the manifests pin
(docker-library `16/alpine`, ClickHouse `24.8` `docker/server/entrypoint.sh`);
`nats-server` 2.10, ClickHouse 24.8 (with the image's stock `config.xml` plus
our `config.d`/`users.d`) and PostgreSQL 16 were each started under `strace`
and every file opened for writing or created was listed. None writes outside
the paths above.

## Deviations from restricted

Every one, with the reason. Nothing else in the repository deviates, and the
test refuses anything new that does.

### `shapoclyack-scanner-executor` — `NET_RAW`, `NET_ADMIN`, `allowPrivilegeEscalation: true`

- **`NET_RAW`**: naabu's SYN discovery, pulse's SYN mode and OS fingerprint,
  nmap `-O` and fping's ICMP all open raw sockets.
- **`NET_ADMIN`**: not used by anything we know of at run time — but the
  images grant it, with `NET_RAW`, as a file capability
  (`setcap cap_net_raw,cap_net_admin+eip` in `Dockerfile` and
  `Dockerfile.allinone`), and a binary whose file capabilities include one
  missing from the bounding set **fails `execve` with EPERM**. Dropping
  `NET_ADMIN` here does not narrow the scanner, it stops naabu from starting.
  Removing it from the `setcap` line (and then from here) needs Pulse verified
  without it; that has not been done — see [What changes](#what-changes).
- **`allowPrivilegeEscalation: true`**: `false` sets `no_new_privs`, under which
  the kernel does not raise capabilities on exec — the non-root process would
  run naabu without raw sockets, silently.

Everything else in the baseline applies to it: seccomp `RuntimeDefault` (which
still allows `socket()` for `AF_INET`/`AF_INET6`/`AF_PACKET`; containerd's
profile blocks only `AF_ALG` and `AF_VSOCK`), non-root, `drop: [ALL]` before
the two adds, read-only image, no service-account token. A NetworkPolicy denies
it all ingress: it listens on nothing.

`allowPrivilegeEscalation: true` also lets a setuid-root binary run as uid 0,
so from the first release built after `shapoclyack-0.46-0922` the image has
none: `Dockerfile.allinone` clears every setuid and setgid bit after its last
package install (the Debian base brought `su`, `passwd`, `mount`, `chfn` and
the like, `openssh-client` `ssh-keysign`), sets `fping`'s capability itself
(its package falls back to setuid root when its own `setcap` fails), and fails
the build if `fping` is left without it. What escalation remains is the
scanners' `cap_net_raw,cap_net_admin` and nothing more. **The image these
manifests pin, `shapoclyack-0.46-0922`, predates this and still carries them**;
and CI builds `Dockerfile`, not `Dockerfile.allinone`, so these lines first run
in the release pipeline.

### `shapoclyack-scanner-executor` in `overlays/prod` — `hostNetwork: true`

`overlays/prod` scans from the node's own network, on nodes labelled
`workload=scanner` and tainted `scanner=true:NoSchedule`: L2/ARP discovery then
sees the node's segment rather than a veth, and SYN probes leave from the node
address without the CNI's SNAT and conntrack in the way. It is the widest
privilege in the repository: `NET_ADMIN` in the host's network namespace can
rewrite that node's routes and firewall. That is why the pool is tainted, and
why nothing else tolerates the taint any more — the API used to, to share a
ReadWriteOnce volume with the scan Jobs, and #338 ended that.

What the taint does not keep off those nodes: DaemonSets that tolerate every
taint — the CNI agent, log shippers, node-exporter. Those on the host network
share the executor's network namespace, so whatever they listen on at
`127.0.0.1` is the executor's localhost too. And a NetworkPolicy does not apply
to a host-network pod on most CNIs, so the egress policy suggested
[below](#egress) does not constrain the prod executor: the node's own firewall
has to.

### `overlays/local-scan` — `shapoclyack-api`, `network-scan`, `network-scan-scheduled`, `network-scan-resume`

The opt-in topology of [Local execution](#local-execution): the API runs scans
in its own container, and the scan Job/CronJob write straight onto the PVC the
API reads. All of them need the executor's three deviations, *inside*
`network-scan`, which therefore enforces `privileged`. `overlays/api-readonly`
takes the Job and CronJob from the same component (and so the same namespace
level) but patches its API back to `restricted`.

### `shapoclyack-agent` (examples) — as the executor

`examples/agent-deployment.example.yaml` is the executor for a cluster other
than the API's (a branch office, a customer segment), reaching the API over its
public URL. Same pod — a StatefulSet with the same identity, key file and
storage request — same deviations, same need for a namespace that does not
enforce `baseline`.

### `shapoclyack-maddy` (examples) — root, writable image

A lab-only SMTP sink. The upstream `foxcpp/maddy` image runs as root and has no
other user; it keeps `drop: [ALL]` with only `NET_BIND_SERVICE` (port 25) added,
no privilege escalation, seccomp and no token — `baseline`, not `restricted`.
Which paths it writes besides `/data` has not been verified, so its root
filesystem stays writable. Not for production.

## The scanner-executor

`base/scanner-executor/` is the sensor (`python -m agent`, `agent/worker.py`)
run in the cluster, and since #338 it is where every scan of a default
installation runs:

1. the API queues a job (`OCTO_JOB_EXECUTION_MODE=agent`, base's default now);
2. the executor claims it over HTTP (`POST /api/agent/jobs/claim`, polled every
   few seconds), runs `scanner.main` in its own container and uploads the run
   archive to `POST /api/agent/jobs/{job_id}/results`;
3. the API ingests the archive exactly as it does a remote sensor's.

It shares no volume with the API, reads no Secret of the control plane and holds
one credential: a tenant provisioning key, mounted as a file
(`OCTO_AGENT_PROVISIONING_KEY_FILE`, mode `0440`, readable through the pod's
`fsGroup`) and exchanged at start and on expiry for a short-lived agent JWT.
The worker reads the file again on every exchange, so a rotated Secret reaches
it without a restart, and starts the scanner without its own `OCTO_AGENT_*` and
`OCTO_NATS_*` variables, so neither the key nor a token lands in a tool's
environment, debug output or crash report. That is protection against leaking
it by accident, not against a compromised tool: the scan runs as the same user
(1000, `fsGroup` 1000), which can read the key file and `/proc/1/environ`.
Separating them needs the scan under another uid, which it is not today.

**The pinned image predates both.** The worker in `shapoclyack-0.46-0922` does
not know `OCTO_AGENT_PROVISIONING_KEY_FILE` and exits without a key, so the
StatefulSet also passes the same Secret key as `OCTO_AGENT_PROVISIONING_KEY`
until the pin moves past that release — a current worker prefers the file. It
does not declare the config overlay either; the API of that release does not
send one, so the two pins agree. Bump the two images together. Its configuration is `scanner-config`, generated
from the same `base/config/k8s.yaml` as network-scan's copy, so the two cannot
drift. It does **not** use NATS: HTTP claiming is a supported mode and not a
degraded one, and leaving NATS out keeps the broker's `agent` password out of
its namespace and port 4222 closed to it (`base/networkpolicy-datastores.yaml`
now admits only the API).

**What a job carries to it.** The executor scans with its own config file, so
the parts of a job that change the config travel with the job, as its **config
overlay** (`config_overlay.json` in the claim, passed to `scanner.main` as
`--config-overlay`): the scan intent's settings (`inventory` turns nuclei off
and cuts to the top 100 ports) and the console configurator's overrides. The
scanner merges the overlay onto its config at the point a local scan's merged
file would be read, and applies the tenant's scan policy after it, so an
override or an intent can shape a scan but never lift it above the tenant's
ceilings (#362). It accepts only the settings the configurator and the intents
can set (`scanner/pipeline/config_overlay.py`) and refuses the whole run on
anything else.

One installation-wide override now reaches every tenant's sensors, so for the
settings that decide how hard a sensor hits its network **the sensor's own
file stays the limit**: discovery and port rates, nuclei's rate limit and
concurrency, and nmap timing take the lower of the file's value and the
overlay's; nuclei's excluded tags are the union of the two, so an override
cannot re-enable `intrusive`, `fuzz` or `dos` templates a sensor excludes; and
screenshots run only where the sensor's file enables them. An overlay can make
a sensor gentler, never rougher — to make a sensor faster, raise its own file.
Stage switches (nuclei on or off, the organisation-profile stages) follow the
overlay, since that is what an intent is.

The capability is versioned with the set of settings the overlay may carry:
`config_overlay.v1`. A sensor that does not declare the version the API sends
is never handed such a job — the claim hands it the jobs it can run first, and
answers `426` only when nothing else is waiting — and the job stays queued for
one that can, flagged `sensor_unavailable` while no live sensor of the tenant
declares it. Three things deliberately do not travel: the NVD API key, a secret
the executor's scans do not use (its config leaves online CVE lookups off) —
give an executor that needs it its own `NVD_API_KEY`; the nuclei templates
directory, a path on the API's host; and a custom wordlist, a file of up to
megabytes held by the API, which `POST /api/jobs` refuses in agent mode rather
than ignoring.

**Identity.** It is a StatefulSet for its pod names, not for storage: each pod
sends its own name — `shapoclyack-scanner-executor-0`, `-1`, … — behind a
random prefix as its agent id (`OCTO_AGENT_ID` =
`$(OCTO_AGENT_ID_PREFIX)-$(POD_NAME)`), so it is the same agent in the fleet
view after a rollout, an eviction or a drain. The prefix is 64 random bits
generated at enrollment and kept in the executor's Secret (`agent_id_prefix`)
beside the key. Agent ids are unique across the installation and the pod names
are in these manifests, so without it any tenant admin could mint a key in
their own tenant and register `shapoclyack-scanner-executor-0` first — during
the window between the apply and the enrollment — and the executor would be
refused (`403`, "registered in another tenant") until a platform admin found
and deleted a row its own tenant cannot see. The prefix is not a secret, but it
does not exist before enrollment, and it is not rotated with the key: a new
prefix is a new agent, and so a way out of a quarantine for whoever can write
the Secret. The API refuses a token for an id
that is quarantined or disabled, so an operator's quarantine outlives the pod,
and a group set on the agent (#361) stays set. A PodDisruptionBudget lets
drains take one executor at a time. A drained or evicted executor still loses
the scan it was running: the run is on its `emptyDir`, and the job returns to
the queue when its lease (`OCTO_JOB_LEASE_SECONDS`) expires, to start again
from nothing.

Scale it with `replicas`; each replica claims its own jobs
(`FOR UPDATE SKIP LOCKED`). `overlays/agents` runs three under a VPA
(`base/agents/agent-vpa.yaml`) in `Initial` mode, which sizes pods when they
are created anyway: `Auto` would resize by evicting, and an evicted executor
drops the scan it is running. The container requests 8Gi of ephemeral storage
(limit 32Gi): its `emptyDir`s may hold 31Gi between them, and without a request
the scheduler would place it on a node with a few gigabytes free and let the
kubelet evict it later.

**One key serves one tenant.** A provisioning key belongs to a tenant, and an
agent claims only its own tenant's jobs. A single-tenant installation needs one
executor; an installation that used to rely on the API scanning for every
tenant runs one executor per tenant that scans (copy `base/scanner-executor/`
with another name and Secret, enrolled with that tenant's key) or gives each
tenant its own sensor. A tenant with no executor online is not refused scans:
its jobs are accepted and wait, flagged `sensor_unavailable` in the job list,
with a banner above the launcher and the System page's scan-execution tile
reading "no sensor online". When a tenant is deleted
([#325](https://github.com/onixus/Shapoclyack/issues/325)), delete its
executor and Secret as well: the purge reaches the API's stores, not the run
directories in the executor's `emptyDir`s, which go only with the pod.

**Scan state lives with the pod.** The delta baseline (`--delta` / the `delta`
intent) and the previous run the report diff compares against are under
`scanner/state` and `scanner/output`, both `emptyDir`: after a restart the next
delta run of a target is a full one and its report has no diff; with several
replicas, each keeps its own, so which baseline a run compares against depends
on which executor claimed it.

### Egress

Scanning needs egress to every target, so base ships no egress policy for the
executor. One thing it never needs is the cloud's instance metadata service,
which on most providers hands out the node's credentials to anything that can
reach `169.254.169.254`. Where the CNI enforces NetworkPolicy, deny it:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: shapoclyack-scanner-executor-egress
  namespace: network-scan-executor
spec:
  podSelector:
    matchLabels: {app.kubernetes.io/component: scanner-executor}
  policyTypes: [Egress]
  egress:
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
            except: [169.254.169.254/32]   # instance metadata
        - ipBlock:
            cidr: ::/0
            except: ["fd00:ec2::254/128"]  # the same on AWS over IPv6
```

Narrow the `cidr`s to the ranges the tenant's scope allows, plus the API's
Service, where that is known in advance. On `overlays/prod` this does nothing:
a host-network pod is outside NetworkPolicy on most CNIs.

### NATS for the executor

Not needed, but possible where the push latency matters: copy the `agent`
password into the executor's namespace, point `OCTO_NATS_URL` at the broker's
FQDN, and let the NATS ingress policy admit the namespace.

```bash
kubectl -n network-scan get secret shapoclyack-nats -o jsonpath='{.data.agent_password}' \
  | base64 -d | kubectl -n network-scan-executor create secret generic shapoclyack-nats-agent \
      --from-file=agent_password=/dev/stdin
```

```yaml
# overlay patch on StatefulSet/shapoclyack-scanner-executor, container executor
env:
  - name: NATS_PASSWORD
    valueFrom:
      secretKeyRef: {name: shapoclyack-nats-agent, key: agent_password}
  - name: OCTO_NATS_URL
    value: nats://agent:$(NATS_PASSWORD)@shapoclyack-nats-client.network-scan.svc:4222
---
# and in NetworkPolicy/shapoclyack-nats-ingress (base/networkpolicy-datastores.yaml),
# a second `from` entry on the 4222 rule:
- namespaceSelector:
    matchLabels: {kubernetes.io/metadata.name: network-scan-executor}
  podSelector:
    matchLabels: {app.kubernetes.io/component: scanner-executor}
```

The copied password has to be rotated with the original
([operations.md § Data-plane credentials](operations.md#data-plane-credentials)).

## Traffic between the executor and the API

By default the executor talks to `http://shapoclyack-api.network-scan.svc:8080`
— **plain HTTP across the cluster network**, like every other client of that
Service. This is a deviation, and what crosses the wire is not small: the
provisioning key on every exchange, the agent JWT on every call, and every
run's results on upload. Someone who can read traffic between the two pods — a
compromised node on the path, or a host-network pod on either node (on
`overlays/prod` the executor itself is one) — can replay the key and enroll an
agent of that tenant until the key is revoked or expires, and read the scan
results. A CNI that encrypts pod traffic (WireGuard in Calico or Cilium, IPsec)
closes this; the manifests cannot know whether yours does.

Base does not switch to TLS by default because it needs a certificate these
manifests cannot ship. The component that does is **`base/api-tls`**: the API
serves TLS itself (`OCTO_API_TLS_CERT`/`_KEY` from Secret `shapoclyack-api-tls`)
and the executor dials `https://` with verification against ConfigMap
`shapoclyack-api-ca` in its own namespace. `overlays/kind-dev` uses it with the
stand's development CA; for any other overlay:

```yaml
components:
  - ../../base/api-tls
```

with a certificate naming `shapoclyack-api.network-scan.svc` (cert-manager's
`Certificate` writes the Secret's shape) and its CA copied into the ConfigMap.
Whatever else talks to the Service then has to speak HTTPS to it too — an
ingress needs its backend protocol set (for ingress-nginx,
`nginx.ingress.kubernetes.io/backend-protocol: HTTPS`).
`tests/test_k8s_topology.py` fails any render in which the executor's scheme
does not match the API's.

## Enrolling the scanner-executor

The executor starts only once Secret `shapoclyack-scanner-executor` (key
`provisioning_key`) exists in `network-scan-executor`. Until then it waits in
`ContainerCreating` with a `FailedMount` event naming the Secret — deliberately:
a key is minted by the API after it is up, so it cannot ship with the
manifests, and a crash-looping pod says less than a missing Secret does. The
namespace is created by the apply, so the Secret comes after it.

1. Mint a key for the tenant the executor scans for, as an account with
   `tenant.credential.manage` (the tenant's admin, or the `token-admin` role).
   From the console: **Sensor Fleet → Deploy Sensor**, which shows the key
   once. Or:

   ```bash
   curl -sS -X POST https://scan.example.com/api/tenants/default/provisioning-keys \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"label": "in-cluster scanner-executor"}'
   ```

   The response carries `key` once; it is stored only as a hash. Mint it in
   the tenant the executor is to scan for — an agent only ever claims its own
   tenant's jobs.

2. Store it where the executor reads it:

   ```bash
   read -rs KEY   # paste the key; keeps it out of shell history and argv
   printf '%s' "$KEY" | kubectl -n network-scan-executor create secret generic \
     shapoclyack-scanner-executor --from-file=provisioning_key=/dev/stdin \
     --from-literal=agent_id_prefix="$(openssl rand -hex 8)"
   unset KEY
   ```

   `agent_id_prefix` is generated once, here, and kept for the life of the
   installation ([Identity](#the-scanner-executor)). With External Secrets,
   `examples/externalsecret.example.yaml` has the `ExternalSecret` for both.

3. The pod starts on its own (the kubelet retries), registers, and appears in
   **Sensor Fleet** as `<prefix>-shapoclyack-scanner-executor-0`, on the node's
   hostname.

On the kind stand `scripts/dev-up.sh` does steps 1–2 with the demo admin
account, once; an existing Secret is left alone.

### Key expiry and rotation

**The key expires, and the executor stops with it.** Keys expire after
`OCTO_PROVISIONING_KEY_TTL_DAYS` (default 90) from minting, and the executor
exchanges its key again every time it refreshes its token — so on that day it
stops taking scans, its jobs queue flagged `sensor_unavailable`, and it shows
stale in **Sensor Fleet**. **Users → Provisioning keys** shows every key's
expiry and marks the ones within 14 days of it (`GET
/api/tenants/{tenant}/provisioning-keys` reports `expires_at` and
`expires_soon`). An installation that would rather manage the key's lifetime
itself sets `OCTO_PROVISIONING_KEY_TTL_DAYS=0`, which mints keys that never
expire; that is an installation-wide policy, deliberately not a per-key
choice a tenant admin could make.

To rotate, before the old key expires:

1. Mint a new key in the same tenant (step 1 above).
2. Replace the key and **keep the prefix** — a new prefix is a new agent id:

   ```bash
   read -rs KEY
   PREFIX="$(kubectl -n network-scan-executor get secret shapoclyack-scanner-executor \
     -o jsonpath='{.data.agent_id_prefix}' | base64 -d)"
   printf '%s' "$KEY" | kubectl -n network-scan-executor create secret generic \
     shapoclyack-scanner-executor --from-file=provisioning_key=/dev/stdin \
     --from-literal=agent_id_prefix="$PREFIX" --dry-run=client -o yaml | kubectl apply -f -
   unset KEY
   ```

   or update the source an `ExternalSecret` reads. The kubelet updates the
   mounted file within a minute or two.
3. Revoke the old key. The executor's token, minted from it, is refused on its
   next call; the executor exchanges again, reading the file, and gets a token
   from the new key under the same agent id — the id is released to the new key
   because the old one is revoked (#308).
4. If the pod does not recover within a few minutes (the file was not updated,
   the Secret was replaced under another key name, or it runs the pinned
   `shapoclyack-0.46-0922` image, whose worker reads the key from the
   environment, once):
   `kubectl -n network-scan-executor rollout restart statefulset/shapoclyack-scanner-executor`.

Revoking before the Secret is updated makes the executor retry with the revoked
key until the file changes; nothing is lost, the jobs wait.

**After a tenant is suspended and resumed**
([tenant lifecycle](tenant-lifecycle.md), [#325](https://github.com/onixus/Shapoclyack/issues/325)): a suspension
revokes the tenant's provisioning keys unless it was asked to keep them, and a
resume does not bring them back. The executor holding that tenant's key keeps
retrying it after the resume, and the tenant's scans queue `sensor_unavailable`,
until it has a new one: mint a key and replace it as in step 2, keeping the
prefix.

## Kyverno and Gatekeeper

Both are cluster-wide policy engines that know nothing of the namespace labels
above; each needs its own exception, scoped as narrowly as it can express.

### Kyverno

`k8s/shapoclyack/examples/kyverno-policyexception.example.yaml`, against the
upstream [pod-security policies](https://github.com/kyverno/policies/tree/main/pod-security)
(`baseline` and `restricted` sets). Scoped by policy and rule, by namespace
*and* by name, so it covers the executor's pods and nothing later put beside
them. The `autogen-` rule names are the ones Kyverno generates for the
StatefulSet — an exception naming only the Pod rule admits the pod and blocks
the StatefulSet that creates it:

```yaml
apiVersion: kyverno.io/v2          # v2beta1 on Kyverno 1.11/1.12
kind: PolicyException
metadata:
  name: shapoclyack-scanner-executor
  namespace: network-scan-executor
spec:
  exceptions:
    - policyName: disallow-capabilities
      ruleNames: [adding-capabilities, autogen-adding-capabilities]
    - policyName: disallow-capabilities-strict
      ruleNames: [adding-capabilities-strict, autogen-adding-capabilities-strict]
    - policyName: disallow-privilege-escalation
      ruleNames: [privilege-escalation, autogen-privilege-escalation]
  match:
    any:
      - resources:
          kinds: [Pod, StatefulSet]
          namespaces: [network-scan-executor]
          names: ["shapoclyack-scanner-executor*"]
```

`overlays/prod`'s `hostNetwork` needs a second exception,
`disallow-host-namespaces`, in a file of its own —
`kyverno-policyexception-prod-hostnetwork.example.yaml` — so that it is applied
only where that overlay is. PolicyExceptions
must be enabled in the Kyverno install (`--enablePolicyException`; with
`--exceptionNamespace` set, create them in that namespace instead).

`overlays/local-scan` needs the same three exceptions for
`Deployment/shapoclyack-api`, `Job/network-scan` and
`CronJob/network-scan-scheduled` in `network-scan` (the CronJob's rules are the
`autogen-cronjob-*` ones). They are not shipped as a file: an exception for the
API pod is the thing #338 exists to remove, and writing one should be a
decision, not a copy.

### Gatekeeper

`k8s/shapoclyack/examples/gatekeeper-exemptions.example.yaml`, on the
gatekeeper-library pod-security-policy templates (`K8sPSPCapabilities`,
`K8sPSPAllowPrivilegeEscalationContainer`, `K8sPSPReadOnlyRootFilesystem`,
`K8sPSPHostNetworkingPorts`). Gatekeeper has no exception object — an exemption
is a constraint that does not match — so:

- **capabilities**: `drop: [ALL]`, nothing added, in `network-scan`; a second
  constraint for `network-scan-executor` allowing exactly `NET_RAW` and
  `NET_ADMIN`, still requiring `drop: [ALL]`. Narrower than excluding the
  namespace.
- **privilege escalation**: the template has no "allowed" parameter, so
  `network-scan-executor` is left out (`excludedNamespaces` on a cluster-wide
  constraint). `exemptImages` is not an alternative: the executor and the API
  run the same image.
- **read-only root filesystem**: no exemption; every Shapoclyack container
  passes.
- **host network**: off in both namespaces — `network-scan-executor` is
  `privileged` to Pod Security, so without this Gatekeeper would be the only
  thing standing between it and a host-network pod, and it would not be
  standing. For `overlays/prod`, `gatekeeper-prod-hostnetwork.example.yaml`
  replaces the executor namespace's constraint (same name) with one that allows
  it; apply it after the main file, every time. Forgetting it refuses the next
  executor pod — loudly, rather than widening the namespace.

Already running cluster-wide constraints of these kinds? Add
`network-scan-executor` to their `spec.match.excludedNamespaces` and apply only
`shapoclyack-capabilities-scanner-executor` from the file.

## Local execution

`overlays/local-scan` (the `base/local-scan` component) is the topology before
#338: `OCTO_JOB_EXECUTION_MODE=local`, the API running `scanner.main` as a
subprocess of its own container with `NET_RAW`/`NET_ADMIN` and
`allowPrivilegeEscalation: true`, the scan Job and weekly CronJob in
`network-scan` writing onto the shared `scanner-data` PVC, and `network-scan`
relabelled `enforce: privileged`. The executor is removed.

It exists because some things only work that way:

- **Custom wordlists** reach a scan only when the API runs it: `POST
  /api/jobs` refuses a `wordlist_id` in agent mode rather than ignoring it.
  (Config overrides and scan intents reach the executor as the job's config
  overlay — [above](#the-scanner-executor).)
- **A CronJob scan driven by the `scan-targets` Secret.** In the default
  topology a recurring scan is an API schedule (`POST /api/schedules`), which
  also gives it a job row, a tenant and that tenant's notification channels —
  the CronJob path never had those
  ([configuration.md](configuration.md), notification channels).
- **A single-node lab** where one pod is the point.

What it costs is what #338 removes: an RCE in the API becomes an RCE with raw
sockets, next to the JWT secret, the database password and every tenant's data,
in a namespace that no longer enforces anything. Use it deliberately:

```bash
kubectl apply -k k8s/shapoclyack/overlays/local-scan
# apply prunes nothing: the executor from the default topology keeps running,
# and keeps its raw sockets, until it is deleted.
kubectl delete namespace network-scan-executor --ignore-not-found
```

To combine it with another overlay, list the component there:

```yaml
components:
  - ../../base/local-scan
```

The CronJob in this topology reads GeoIP/CVSS4 from the image, not from
`base/enrichment`'s volume (the API's own local scans do read the volume, since
they run in the API container that mounts it). Its old enrichment patch left
with it; an overlay combining both components can patch the CronJob with the
same volume and `OCTO_GEOIP_DATABASE`/`OCTO_CVSS4_DATABASE` as
`base/enrichment/api-enrichment-patch.yaml` gives the API.

## What changes

For an installation moving from a pre-#338 release:

- **Scans run in the executor**, which needs a provisioning key before it starts
  ([Enrolling](#enrolling-the-scanner-executor)). Until it has one, jobs are
  accepted and stay `queued`, flagged `sensor_unavailable` (a banner above the
  scan launcher and "no sensor online" on the System page say the same).
- **One executor serves one tenant**, the one its key belongs to, and **it
  stops when that key expires** (90 days by default). Other tenants' scans
  queue flagged the same way until they have an executor of their own; the key
  list shows each key's expiry ([Key expiry and rotation](#key-expiry-and-rotation)).
- **Jobs carry their config.** The scan intent and the configurator's
  overrides reach the executor as the job's config overlay; an agent that
  predates it is not handed such jobs (`426` when nothing else is waiting)
  until upgraded. External sensors must be upgraded with the API. The NVD key,
  the templates directory and custom wordlists do not travel
  ([above](#the-scanner-executor)). **Review the configurator's overrides
  before upgrading**: they used to stop at the API in agent mode, and now reach
  every tenant's remote sensors — bounded by each sensor's own rates, timing,
  nuclei exclusions and screenshot setting, but otherwise as written.
- **Delta and report-diff baselines live in the executor's `emptyDir`**: a
  restart makes the next delta run a full one, and each replica keeps its own.
- **Queued jobs are claimed oldest first, per tenant**, whatever built up while
  no executor was enrolled; a schedule that fired meanwhile is one job each
  time, not a backlog of one per interval (an overlapping run is skipped). The
  maintenance calendar is checked when a scan is started, not again when the
  executor claims it (docs/api-and-rbac.md), so a job queued before a window
  opened can still run inside it — cancel what should not.
- **The API runs the API image**, without the scanner toolchain
  ([Workloads](#workloads)).
- **The scan Job and CronJob are gone from base.** `kubectl apply` does not
  delete them (no pruning): remove `Job/network-scan` and
  `CronJob/network-scan-scheduled` by hand, and move the schedule to
  `POST /api/schedules` — or apply `overlays/local-scan`.
- **`overlays/prod` no longer pins the API to the scanner pool.** Only the
  executor goes there now, on the host network. Its API is rolled with
  `strategy: Recreate`: unpinned, a surging rollout would schedule the new pod
  on another node, where the ReadWriteOnce `scanner-data` cannot attach while
  the old pod holds it, and stall. Every rollout of it is a short outage of the
  console and API; executors keep scanning and retry their uploads.
- **`overlays/agents` scales the executor** instead of deploying its own
  `shapoclyack-agent` Deployment, which — having no namespace — landed in
  whatever namespace the kubeconfig pointed at. Delete the old Deployment and
  VPA from there. In-cluster sensors no longer use NATS (above).
- **ClickHouse lost `SYS_NICE`** (outside `baseline`). It only served
  `os_thread_priority`, which nothing sets; the server logs the missing
  capability at start and carries on. It also logs to the console only now.
- **The System page** runs the image's scanner binaries for their versions. In
  the API container naabu and pulse cannot be executed any more (EPERM, above);
  in agent mode every tool is shown as not required of this container, with
  that reason, instead of as broken.
- **Scanner-side GeoIP/CVSS4 come from the image.** The executor cannot mount
  `base/enrichment`'s volume (a PVC is mounted from its own namespace only), so
  the scanner's GeoIP and CVSS4 lookups use the data baked into the image at
  build time. The API's EPSS/KEV/CVSS4 scoring still reads the refreshed volume.
- **Features that need local execution** are listed under
  [Local execution](#local-execution).

Not done here, and why:

- **`NET_ADMIN` is still granted.** Whether Pulse needs it cannot be tested
  without the private Pulse build; until it is, dropping it from `setcap` would
  risk breaking OS fingerprinting in every image.
- **The sensor never deletes finished runs** from `scanner/output`
  (`agent/worker.py`). On the executor the directory is an `emptyDir` sized to
  evict the pod before the node fills, which empties it; a systemd-installed
  sensor grows without bound.

## Upgrading

```bash
# 0. Anything in network-scan the new label would refuse (read the warnings):
kubectl label --dry-run=server --overwrite ns network-scan \
  pod-security.kubernetes.io/enforce=baseline

# 1. Apply. network-scan is relabelled enforce=baseline in the same apply (Pod
#    Security never evicts running pods, it only refuses new ones), and
#    network-scan-executor is created. overlays/prod rolls its API with
#    Recreate, so the RWO volume detaches before the new pod needs it.
kubectl apply -k k8s/shapoclyack/overlays/<yours>

# 2. The executor's key and its agent-id prefix, now that its namespace
#    exists. The pod waits until then; scans started meanwhile queue.
#    See "Enrolling the scanner-executor". A Secret made from an earlier
#    draft of these docs lacks agent_id_prefix: add it, or the pod waits in
#    CreateContainerConfigError naming the key. Pulling from a private or
#    air-gapped registry, the pull secret is needed here too — a Secret is
#    namespaced (docs/air-gap.md, "The pull secret"):
#      kubectl -n network-scan-executor create secret docker-registry shapoclyack-registry \
#        --docker-server=<registry> --docker-username=<user> --docker-password=<token>

# 3. What apply does not prune.
kubectl -n network-scan delete cronjob/network-scan-scheduled job/network-scan --ignore-not-found
kubectl delete deploy,vpa shapoclyack-agent --ignore-not-found   # overlays/agents, wherever it landed

# 4. Sensors outside the cluster: upgrade them with the API. One that predates
#    the config overlay is refused jobs carrying an intent or overrides (426 in
#    its log, the job stays queued) until it is.
```

A tenant that scans and is not the one whose key the executor holds needs an
executor of its own (above) before its scans run again.

## Rolling back

To the release before #338: **re-apply that release's manifests**, the same
way they were applied, and delete what they do not know about.

```bash
git checkout <previous-release> -- k8s/
kubectl apply -k k8s/shapoclyack/overlays/<yours>
kubectl delete namespace network-scan-executor --ignore-not-found
```

`kubectl rollout undo deployment/shapoclyack-api` is **not** a way back: it
restores only the pod template — the API with `NET_RAW`/`NET_ADMIN` it had
before — into a namespace that still enforces `baseline`, which refuses the new
pods (`FailedCreate` on the ReplicaSet, "violates PodSecurity") while the
current pod keeps running. Re-applying the old release removes the
`pod-security.kubernetes.io/*` labels it never had (a client-side `apply`
removes fields its last-applied configuration held and the new one does not),
and the namespace is applied before the Deployment. If the labels were set some
other way, drop them first:

```bash
kubectl label ns network-scan pod-security.kubernetes.io/enforce- \
  pod-security.kubernetes.io/audit- pod-security.kubernetes.io/warn-
```

Jobs queued for agent execution in the meantime stay queued under a local-mode
API, which never claims them: cancel them and start them again. On
`overlays/prod` the rollback schedules the API back onto the scanner pool,
where its RWO volume has to follow it — scale the API to zero first, as the
pre-#338 upgrade notes said.

## Verifying on a cluster

What cannot be proven from this repository alone, and the command that proves
it on a real one:

```bash
# Nothing in network-scan would be refused even at restricted.
kubectl label --dry-run=server --overwrite ns network-scan \
  pod-security.kubernetes.io/enforce=restricted

# The executor's bounding set is NET_ADMIN (12) + NET_RAW (13) and nothing else,
# i.e. CapBnd 0000000000003000; the API's is 0000000000000000. getcap shows what
# the image hands naabu on exec.
kubectl -n network-scan-executor exec shapoclyack-scanner-executor-0 -- \
  sh -c 'grep CapBnd /proc/1/status; getcap /usr/local/bin/naabu'
kubectl -n network-scan exec deploy/shapoclyack-api -- grep CapBnd /proc/1/status

# No setuid binary in the executor's image; the key is a file, not in the
# environment, and its agent id is its pod name.
kubectl -n network-scan-executor exec shapoclyack-scanner-executor-0 -- \
  sh -c 'find / -xdev -perm /6000 -type f; env | grep -c PROVISIONING_KEY=; echo "$OCTO_AGENT_ID"'

# No service-account token anywhere.
kubectl -n network-scan exec deploy/shapoclyack-api -- ls /var/run/secrets/kubernetes.io 2>&1

# The image is read-only.
kubectl -n network-scan exec deploy/shapoclyack-api -- touch /app/x   # Read-only file system
```

Then a scan end to end: a job reaches `succeeded` with the run visible under
**Runs**, which exercises the executor's claim, its raw-socket tools under
seccomp, the upload through the API's `/tmp`, and ingest.

## How this is checked

- `tests/test_k8s_pod_security.py` renders base and every overlay with
  `kubectl kustomize`, or reads what `k8s/scripts/validate-kustomize.sh`
  rendered into `OCTO_K8S_RENDER_DIR` (the Jenkinsfile's Tests stage renders on
  the node and hands the directory to its kubectl-less Python containers).
  Without either it skips and says so — and under `OCTO_REQUIRE_INTEGRATION=1`,
  which CI sets, it fails instead. It asserts, per pod:
  admission by its namespace's `enforce` level, using a transcription of
  k8s.io/pod-security-admission's baseline and restricted checks; the
  repository baseline above, with `EXCEPTIONS` as the only way out; the API pod
  `restricted` everywhere but `overlays/local-scan`; the executor always, and
  alone, in `network-scan-executor`; a writable `/tmp` (and `$HOME` where the
  scanner's tools run) for every Shapoclyack container. The examples and
  `job-resume.yaml`, which nothing renders, are checked as files, and
  `examples/*-patch.yaml` may not loosen anything they patch. Every workload
  any of them renders has a row in [Workloads](#workloads), and every row a
  workload — so one added later (the ClickHouse backup of #333, the bundle
  loader and inbox pod of #339) is documented as well as held to the baseline.
- `tests/test_k8s_topology.py` holds the renders to their wiring: an API in
  agent mode has an executor to hand work to; the executor dials the API's
  Service in the API's namespace, over `https` exactly when the API serves TLS
  and against a CA it mounts; its key is a required Secret file, not an
  environment variable; it is a StatefulSet with `OCTO_AGENT_ID` from its pod
  name, a PDB and no evicting VPA; it requests the disk its `emptyDir`s may
  fill; a host-network pod keeps cluster DNS; the API runs the API image;
  `overlays/prod` rolls it with `Recreate`; each datastore can write every path
  its image writes; ClickHouse logs to the console only; the executor's image
  strips setuid bits. Each of these was a mutation of the manifests that the
  Pod Security checks let through.
- Independently, for #338: the upstream `k8s.io/pod-security-admission` library
  (v0.31.4) over every render; `kyverno apply` 1.13.4 with the upstream
  pod-security policy set, with and without the PolicyException example; and
  `gator test` 3.18.2 with the gatekeeper-library templates and the Gatekeeper
  example. The results are in the PR that introduced this document.
- `k8s/scripts/verify-networkpolicy.sh` (kind + Calico) probes the datastore
  policies, now including a pod in `network-scan-executor`.
