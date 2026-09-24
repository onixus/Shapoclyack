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
- [Enrolling the scanner-executor](#enrolling-the-scanner-executor)
- [Kyverno and Gatekeeper](#kyverno-and-gatekeeper)
- [Local execution](#local-execution)
- [What changes](#what-changes)
- [Upgrading](#upgrading)
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
| `CronJob/enrichment-refresh` (base/enrichment) | `network-scan` | 1000:1000 | `scanner/data` (PVC `enrichment-data`); `/tmp` (the geoip/asn/epss/kev fetchers download into `mktemp -d`) | yes |
| `Deployment/shapoclyack-scanner-executor` | `network-scan-executor` | 1000:1000 | `scanner/output`, `scanner/state` (the run and its checkpoints); `/tmp` (the sensor's per-job workdir: target lists and the run archive before upload; the screenshot stage's browser profile); `/home/octo` (nuclei, naabu and dnsx write `~/.config/<tool>/config.yaml` on every start and exit when they cannot — projectdiscovery/goflags) | **no** — see below |
| `Job/network-scan`, `CronJob/network-scan-scheduled`, `Job/network-scan-resume` (base/local-scan only) | `network-scan` | 1000:1000 | as the executor, with `scanner/output`/`state` on the `scanner-data` PVC | **no** — see below |
| `Deployment/shapoclyack-agent` (examples, a sensor in another cluster) | yours, not `network-scan` | 1000:1000 | as the executor | **no** — see below |
| `CronJob/shapoclyack-audit-retention`, `Deployment/shapoclyack-audit-syslog-forwarder` (examples) | `network-scan` | 1000:1000 | `/tmp` (retention only) | yes |
| `Deployment/shapoclyack-maddy` (examples, lab only) | `network-scan` | root | not read-only | **no** — see below |

`PYTHONDONTWRITEBYTECODE=1` is set in every Shapoclyack image, so Python does
not try to write bytecode next to the read-only sources.

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

### `shapoclyack-scanner-executor` in `overlays/prod` — `hostNetwork: true`

`overlays/prod` scans from the node's own network, on nodes labelled
`workload=scanner` and tainted `scanner=true:NoSchedule`: L2/ARP discovery then
sees the node's segment rather than a veth, and SYN probes leave from the node
address without the CNI's SNAT and conntrack in the way. It is the widest
privilege in the repository: `NET_ADMIN` in the host's network namespace can
rewrite that node's routes and firewall. That is why the pool is tainted, and
why nothing else tolerates the taint any more — the API used to, to share a
ReadWriteOnce volume with the scan Jobs, and #338 ended that.

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
public URL. Same pod, same deviations, same need for a namespace that does not
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
one credential: a tenant provisioning key, exchanged at start and on expiry for
a short-lived agent JWT. Its configuration is `scanner-config`, generated from
the same `base/config/k8s.yaml` as network-scan's copy, so the two cannot drift.
It does **not** use NATS: HTTP claiming is a supported mode and not a degraded
one, and leaving NATS out keeps the broker's `agent` password out of its
namespace and port 4222 closed to it (`base/networkpolicy-datastores.yaml` now
admits only the API).

It talks to `http://shapoclyack-api.network-scan.svc:8080` — plain HTTP inside
the cluster, as every other client of that Service does. `overlays/kind-dev`
switches it to HTTPS with verification against the stand's development CA.

Scale it with `replicas`; each replica claims its own jobs
(`FOR UPDATE SKIP LOCKED`). `overlays/agents` runs three under a VPA
(`base/agents/agent-vpa.yaml`).

**One key serves one tenant.** A provisioning key belongs to a tenant, and a
sensor claims only its tenant's jobs. A single-tenant installation needs one
key; an MSSP installation that used to rely on the API scanning for every tenant
runs one executor Deployment per tenant (copy `base/scanner-executor/` with a
different name and Secret) or gives each tenant its own sensor.

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
# overlay patch on Deployment/shapoclyack-scanner-executor, container executor
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

## Enrolling the scanner-executor

The executor starts only once Secret `shapoclyack-scanner-executor` (key
`provisioning_key`) exists in `network-scan-executor`. Until then it waits in
`CreateContainerConfigError` naming the Secret — deliberately: a key is minted
by the API after it is up, so it cannot ship with the manifests, and a
crash-looping pod says less than a missing Secret does.

1. Mint a key for the tenant the executor scans for, as an account with
   `tenant.credential.manage` (the tenant's admin, or the `token-admin` role).
   From the console: **Sensor Fleet → Deploy Sensor**, which shows the key
   once. Or:

   ```bash
   curl -sS -X POST https://scan.example.com/api/tenants/default/provisioning-keys \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"label": "in-cluster scanner-executor"}'
   ```

   The response carries `key` once; it is stored only as a hash. Keys expire
   after `OCTO_PROVISIONING_KEY_TTL_DAYS` (default 90) — rotate by minting a new
   one, replacing the Secret and revoking the old key.

2. Store it where the executor reads it:

   ```bash
   read -rs KEY   # paste the key; keeps it out of shell history and argv
   printf '%s' "$KEY" | kubectl -n network-scan-executor create secret generic \
     shapoclyack-scanner-executor --from-file=provisioning_key=/dev/stdin
   unset KEY
   ```

   With External Secrets, `examples/externalsecret.example.yaml` has the
   `ExternalSecret` for it.

3. The pod starts on its own (the kubelet retries), registers, and appears in
   **Sensor Fleet** under the node's name.

On the kind stand `scripts/dev-up.sh` does steps 1–2 with the demo admin
account, once; an existing Secret is left alone.

## Kyverno and Gatekeeper

Both are cluster-wide policy engines that know nothing of the namespace labels
above; each needs its own exception, scoped as narrowly as it can express.

### Kyverno

`k8s/shapoclyack/examples/kyverno-policyexception.example.yaml`, against the
upstream [pod-security policies](https://github.com/kyverno/policies/tree/main/pod-security)
(`baseline` and `restricted` sets). Scoped by policy and rule, by namespace
*and* by name, so it covers the executor's pods and nothing later put beside
them. The `autogen-` rule names are the ones Kyverno generates for the
Deployment and ReplicaSet — an exception naming only the Pod rule admits the pod
and blocks the Deployment that creates it:

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
          kinds: [Pod, Deployment, ReplicaSet]
          namespaces: [network-scan-executor]
          names: ["shapoclyack-scanner-executor*"]
```

The file has a second exception, `disallow-host-namespaces`, for
`overlays/prod`'s `hostNetwork` only — apply it only there. PolicyExceptions
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
- **host network**: off in `network-scan`; for `overlays/prod`, a
  `K8sPSPHostNetworkingPorts` with `hostNetwork: true` scoped to
  `network-scan-executor`.

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

- **Installation config overrides** (the console's configurator) and **custom
  wordlists** reach a scan only when the API runs it: a sensor scans with its
  own mounted config, and `POST /api/jobs` refuses a `wordlist_id` in agent mode
  rather than ignoring it. Scan-intent overlays (nuclei floors, `top_ports`)
  are skipped in agent mode likewise.
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
  ([Enrolling](#enrolling-the-scanner-executor)). Until it has one, jobs stay
  `queued`.
- **The scan Job and CronJob are gone from base.** `kubectl apply` does not
  delete them (no pruning): remove `Job/network-scan` and
  `CronJob/network-scan-scheduled` by hand, and move the schedule to
  `POST /api/schedules` — or apply `overlays/local-scan`.
- **`overlays/prod` no longer pins the API to the scanner pool.** Only the
  executor goes there now, on the host network.
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
# 1. The executor's key, before or after the apply (it waits for it).
#    See "Enrolling the scanner-executor".

# 2. overlays/prod only: the API moves off the scanner pool. Its RWO volume
#    can attach to one node at a time and the rollout surges before it drains
#    (maxUnavailable: 0), so let the old pod go first:
kubectl -n network-scan scale deploy/shapoclyack-api --replicas=0

# 3. Apply. The namespace is relabelled enforce=baseline in the same apply;
#    Pod Security never evicts running pods, it only refuses new ones.
kubectl apply -k k8s/shapoclyack/overlays/<yours>

# 4. What apply does not prune.
kubectl -n network-scan delete cronjob/network-scan-scheduled job/network-scan --ignore-not-found
kubectl delete deploy,vpa shapoclyack-agent --ignore-not-found   # overlays/agents, wherever it landed
```

Anything else in `network-scan` that the new label would refuse shows up in step
3's warnings and in `kubectl label --dry-run=server --overwrite ns network-scan
pod-security.kubernetes.io/enforce=baseline` beforehand.

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
kubectl -n network-scan-executor exec deploy/shapoclyack-scanner-executor -- \
  sh -c 'grep CapBnd /proc/1/status; getcap /usr/local/bin/naabu'
kubectl -n network-scan exec deploy/shapoclyack-api -- grep CapBnd /proc/1/status

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
  `kubectl kustomize` (skipped, and saying so, without it) and asserts, per pod:
  admission by its namespace's `enforce` level, using a transcription of
  k8s.io/pod-security-admission's baseline and restricted checks; the
  repository baseline above, with `EXCEPTIONS` as the only way out; the API pod
  `restricted` everywhere but `overlays/local-scan`; the executor always, and
  alone, in `network-scan-executor`; a writable `/tmp` (and `$HOME` where the
  scanner's tools run) for every Shapoclyack container. The examples and
  `job-resume.yaml`, which nothing renders, are checked as files, and
  `examples/*-patch.yaml` may not loosen anything they patch.
- Independently, for #338: the upstream `k8s.io/pod-security-admission` library
  (v0.31.4) over every render; `kyverno apply` 1.13.4 with the upstream
  pod-security policy set, with and without the PolicyException example; and
  `gator test` 3.18.2 with the gatekeeper-library templates and the Gatekeeper
  example. The results are in the PR that introduced this document.
- `k8s/scripts/verify-networkpolicy.sh` (kind + Calico) probes the datastore
  policies, now including a pod in `network-scan-executor`.
