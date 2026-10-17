# Helm chart

`charts/shapoclyack/` packages the kustomize base (`k8s/shapoclyack/base`) as a
Helm chart ([#341](https://github.com/onixus/Shapoclyack/issues/341)). With its
default values it renders the same objects as the base; the overlays
(`prod-ha`, `agents`, `airgap`, ...) are not part of the chart, and the kustomize
tree stays the source of truth. Pick the packaging you deploy with, not both.

What the chart installs: the API Deployment, Postgres, NATS and ClickHouse
StatefulSets, the scanner-data PVC, the Postgres and ClickHouse backup CronJobs,
PodDisruptionBudgets, NetworkPolicies, ServiceAccounts, and the scanner-executor
StatefulSet in its own namespace. What it does not: the optional components
(`local-scan`, monitoring, enrichment, agents, API TLS), anything in
`k8s/shapoclyack/examples/`, and the Secrets the base also expects you to create
yourself (`shapoclyack-registry`, `scan-targets`, `shapoclyack-api-users`, the
S3 credentials, the executor's provisioning key).

## Install

The control plane goes into the release namespace; the chart creates the
executor namespace (`network-scan-executor`, Pod Security `privileged`, because
the executor holds `NET_RAW`/`NET_ADMIN`; see [Kubernetes hardening](k8s-hardening.md)).
Create and label the release namespace first. The release record is stored in
it, so the chart cannot create it for `helm install`:

```bash
kubectl create namespace network-scan
kubectl label namespace network-scan \
  pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

helm install shapoclyack charts/shapoclyack --namespace network-scan -f my-values.yaml
```

For tools that render with `helm template` (Argo CD, Flux), set
`namespaces.main.create=true` and the chart emits the labelled Namespace itself.

Credentials come first. The default values render the base's dev placeholders, and the
API refuses to start on the placeholder JWT secret unless `OCTO_ENV=dev`. Use one of:

- `existingSecrets.<name>`: the name of a Secret you created. Keys are the base's:
  `api` is `jwt_secret`, `postgres`, `clickhouse` and `clickhouseBackup` are `password`,
  `nats` is `api_password` and `agent_password`. The chart then renders no placeholder
  for that Secret and points every workload at yours.
- `externalSecrets.enabled=true`: External Secrets Operator (its CRDs must be installed)
  creates the Secrets from your store, one `ExternalSecret` each, under
  `<externalSecrets.remoteKeyPrefix>/<api|postgres|clickhouse|...>`, the same layout as
  `k8s/shapoclyack/examples/externalsecret.example.yaml`. The `shapoclyack-api-users`
  Secret (master key, console bootstrap) is not generated: ESO's `creationPolicy: Owner`
  needs the complete key list, so keep using that example for it.

The scanner-executor starts once the Secret `shapoclyack-scanner-executor` exists in its
namespace ([Kubernetes hardening](k8s-hardening.md), enrolling the executor).

## Values

| Value | Default | Purpose |
|-------|---------|---------|
| `replicas.api`, `replicas.scannerExecutor` | `1` | Datastores stay single-replica; clustering them is a configuration change, see [High availability](high-availability.md) |
| `storage.<scannerData\|clickhouse\|nats\|postgres>.size` / `.storageClass` | base sizes / cluster default | `scannerData.accessMode` must be `ReadWriteMany` for `replicas.api > 1` |
| `existingSecrets.*` | empty | See above |
| `externalSecrets.*` | disabled | See above |
| `ingress.*` | disabled | Host, class, annotations, TLS. TLS is not optional (#309) |
| `images.<api\|aio\|clickhouse\|nats\|postgres\|awscli>` | digest-pinned, as in the base | Set `digest: ""` to deploy by tag |
| `resources.*` | the base's requests and limits | One entry per workload |
| `networkPolicy.enabled` | `true` | The datastore and executor-namespace ingress rules |
| `podDisruptionBudget.enabled`, `backup.<postgres\|clickhouse>.enabled/schedule` | on | |
| `api.natsUrl`, `api.clickhouseUrl`, `api.extraEnv` | empty | The base leaves both URLs empty; examples in `values.yaml` |

`values.yaml` is commented per key. There is no value for real hosts or credentials
and none should be added: those belong in your own values file or Secret store.

## Keeping the chart equal to the base

`scripts/ci-helm.sh` runs `helm lint --strict` (defaults and with each switch on),
renders every switch, and compares the default render with `kubectl kustomize
k8s/shapoclyack/base` through `scripts/helm_parity.py`. The comparison is on parsed objects, not
bytes: the same set of (kind, namespace, name), each equal after dropping the
`managed-by` label and decoding Secret data. Everything else is compared in full,
including `securityContext`, `readOnlyRootFilesystem`, `automountServiceAccountToken`,
probes, volumes, images and NetworkPolicy rules, so a hardening change made on one
side only fails the check. `tests/test_helm_chart.py` runs the same comparison and
covers the switches.

The large ConfigMap payloads (scanner config, ClickHouse and NATS config, the backup
script) are plain files in `charts/shapoclyack/files/`, loaded with `.Files.Get`.
After editing their sources under `k8s/shapoclyack/base/`, run

```bash
scripts/ci-helm.sh --sync
```

and commit the result. Edits to a Deployment or StatefulSet in the base have to be
repeated in `charts/shapoclyack/templates/`; the parity check says where they differ.
Bump `version` in `Chart.yaml` with any chart change.

`ci-helm.sh` needs `helm` (3.12+ or 4.x), `kubectl` and PyYAML. It is not wired into the
Jenkinsfile: the Jenkins controller image (`jenkins-local/Dockerfile`) has `kubectl` but
neither `helm` nor PyYAML. To add it, install `helm` there (pinned, like `kubectl`) and
add `sh 'scripts/ci-helm.sh'` next to `validate-kustomize.sh` in the `Kustomize` stage; in
`.github/workflows/ci.yml` the `helm` job already runs it.

## Publishing as an OCI artifact (not set up)

Nothing here publishes yet, and no registry credentials are configured. The intended
route is `ghcr.io/onixus/charts`, next to the images ([Supply chain](supply-chain.md)):

```bash
helm package charts/shapoclyack --destination dist/
echo "$GITHUB_TOKEN" | helm registry login ghcr.io -u <user> --password-stdin
helm push dist/shapoclyack-<version>.tgz oci://ghcr.io/onixus/charts
cosign sign ghcr.io/onixus/charts/shapoclyack@<digest>   # same keyless policy as the images
```

Consumers then run `helm install shapoclyack oci://ghcr.io/onixus/charts/shapoclyack
--version <version>`. Doing it from CI means a publish job (the release path's
`shapoclyack-publish`) with a token that has `packages: write`, run after the
`ci-helm.sh` gate, with `Chart.yaml` `version`/`appVersion` set from the release tag.
