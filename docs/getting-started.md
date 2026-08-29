# Getting started

This guide starts an all-in-one installation, validates its dependencies, and
runs the first authorized scan.

## Prerequisites

- Docker Engine (to build/load images), [kind](https://kind.sigs.k8s.io/), and `kubectl`;
- 4 GB free memory for evaluation, more when scanning large target sets;
- explicit authorization for every target.

Raw socket capabilities are required by some discovery modes. The Kubernetes
manifests add `NET_RAW` and `NET_ADMIN` to the scanner container (see the
[Kubernetes guide](../k8s/README.md) for the capabilities/`allowPrivilegeEscalation`
detail).

## 1. Clone

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack
```

`scripts/dev-up.sh` (below) uses the dev-only JWT secret baked into
`k8s/shapoclyack/base/kustomization.yaml`. For anything beyond a local kind
cluster, override it with `k8s/shapoclyack/examples/api-secrets.example.yaml`
(see the [Kubernetes guide](../k8s/README.md)) rather than exporting an env var.

The default users are for local evaluation only:

| User | Default password | Role |
|---|---|---|
| `viewer` | `viewer-change-me` | viewer |
| `operator` | `operator-change-me` | operator |
| `admin` | `admin-change-me` | admin |

Do not bind the demo configuration to a public address. These accounts are
seeded into the `users` table only when the API runs with `OCTO_ENV=dev`, which
the `dev`/`kind-dev` overlays set and `scripts/dev-up.sh` therefore inherits.
Anywhere else the API refuses to start until the JWT secret, the CORS origins
and a real account are supplied — see
[Startup safety](configuration.md#startup-safety-octo_env). Change a password
with `POST /api/auth/password`; add accounts through `/api/users`
([api-and-rbac.md](../docs/api-and-rbac.md#console-accounts)).

## 2. Prepare targets

One entry per line; blank lines and comments are ignored.

`scanner/inputs/ranges.txt`:

```text
203.0.113.10
198.51.100.0/28
```

`scanner/inputs/domains.txt`:

```text
portal.example.test
api.example.test
```

Optional port overrides:

```text
# scanner/inputs/ports.txt
22
80
443
8443

# scanner/inputs/ports_udp.txt
53
123
161
```

The addresses above are documentation ranges. Replace them with authorized
targets.

The Web UI's on-demand job submission (below) takes targets directly in the
request. The scheduled Job/CronJob path instead reads them from a `scan-targets`
Kubernetes Secret built from these files — see step 4.

## 3. Validate scanner configuration

```bash
python -m scanner.main --config scanner/config/default.yaml --validate-config
```

A validation failure exits with code `2` and does not start external tools.

## 4. Start the platform

```bash
scripts/dev-up.sh
```

This creates a local `kind` cluster, builds and loads the all-in-one image,
and applies `k8s/shapoclyack/overlays/kind-dev` — PostgreSQL, NATS, and
ClickHouse are included (NATS/ClickHouse client wiring is opt-in via env vars,
off by default). Tear down with `scripts/dev-down.sh`.

For real GeoIP/ASN/EPSS/KEV/CVSS4 data instead of the seed files, run it as
`OVERLAY=kind-enrichment scripts/dev-up.sh`. Once that PVC exists the script
re-selects it on later runs unless `OVERLAY` says otherwise, so rebuilding
cannot quietly drop the API back to the image's seed data.

The scheduled Job/CronJob require a `scan-targets` Secret built from the files
in step 2:

```bash
kubectl create secret generic scan-targets -n network-scan \
  --from-file=ranges.txt=scanner/inputs/ranges.txt \
  --from-file=domains.txt=scanner/inputs/domains.txt \
  --from-file=ports.txt=scanner/inputs/ports.txt \
  --from-file=ports_udp.txt=scanner/inputs/ports_udp.txt
```

## 5. Verify health

```bash
curl --fail http://127.0.0.1:8080/api/health
```

Use `127.0.0.1` rather than `localhost` on the kind path: kind publishes the
NodePort on `0.0.0.0` (IPv4 only), and on macOS `localhost` resolves to `::1`
first, which is refused.

The response reports API health and the configured state of NATS, ClickHouse,
and ingest. A service shown as disabled is not an error when its `OCTO_NATS_URL`
/ `OCTO_CLICKHOUSE_URL` env var was left empty.

Open <http://127.0.0.1:8080> and use the operator account for the first scan.

## 6. Approve a scanning scope

A fresh installation scans nothing until an admin says what it may scan. Since
[#226](https://github.com/onixus/Shapoclyack/issues/226) every target is checked
against the tenant's **approved scanning scope**, and the check is fail-closed:
a tenant with no entries starts no scan at all, not even one that would have
used the input files from step 2. Migration `0025` grandfathers tenants that
already existed at upgrade time, but the `default` tenant of a brand-new
install is created at first API start — after the migration — so it has an
empty scope and the first job would be refused with `403`.

Approve the addresses from step 2, as `admin`:

```bash
TOKEN=$(curl -s http://127.0.0.1:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin-change-me"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

curl -s -X PUT http://127.0.0.1:8080/api/tenants/default/scan-scope \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"entries": [
        {"effect": "allow", "kind": "cidr",   "value": "203.0.113.10/32", "note": "lab"},
        {"effect": "allow", "kind": "cidr",   "value": "198.51.100.0/28", "note": "lab"},
        {"effect": "allow", "kind": "domain", "value": "example.test"},
        {"effect": "deny",  "kind": "cidr",   "value": "169.254.0.0/16",  "note": "cloud metadata"}
      ]}'
```

`PUT` replaces the whole scope, allow is containment (a range half-inside an
approved one is not half-approved) and deny wins by overlap. Read it back with
`GET /api/tenants/default/scan-scope`. The rules, the upgrade path for an
existing installation and the recommended per-tenant order are in
[operations.md](operations.md#approved-scan-scope-per-tenant).

## 7. Start a scan

From the UI:

1. Open **Jobs**.
2. Select a conservative profile for the first run.
3. Confirm target inputs and optional stages.
4. Submit the job.
5. Follow the job to its run detail and reports.

Scanner-only execution is also available:

```bash
docker build -t shapoclyack-scanner .

docker run --rm \
  --cap-add NET_RAW \
  --cap-add NET_ADMIN \
  -v "$PWD/scanner/inputs:/app/scanner/inputs:ro" \
  -v "$PWD/scanner/output:/app/scanner/output" \
  -v "$PWD/scanner/state:/app/scanner/state" \
  -v "$PWD/scanner/config:/app/scanner/config:ro" \
  shapoclyack-scanner \
  --config scanner/config/default.yaml
```

## 8. Verify results

Check:

- the job reaches `succeeded`;
- a run appears under **Runs**;
- `scanner/output/runs/<run_id>/` contains `run_meta.json` and stage artifacts;
- summary counts are plausible for the authorized target set;
- external tool errors are absent from the run log.

Treat an empty result as a condition to investigate, not automatically as a
clean bill of health. Network ACLs, missing capabilities, rate limits, and DNS
failures can all reduce coverage.

## Next steps

- Tune [profiles and stages](configuration.md).
- Review [data flow and trust boundaries](architecture.md).
- Configure [operations, resume, and retention](operations.md).
- Use the [Kubernetes guide](../k8s/README.md) for production deployment.
