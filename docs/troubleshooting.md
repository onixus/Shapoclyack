# Troubleshooting

Start with the narrowest failing layer and preserve the first useful error.

## API or UI does not start

```bash
kubectl -n network-scan get pods
kubectl -n network-scan logs deploy/shapoclyack-api --tail=200
curl -v http://127.0.0.1:8080/api/health
```

Check for a port collision on `8080`, invalid environment values, an
unavailable PostgreSQL URL, or a read-only mounted output directory.

If the pods are healthy but the curl fails to connect, try `127.0.0.1`
explicitly before hunting a port collision: kind publishes the NodePort on
`0.0.0.0` (IPv4 only), while `localhost` resolves to `::1` first on macOS.

## UI redirects to login

- confirm the API is reachable at the same origin or configured base URL;
- check `POST /api/auth/login` and `GET /api/auth/me`;
- remove an expired local token by signing out;
- verify system time, JWT secret consistency, and ingress headers;
- do not debug authorization by disabling server-side role checks.

## Jobs remain queued

- check `OCTO_JOB_EXECUTION_MODE`;
- in local mode, confirm scan start is allowed and the AIO image includes tools;
- in agent mode, confirm NATS/API connectivity and at least one online agent;
- verify agent and job tenant IDs match;
- inspect agent heartbeat and claim logs.

A job stuck in `claimed` is a distinct symptom: an agent took it and never
reported starting, so the worker most likely died between the claim and its
first heartbeat. Nothing reclaims it automatically yet (ROADMAP P1.4) — close
it with `POST /api/jobs/{job_id}/cancel` and start the scan again. That
endpoint only stops jobs that have not started executing: once the status is
`running`, it answers 409, because there is no way to stop a scan in flight.

## Scan Job fails with DeadlineExceeded and no logs

`kubectl describe job` shows `Job was active longer than specified deadline`,
`Events: <none>`, and there is no pod left to pull logs from.

Check the `scan-targets` Secret first:

```bash
kubectl -n network-scan get secret scan-targets
```

`job.yaml`, `job-resume.yaml`, and `cronjob.yaml` mount it as a **required**
volume (unlike the API Deployment, where it is optional). When it is missing the
kubelet cannot create the pod at all — it stays in `ContainerCreating` until
`activeDeadlineSeconds` (4h in base, 1h in the dev overlay) expires and the Job
is failed, deleting the pod and its events along with it. So the hour of silence
is the symptom, not a scan that ran and stalled. Create the Secret
(`examples/scan-targets.secret.example.yaml`) and re-create the Job.

Catch it early instead: `scripts/dev-up.sh` warns when the Secret is absent.

## Scanner finds no hosts

- confirm the normalized target files are non-empty;
- validate the config and inspect exit code;
- verify `NET_RAW`/`NET_ADMIN` where required;
- test DNS and route reachability from the scanner namespace;
- retry with the `safe` profile and a single authorized host;
- inspect discovery coverage artifacts before increasing rates.

## Nmap, Naabu, DNSx, or Nuclei fails

```bash
docker run --rm --entrypoint sh \
  ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.40-0806 \
  -lc 'nmap --version; naabu -version; dnsx -version; nuclei -version'
```

Use the pinned image tag, not `latest`. Exit code `4` means an external stage
failed after retries; inspect the corresponding stage log.

## PostgreSQL errors

- verify the database exists and credentials are injected;
- confirm migrations ran before serving requests;
- check connection limits and network policy;
- avoid pointing multiple incompatible versions at the same schema;
- back up before manual migration intervention.

## NATS or ClickHouse shows unavailable

An optional service is expected to be unavailable when its URL env var
(`OCTO_NATS_URL` / `OCTO_CLICKHOUSE_URL`) is empty. When enabled:

```bash
kubectl -n network-scan get pods -l app.kubernetes.io/component=nats
kubectl -n network-scan get pods -l app.kubernetes.io/component=clickhouse
kubectl -n network-scan port-forward svc/shapoclyack-nats-client 8222:8222 &
curl http://localhost:8222/healthz
kubectl -n network-scan port-forward svc/shapoclyack-clickhouse-client 8123:8123 &
curl http://localhost:8123/ping
```

Check service DNS names from inside the API container, not only from the host.

## Reports or artifacts are missing

- verify the job completed successfully;
- check whether the producing stage was enabled;
- inspect the run artifact list through the API;
- confirm the output volume is writable and persistent;
- for PDF, inspect report-generation dependencies and logs;
- never construct artifact paths outside the run directory.

## Resume does not continue

Resume requires compatible checkpoint state and output. If targets, config, or
image version changed, start a new run. Preserve the failed directory for
forensics rather than deleting it before diagnosis.

## Kubernetes apply fails

```bash
bash k8s/scripts/validate-kustomize.sh
kubectl kustomize k8s/shapoclyack/overlays/dev
kubectl -n network-scan get events --sort-by=.lastTimestamp
```

Optional overlays can require CRDs, a ReadWriteMany StorageClass, or secrets
that the base does not create.

## Collecting a support bundle

Collect only what is necessary:

- release/commit and deployment mode;
- rendered manifests with secrets removed;
- component status and relevant log window;
- job/run identifiers and scanner exit code;
- redacted configuration;
- exact reproduction steps.

Do not attach tokens, provisioning keys, passwords, database URLs, real target
lists, or raw findings unless the recipient and transfer channel are approved.
