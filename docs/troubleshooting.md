# Troubleshooting

Start with the narrowest failing layer and preserve the first useful error.

## API or UI does not start

```bash
docker compose ps
docker compose logs --tail=200 shapoclyack
curl -v http://localhost:8080/api/health
```

Check for a port collision on `8080`, invalid environment values, an
unavailable PostgreSQL URL, or a read-only mounted output directory.

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
  ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.36-0723 \
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

An optional service is expected to be unavailable when its profile/URL is not
enabled. When enabled:

```bash
docker compose --profile nats --profile clickhouse ps
curl http://localhost:8222/healthz
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
kubectl kustomize k8s/octo-man/overlays/dev
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
