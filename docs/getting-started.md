# Getting started

This guide starts an all-in-one installation, validates its dependencies, and
runs the first authorized scan.

## Prerequisites

- Docker Engine with the Compose plugin;
- 4 GB free memory for evaluation, more when scanning large target sets;
- write access to `scanner/inputs`, `scanner/output`, and `scanner/state`;
- explicit authorization for every target.

Raw socket capabilities are required by some discovery modes. The Compose file
adds `NET_RAW` and `NET_ADMIN` to the scanner container.

## 1. Clone and set secrets

```bash
git clone https://github.com/onixus/Shapoclyack.git
cd Shapoclyack

export OCTO_JWT_SECRET='replace-with-a-long-random-secret'
```

The default users are for local evaluation only:

| User | Default password | Role |
|---|---|---|
| `viewer` | `viewer-change-me` | viewer |
| `operator` | `operator-change-me` | operator |
| `admin` | `admin-change-me` | admin |

Do not bind the demo configuration to a public address.

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

## 3. Validate scanner configuration

```bash
python -m scanner.main --config scanner/config/default.yaml --validate-config
```

A validation failure exits with code `2` and does not start external tools.

## 4. Start the platform

Minimal evaluation:

```bash
docker compose up --build
```

Persistent inventory:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  --profile postgres \
  up --build
```

Distributed execution and analytics:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.postgres.yml \
  -f docker-compose.nats.yml \
  -f docker-compose.clickhouse.yml \
  --profile postgres \
  --profile nats \
  --profile clickhouse \
  up --build
```

## 5. Verify health

```bash
curl --fail http://localhost:8080/api/health
```

The response reports API health and the configured state of NATS, ClickHouse,
and ingest. A service shown as disabled is not an error when its Compose profile
was not selected.

Open <http://localhost:8080> and use the operator account for the first scan.

## 6. Start a scan

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

## 7. Verify results

Check:

- the job reaches `succeeded`;
- a run appears under **Runs**;
- `scanner/output/<run_id>/` contains `run.json` and stage artifacts;
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
