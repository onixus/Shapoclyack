# Operations

## Run directories

Every scan writes to:

```text
scanner/output/runs/<run_id>/
```

The directory can contain:

- run metadata and normalized summaries;
- resolved and alive hosts;
- open ports and service aggregates;
- Nmap XML and tool logs;
- vulnerability and enrichment JSON;
- Markdown, HTML, and PDF reports;
- diff and normalized asset events;
- DefectDojo exports;
- diagnostic stage output.

Artifact presence depends on the enabled stages and whether a stage produced
data.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Successful run |
| `1` | Unexpected internal error |
| `2` | Configuration validation error |
| `3` | No valid targets after input validation |
| `4` | External tool failed after retries |
| `130` | Interrupted by the operator |

Automation should distinguish invalid configuration/inputs from transient tool
failure.

## Resume

Checkpoints are stored under `scanner/state`. Preserve both state and the
corresponding run output when moving or resuming a run.

```bash
python -m scanner.main \
  --config scanner/config/default.yaml \
  --resume
```

Do not resume after changing target scope or incompatible stage settings.
Start a new run instead so provenance stays clear.

## Scheduling

Two scheduling models exist:

- `scanner/scheduler.py` and the Kubernetes CronJob for simple single-tenant
  installations;
- API-managed tenant schedules for the platform deployment.

The API dispatcher skips a schedule tick while its previous job is still
running. Use this behavior to prevent overlapping long scans; it is not a
replacement for capacity planning.

## Diffs and events

Run diffs compare current and previous compatible results. Normalized events
include new assets, open ports, CVEs, certificate-expiry findings, and manual
decommissioning. Verify that both compared runs use equivalent scope and
profiles before treating a count change as a security event.

## Alerts and exports

Supported integrations include Slack/Telegram summary alerts, SMTP, DefectDojo,
and report artifacts. Configure credentials only through secrets or environment
injection. Test notification delivery with non-sensitive data before enabling
production findings.

## Retention

Retention must cover all stateful layers:

| Layer | Retain/backup |
|---|---|
| Run filesystem/PVC | Raw artifacts, reports, checkpoints |
| PostgreSQL | Tenants, keys metadata, assets, schedules, overrides, endpoint inventory |
| ClickHouse | Analytical vulnerability and port history |
| NATS | Pending jobs and ingest messages |

Set retention according to legal, operational, and privacy requirements. Scan
artifacts can contain internal hostnames, IPs, software versions, and
vulnerability evidence.

## Logs and observability

Use structured application logs and correlate by tenant, `job_id`, `run_id`,
and `agent_id`. Do not log secrets or full authorization headers.

Useful checks:

```bash
curl --fail http://localhost:8080/api/health
docker compose ps
docker compose logs --tail=200 shapoclyack
```

Kubernetes:

```bash
kubectl -n network-scan get pods,jobs,cronjobs
kubectl -n network-scan logs deployment/octo-man-api --tail=200
```

## Backups

At minimum:

1. quiesce or coordinate writers;
2. back up PostgreSQL with a database-native method;
3. snapshot artifact and ClickHouse volumes consistently;
4. export deployment manifests without secret values;
5. test restore into an isolated namespace.

NATS streams are operational queues. Design recovery so a restored message
cannot silently duplicate an already-ingested result.
