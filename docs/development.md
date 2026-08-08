# Development guide

This guide defines the supported local toolchains, validation commands, and
review expectations for Shapoclyack changes.

## Toolchains

- Python 3.12 for local development; CI also validates the supported matrix.
- Node.js 24 or newer for `web-next/`.
- Go version declared in `recon/go.mod`.
- Docker for image, smoke, load, and end-to-end validation.
- `kubectl kustomize` or standalone Kustomize for manifest validation.

Use pinned dependency files from the repository. Do not silently upgrade a
runtime or package in an unrelated feature change.

## Python environment

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install \
  -r requirements.txt \
  -r requirements-api.txt \
  -r requirements-dev.txt
```

Run the baseline checks:

```bash
ruff check .
python -m compileall scanner api tests agent
python -m pytest
```

Run the API locally:

```bash
python -m api
```

Host, port, database, broker, authentication, and feature settings are defined
in `api/__main__.py` and `api/settings.py`. Prefer environment overrides over
editing defaults for local experiments.

## Web UI

```bash
cd web-next
npm ci
API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

Open <http://localhost:3000/login>. The development server proxies `/api/*` to
the configured API target. Production uses a static export served by FastAPI.

Before opening a pull request, run:

```bash
npm run format:check
npm run lint
npm run typecheck
npm run test
npm run build
```

`npm run build` is the authoritative static-export check. The development
rewrite warning for `output: "export"` is expected and does not indicate a
production routing failure.

## Scale fixtures

`tests/fixtures/scale_seed.py` populates the two stores that grow with asset
count — Postgres `assets`/`asset_identifiers` and the ClickHouse analytics
tables — so pagination, search, and the tenant-wide diff queries can be
measured at 1k, 10k, and 50k assets instead of on a handful of dev rows:

```bash
python -m tests.fixtures.scale_seed --assets 10000 \
  --postgres-url "$OCTO_POSTGRES_URL" --clickhouse-url "$OCTO_CLICKHOUSE_URL"
```

Both URLs fall back to `OCTO_POSTGRES_URL` / `OCTO_CLICKHOUSE_URL`; add
`--skip-postgres` or `--skip-clickhouse` to seed one store only. Rows are
derived from `--seed` and the asset index, so a rerun with the same arguments
is idempotent and a larger `--assets` value extends a smaller fixture rather
than replacing it — a measurement stays comparable after growing the dataset.

Clean up with the same tenant:

```bash
python -m tests.fixtures.scale_seed --purge --tenant scale-test
```

`--purge` is a tenant-scoped delete, which is why the default tenant is
`scale-test` and not `default`. Point it at a tenant holding real scan data and
that data is gone. On ClickHouse it submits an `ALTER TABLE … DELETE` mutation
and returns before the parts are rewritten, so counts settle a moment later.

This is a *data* generator. `tests/load/run.sh` is the separate network-load
harness that runs the scanner against live target containers; neither replaces
the other.

## Kubernetes and containers

Validate manifests:

```bash
bash k8s/scripts/validate-kustomize.sh
kubectl kustomize k8s/shapoclyack/overlays/dev >/dev/null
kubectl kustomize k8s/shapoclyack/overlays/prod >/dev/null
```

Examples are intentionally not applied by the base. Copy an example, replace
all placeholders, and validate the rendered output before applying it.

For changes that affect packaging or runtime dependencies, also build the
relevant image and run its smoke check. CI remains the final source of truth for
the full image, load, Trivy, and SBOM pipeline.

## Documentation workflow

Documentation is part of the implementation contract. When behavior changes:

1. update the authoritative guide listed in [the documentation index](README.md);
2. update the root README only when the project overview or primary workflow
   changes;
3. add an `Unreleased` changelog entry;
4. update roadmap status when a planned item is delivered or materially changed;
5. regenerate interface screenshots when a documented UI surface changes;
6. verify relative Markdown links, commands, file paths, image tags, and
   environment variable names;
7. distinguish behavior available on `main` from behavior available in the
   latest release tag.

Do not copy the same procedure into several files. Keep one authoritative
procedure and link to it from indexes and summaries. This prevents the usual
outcome where three guides confidently disagree with one another.

The screenshot process is documented in [ui.md](ui.md).

## Pull request structure

Keep changes reviewable:

- one primary concern per pull request;
- separate mechanical renames from behavior changes when practical;
- explain compatibility and migration impact;
- include the exact validation performed;
- call out checks that require CI or external infrastructure;
- avoid drive-by formatting outside the changed area.

A useful pull request description includes:

```text
Summary
Why
Behavior and compatibility
Security or tenancy impact
Validation
Follow-up work
```

## Review checklist

### Correctness

- tests cover the changed contract and important failure paths;
- schemas, API responses, and generated or handwritten client types remain
  aligned;
- timeouts, retries, and concurrency are bounded;
- cleanup paths are deterministic and idempotent;
- database migrations have a single head and a documented rollback strategy.

### Security and tenancy

- tenant context is derived and enforced server-side;
- role checks are explicit at the protected operation;
- cross-tenant identifiers do not leak through distinguishable errors;
- secrets and credentials are not logged, committed, or embedded in examples;
- remote inputs, archives, paths, and URLs are validated before use;
- containers and Kubernetes workloads retain least privilege.

### Operations

- logs identify the failed component and action without exposing sensitive data;
- metrics and health checks still describe actual readiness;
- deployment and upgrade paths remain reproducible;
- retention, backup, and recovery behavior is documented when storage changes;
- documentation matches the code being merged, not an intended future state.
