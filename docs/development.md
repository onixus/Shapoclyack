# Development

## Toolchains

- Python 3.12
- Node.js 24 or newer
- Go version from `recon/go.mod`
- Docker for image and end-to-end validation
- `kubectl kustomize` or standalone Kustomize for manifests

## Python

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-api.txt -r requirements-dev.txt

ruff check .
python -m pytest
```

Run the API:

```bash
python -m api
```

Exact host, port, and environment settings are defined in `api/__main__.py` and
`api/settings.py`.

## Web UI

```bash
cd web-next
npm ci

API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

Open <http://localhost:3000/login>. The dev server rewrites `/api/*` to the API
target. Production uses a static export mounted by FastAPI.

Validation:

```bash
npm run format:check
npm run typecheck
npm run test
npm run build
```

`npm run build` is the authoritative static-export check. The warning that
development rewrites do not apply to `output: "export"` is expected.

## Kubernetes

```bash
bash k8s/scripts/validate-kustomize.sh
kubectl kustomize k8s/octo-man/overlays/dev >/dev/null
kubectl kustomize k8s/octo-man/overlays/prod >/dev/null
```

Examples are intentionally not applied by the base. Validate any example after
copying and replacing placeholders.

## Documentation

When behavior changes:

1. update the relevant guide, not only the root README;
2. add an `Unreleased` changelog entry;
3. update the roadmap status if a planned item is delivered;
4. regenerate UI screenshots when a documented surface changed;
5. check relative Markdown links.

The screenshot procedure is in [ui.md](ui.md).

## Change checklist

- tests cover the changed contract;
- schemas and client types remain aligned;
- tenant and role checks are explicit;
- external calls have timeouts and bounded concurrency;
- no secret or real target appears in fixtures, logs, or screenshots;
- Docker and Kustomize paths remain reproducible;
- docs distinguish released behavior from `main`.
