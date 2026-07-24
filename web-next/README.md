# Shapoclyack Web UI

The operator console is a Next.js 14 App Router application. It is exported as
static HTML/JavaScript and served by FastAPI in production; no Node.js process
is required in the runtime image.

Platform documentation: [../docs/README.md](../docs/README.md).
UI guide and screenshots: [../docs/ui.md](../docs/ui.md).

## Stack

- TypeScript and React 18
- Tailwind CSS and Shadcn/Radix primitives
- TanStack Query and Table
- Tremor charts
- Zustand authentication state
- Axios API client
- Vitest and Testing Library

## Requirements

Node.js 24 or newer and a running Shapoclyack API.

## Development

```bash
npm ci
API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

Open <http://localhost:3000/login>. In development, `/api/*` is proxied to
`API_PROXY_TARGET`.

Alternatively, point the browser client directly at an API that permits the
origin:

```bash
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8080/api npm run dev
```

## Production build

```bash
npm run build
```

Output is written to `out/`. `Dockerfile.allinone` copies the export into the
FastAPI-served Web distribution directory.

The warning that rewrites are not applied to `output: "export"` is expected:
rewrites are a development convenience, while production uses same-origin
FastAPI routes.

## Routes

| Route | Surface |
|---|---|
| `/login` | JWT login |
| `/` | Exposure dashboard |
| `/assets` and `/assets/view` | Persistent inventory and asset detail |
| `/attack-surface` | Hostname/IP/port/service graph |
| `/jobs` | Scan job creation and status |
| `/runs` and `/runs/view` | Run history, findings, diff, and artifacts |
| `/reports` | Report discovery and download |
| `/agents` | Remote worker fleet |
| `/tenants` | Tenant provisioning |
| `/system` | Component status and validated config overrides |

Query-string detail routes are intentional because static export cannot produce
dynamic server routes.

## Scripts

| Command | Purpose |
|---|---|
| `npm run dev` | Development server |
| `npm run build` | Typecheck, lint, and static export |
| `npm run typecheck` | TypeScript without emit |
| `npm run test` | Vitest suite |
| `npm run format` | Format `src/` |
| `npm run format:check` | Verify formatting |

## Conventions

- API response types and functions live in `src/lib/api.ts`.
- React Query hooks live in `src/hooks/`.
- Shared status semantics live in `src/lib/config/statuses.ts`.
- Secrets never belong in `NEXT_PUBLIC_*` variables.
- Role checks in the UI do not replace API authorization.
- Screenshots use only synthetic tenants, users, addresses, and domains.
