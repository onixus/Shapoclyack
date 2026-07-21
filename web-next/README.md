# Shapoclyack Web UI v2 (`web-next/`)

Next.js 14 App Router dashboard for MSSP / Enterprise Vulnerability Management.

Production builds use **`output: "export"`** so the static `out/` tree is served by
FastAPI from `OCTO_WEB_DIST` (aio / API images copy `out/` → `/app/web/dist`).

## Stack

- Next.js 14 (App Router) + TypeScript + Tailwind CSS
- Shadcn UI (Slate) + Lucide icons
- Tremor charts
- TanStack Table + React Query
- Axios JWT client (`src/lib/api.ts`) + Zustand auth store

## Develop

```bash
cd web-next
npm install
# API on :8080 (rewrites /api/* → API_PROXY_TARGET during next dev)
npm run dev
# http://localhost:3000/login
```

Optional:

```bash
API_PROXY_TARGET=http://localhost:8080 npm run dev
# or point the browser client directly at the API:
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080/api npm run dev
```

Static export (same as Docker image build):

```bash
npm run build   # writes out/
```

Demo users (aio defaults): `viewer` / `operator` / `admin` with `*-change-me` passwords.

## Current pages

| Route | Status |
|-------|--------|
| `/login` | JWT login against `POST /api/auth/login` |
| `/` Dashboard | Live KPIs/charts from latest run |
| `/tenants` | Live `GET/POST /api/tenants` + provisioning key (admin) |
| `/assets` | Cross-run asset inventory from `GET /api/assets` (first/last seen, status) |
| `/agents` | Live `GET /api/agents` (5s poll) |
| `/jobs` | Live `GET/POST /api/jobs` (operator+) |
| `/runs` | Live `GET /api/runs` (10s poll); links to detail |
| `/runs/view?runId=` | Live run detail (static-export friendly query URL) |

See [ROADMAP.md](../ROADMAP.md) Phase 6.

## Scripts

| Command | Purpose |
|---------|---------|
| `npm run dev` | Dev server with `/api/*` proxy |
| `npm run build` | Static export to `out/` (includes typecheck + ESLint) |
| `npm run lint` | ESLint (`next lint`) |
| `npm run typecheck` | `tsc --noEmit` |
| `npm run test` | Vitest (unit + component tests, jsdom) |
| `npm run format` / `format:check` | Prettier over `src/` |

## Conventions

- Shared table UI: `src/components/data-table.tsx` (sorting, search, pagination).
- Status/severity colors: `src/lib/config/statuses.ts` + `StatusBadge` — do not
  hardcode badge colors in pages.
- Data fetching: hooks in `src/hooks/` with keys from `src/lib/query-keys.ts`
  and intervals from `src/lib/config/constants.ts`; pages stay presentational.
- Mutation feedback: sonner toasts (`Toaster` is mounted in the dashboard layout).
