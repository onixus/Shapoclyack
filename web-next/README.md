# Octo-man Web UI v2 (`web-next/`)

Next.js 14 App Router dashboard for MSSP / Enterprise Vulnerability Management.

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
# API on :8080 (rewrites /api/* → API_PROXY_TARGET)
npm run dev
# http://localhost:3000/login
```

Optional:

```bash
API_PROXY_TARGET=http://localhost:8080 npm run dev
# or point the browser client directly at the API:
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080/api npm run dev
```

Demo users (aio defaults): `viewer` / `operator` / `admin` with `*-change-me` passwords.

## Current pages

| Route | Status |
|-------|--------|
| `/login` | JWT login against `POST /api/auth/login` |
| `/` Dashboard | Tremor cards + charts (mock KPIs) |
| `/tenants` | Live `GET/POST /api/tenants` + provisioning key (admin) |
| `/assets` | Inventory mock (no `/api/assets` yet) |
| `/agents` | Live `GET /api/agents` (5s poll) |
| `/jobs` | Live `GET/POST /api/jobs` (operator+) |
| `/runs` | Live `GET /api/runs` (10s poll) |

See [ROADMAP.md](../ROADMAP.md) Phase 6. Keep `web/` (v1) until full parity (run detail, assets inventory API).
