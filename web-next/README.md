# Octo-man Web UI v2 (`web-next/`)

Next.js 14 App Router dashboard for MSSP / Enterprise Vulnerability Management.

## Stack

- Next.js 14 (App Router) + TypeScript + Tailwind CSS
- Shadcn UI (Slate) + Lucide icons
- Tremor charts
- TanStack Table + React Query
- Axios JWT client (`src/lib/api.ts`)

## Develop

```bash
cd web-next
npm install
npm run dev
# http://localhost:3000
```

Optional API base URL:

```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8080/api npm run dev
```

## Current pages

| Route | Status |
|-------|--------|
| `/` Dashboard | Tremor cards + AreaChart / DonutChart (mock) |
| `/tenants` | TanStack table + Create Tenant dialog (Provisioning Key) |
| `/assets` | Inventory table + Diff-badges (sample rows; fleet total mocked at 50k+) |
| `/agents` `/jobs` `/runs` | Shell placeholders |

See [ROADMAP.md](../ROADMAP.md) Phase 6 for the full plan. Keep `web/` (v1) until parity.
