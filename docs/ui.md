# Web interface

The Next.js 14 interface is built as a static export and served by FastAPI in
the all-in-one and API images.

## Surfaces

| Route | Purpose | Minimum role |
|---|---|---|
| `/login` | Create a user session | Public |
| `/` | Exposure KPIs, trend, severity, top findings, asset posture | Viewer |
| `/assets` | Cross-run asset inventory | Viewer |
| `/assets/view?assetId=…` | Asset metadata, findings, ports, OS/GeoIP, endpoint software | Viewer; operator for edits |
| `/attack-surface` | Hostname → IP → port → service graph | Viewer |
| `/jobs` | Start and monitor scan jobs | Operator |
| `/runs` | Run history | Viewer |
| `/runs/view?runId=…` | Findings, entities, diff, and artifacts | Viewer |
| `/reports` | Report and artifact discovery | Viewer |
| `/agents` | Distributed worker fleet | Operator |
| `/tenants` | Tenant provisioning | Admin |
| `/system` | Versions, dependencies, stages, runtime, and safe config | Viewer; admin for edits |

## Screenshots

Interface screenshots must be captured from the current commit with synthetic
`.test` domains and RFC 5737 documentation addresses. Never use production
targets, tenant names, user identities, or tokens.

Expected files:

```text
docs/images/ui-dashboard.png
docs/images/ui-assets.png
docs/images/ui-attack-surface.png
docs/images/ui-jobs.png
docs/images/ui-run-report.png
docs/images/ui-system.png
```

The Markdown below intentionally renders only files that exist in the
repository. Regenerate all images as one set after a material UI change.

<!-- UI_SCREENSHOTS_START -->

Screenshots are pending capture from a browser environment that can reach the
locally built application.

<!-- UI_SCREENSHOTS_END -->

## Reproducible capture

1. Build the current UI:

   ```bash
   cd web-next
   npm ci
   npm run build
   ```

2. Start the AIO stack with a synthetic dataset or a mock API whose response
   types match `web-next/src/lib/api.ts`.
3. Use a 1440×900 viewport at 100% scale.
4. Sign in with a disposable admin account.
5. Wait for all loading indicators to settle.
6. Capture the six routes listed above as PNG without browser chrome.
7. Inspect every image for secrets and real environment data.
8. Place images under `docs/images/` and replace the pending block with:

   ```markdown
   ![Exposure dashboard](images/ui-dashboard.png)
   ![Asset inventory](images/ui-assets.png)
   ![Attack-surface graph](images/ui-attack-surface.png)
   ![Scan jobs](images/ui-jobs.png)
   ![Run report](images/ui-run-report.png)
   ![System status](images/ui-system.png)
   ```

## UI development

```bash
cd web-next
API_PROXY_TARGET=http://127.0.0.1:8080 npm run dev
```

The production export does not use Next.js rewrites. FastAPI serves the static
files and `/api` on the same origin.
