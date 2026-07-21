/** React Query refetch intervals, in milliseconds. */
export const POLL_INTERVALS = {
  jobs: 4_000,
  agents: 5_000,
  runs: 10_000,
  dashboard: 15_000,
  assets: 30_000,
} as const;

/** Backend caps for per-run collections (api/routes/runs.py Query le=…). */
export const VULN_FETCH_LIMIT = 10_000;
export const HOSTS_FETCH_LIMIT = 10_000;

/** Findings rendered per severity group before the "Show all" toggle. */
export const FINDINGS_GROUP_PREVIEW = 200;

export const DEFAULT_PAGE_SIZE = 15;
