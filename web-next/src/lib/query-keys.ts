/**
 * Central query-key factory. Values intentionally match the literal arrays the
 * pages used before the hooks migration so existing caches stay addressable.
 */
export const queryKeys = {
  runs: ["runs"] as const,
  run: (runId: string) => ["run", runId] as const,
  runHosts: (runId: string) => ["run", runId, "hosts"] as const,
  runPorts: (runId: string) => ["run", runId, "ports"] as const,
  runVulns: (runId: string, filters?: { host?: string | null; port?: string | null }) =>
    ["run", runId, "vulns", { host: filters?.host ?? null, port: filters?.port ?? null }] as const,
  jobs: ["jobs"] as const,
  agents: ["agents"] as const,
  tenants: ["tenants"] as const,
  assets: (filters: { status?: string }) => ["assets", filters] as const,
  asset: (assetId: string) => ["asset", assetId] as const,
};
