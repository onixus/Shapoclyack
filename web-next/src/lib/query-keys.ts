/**
 * Central query-key factory. Values intentionally match the literal arrays the
 * pages used before the hooks migration so existing caches stay addressable.
 */
import type { PageParams } from "@/lib/api";

/** Pagination state is part of the cache identity: two pages of the same list
 * are different server responses (ROADMAP P3.3). */
function pageKey(page?: PageParams) {
  return {
    offset: page?.offset ?? 0,
    limit: page?.limit ?? null,
    q: page?.q ?? "",
    sort: page?.sort ?? "",
    order: page?.order ?? "",
  };
}

export const queryKeys = {
  runs: ["runs"] as const,
  runsPage: (page?: PageParams) => ["runs", pageKey(page)] as const,
  run: (runId: string) => ["run", runId] as const,
  runHosts: (runId: string) => ["run", runId, "hosts"] as const,
  runPorts: (runId: string) => ["run", runId, "ports"] as const,
  runVulns: (runId: string, filters?: { host?: string | null; port?: string | null }) =>
    ["run", runId, "vulns", { host: filters?.host ?? null, port: filters?.port ?? null }] as const,
  runScreenshots: (runId: string) => ["run", runId, "screenshots"] as const,
  jobs: ["jobs"] as const,
  jobsPage: (page?: PageParams) => ["jobs", pageKey(page)] as const,
  wordlists: (tenantId: string | null) => ["wordlists", tenantId] as const,
  schedules: ["schedules"] as const,
  schedulesPage: (tenantId: string | undefined, page?: PageParams) =>
    ["schedules", tenantId ?? null, pageKey(page)] as const,
  agents: ["agents"] as const,
  agentsPage: (page?: PageParams) => ["agents", pageKey(page)] as const,
  tenants: ["tenants"] as const,
  assets: (filters: { status?: string }) => ["assets", filters] as const,
  assetsPage: (
    filters: { status?: string; unowned?: boolean; exposure?: string },
    page?: PageParams,
  ) => ["assets", filters, pageKey(page)] as const,
  tenantPosture: ["tenants", "posture"] as const,
  assetSummary: ["assets", "summary"] as const,
  asset: (assetId: string, tenantId = "default") => ["asset", assetId, tenantId] as const,
  assetEvents: (assetId: string, tenantId = "default") =>
    ["asset", assetId, "events", tenantId] as const,
  endpointDevices: (tenantId = "default") => ["endpoint-devices", tenantId] as const,
  endpointDevicesForAsset: (assetId: string, tenantId = "default") =>
    ["endpoint-devices", "asset", assetId, tenantId] as const,
  assetSoftware: (assetId: string, tenantId = "default") =>
    ["asset", assetId, "software", tenantId] as const,
  endpointDeviceChanges: (deviceId: string, tenantId = "default") =>
    ["endpoint-device", deviceId, "changes", tenantId] as const,
  recentSoftwareChanges: (tenantId = "default", limit = 50) =>
    ["endpoint-changes", tenantId, limit] as const,
  vulnerabilities: ["vulnerabilities"] as const,
  vulnerabilitiesPage: (filters: Record<string, unknown>, page?: PageParams) =>
    ["vulnerabilities", filters, pageKey(page)] as const,
  vulnerabilitySummary: ["vulnerabilities", "summary"] as const,
  vulnerability: (vulnId: string) => ["vulnerability", vulnId] as const,
  vulnerabilityEvents: (vulnId: string, page?: PageParams) =>
    ["vulnerability", vulnId, "events", pageKey(page)] as const,
  vulnerabilityActivity: (page?: PageParams) =>
    ["vulnerabilities", "events", pageKey(page)] as const,
  riskHistory: (params?: { since?: string; until?: string; limit?: number }) =>
    ["vulnerabilities", "risk-history", params] as const,
  system: ["system"] as const,
  config: ["config"] as const,
};
