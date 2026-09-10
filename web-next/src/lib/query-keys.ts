/**
 * Central query-key factory. Values intentionally match the literal arrays the
 * pages used before the hooks migration so existing caches stay addressable.
 */
import type { PageParams, ScanListFilters } from "@/lib/api";

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
  runsPage: (page?: PageParams, filters?: ScanListFilters) =>
    ["runs", pageKey(page), { surface: filters?.surface ?? null }] as const,
  run: (runId: string) => ["run", runId] as const,
  runHosts: (runId: string) => ["run", runId, "hosts"] as const,
  runPorts: (runId: string) => ["run", runId, "ports"] as const,
  runVulns: (runId: string, filters?: { host?: string | null; port?: string | null }) =>
    ["run", runId, "vulns", { host: filters?.host ?? null, port: filters?.port ?? null }] as const,
  runScreenshots: (runId: string) => ["run", runId, "screenshots"] as const,
  jobs: ["jobs"] as const,
  jobsPage: (page?: PageParams, filters?: ScanListFilters) =>
    ["jobs", pageKey(page), { surface: filters?.surface ?? null }] as const,
  job: (jobId: string) => ["jobs", "detail", jobId] as const,
  jobSummary: ["jobs", "summary"] as const,
  wordlists: (tenantId: string | null) => ["wordlists", tenantId] as const,
  schedules: ["schedules"] as const,
  schedulesPage: (tenantId: string | undefined, page?: PageParams) =>
    ["schedules", tenantId ?? null, pageKey(page)] as const,
  agents: ["agents"] as const,
  agentsPage: (page?: PageParams) => ["agents", pageKey(page)] as const,
  agentSummary: ["agents", "summary"] as const,
  agentDetail: (agentId: string) => ["agents", "detail", agentId] as const,
  agentSnippets: ["agents", "snippets"] as const,
  deployStatus: (deployId: string) => ["agents", "deploy", deployId] as const,
  tenants: ["tenants"] as const,
  users: ["users"] as const,
  /** The signed-in account's own second-factor state (#315). Not keyed by
   * username: it is always "mine", and a key that named the user would
   * survive a sign-out into the next person's session. */
  mfa: ["auth", "mfa"] as const,
  authEvents: (page?: PageParams, outcome?: string) =>
    ["auth", "events", outcome ?? null, pageKey(page)] as const,
  auditEvents: (page?: PageParams, filters?: Record<string, string | undefined>) =>
    ["audit", "events", filters ?? {}, pageKey(page)] as const,
  tenantMembers: (tenantId: string) => ["tenants", tenantId, "members"] as const,
  provisioningKeys: (tenantId: string) => ["tenants", tenantId, "provisioning-keys"] as const,
  serviceTokens: (tenantId: string) => ["tenants", tenantId, "service-tokens"] as const,
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
  endpointCveMatches: (deviceId: string, tenantId = "default") =>
    ["endpoint-device", deviceId, "cve-matches", tenantId] as const,
  patchGaps: (tenantId = "default", limit = 50) =>
    ["endpoint-patch-gaps", tenantId, limit] as const,
  devicePatchGap: (deviceId: string, tenantId = "default") =>
    ["endpoint-device", deviceId, "patch-gap", tenantId] as const,
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
  complianceFrameworks: ["compliance", "frameworks"] as const,
  compliancePosture: (frameworkId: string) => ["compliance", frameworkId] as const,
  reportBranding: ["reports", "branding"] as const,
  webhooks: ["webhooks"] as const,
  webhooksPage: (page?: PageParams) => ["webhooks", pageKey(page)] as const,
  webhookDeliveries: (status: string | null, page?: PageParams) =>
    ["webhooks", "deliveries", status ?? null, pageKey(page)] as const,
  reportTemplates: ["reports", "templates"] as const,
  reportSchedules: ["reports", "schedules"] as const,
  generatedReports: (limit = 50) => ["reports", "generated", limit] as const,
  adoption: (windowDays: number) => ["adoption", windowDays] as const,
  usage: (historyMonths: number) => ["usage", historyMonths] as const,
  fleetUsage: ["usage", "tenants"] as const,
  tenantQuota: (tenantId: string) => ["tenants", tenantId, "quota"] as const,
  scanScope: (tenantId: string) => ["tenants", tenantId, "scan-scope"] as const,
  promotedDomains: (tenantId: string) => ["tenants", tenantId, "promoted-domains"] as const,
  system: ["system"] as const,
  config: ["config"] as const,
};
