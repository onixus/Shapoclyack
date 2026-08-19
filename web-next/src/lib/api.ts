import axios from "axios";

const TOKEN_KEY = "shapoclyack_access_token";
const TENANT_KEY = "shapoclyack_active_tenant";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

/** Tenant the console is currently acting in, or `null` for "let the server
 * decide" — which for a platform admin means the fleet-wide view (ROADMAP P0).
 * Survives reloads; `auth-store` drops it on login/hydrate if the signed-in
 * user is not entitled to it. */
export function getActiveTenant(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TENANT_KEY);
}

export function setActiveTenant(tenantId: string | null) {
  if (typeof window === "undefined") return;
  if (!tenantId) {
    window.localStorage.removeItem(TENANT_KEY);
    return;
  }
  window.localStorage.setItem(TENANT_KEY, tenantId);
}

export function setAccessToken(token: string | null) {
  if (typeof window === "undefined") return;
  if (!token) {
    window.localStorage.removeItem(TOKEN_KEY);
    return;
  }
  window.localStorage.setItem(TOKEN_KEY, token);
}

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_BASE_URL || "/api",
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  // Attach the active tenant to every request unless the caller already named
  // one (deep links like /assets/view?tenantId= still win). The server treats a
  // missing tenant_id as "resolve from my memberships".
  const tenantId = getActiveTenant();
  if (tenantId) {
    const params = config.params;
    if (params instanceof URLSearchParams) {
      if (!params.has("tenant_id")) params.set("tenant_id", tenantId);
    } else if (params && typeof params === "object") {
      if ((params as Record<string, unknown>).tenant_id == null) {
        (params as Record<string, unknown>).tenant_id = tenantId;
      }
    } else {
      config.params = { tenant_id: tenantId };
    }
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error?.response?.status === 401 && typeof window !== "undefined") {
      setAccessToken(null);
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  },
);

function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (detail != null) return JSON.stringify(detail);
    return error.message;
  }
  if (error instanceof Error) return error.message;
  return "Request failed";
}

export type Role = "viewer" | "operator" | "admin";

export type Me = {
  username: string;
  role: Role;
  /** Tenants this user may act in, and the one used when a request omits
   * `tenant_id` (ROADMAP P0). The tenant switcher builds on these. */
  tenants: string[];
  default_tenant: string;
  is_platform_admin: boolean;
};

/** The API resolves the tenant from the caller's memberships when the request
 * omits `tenant_id` (ROADMAP P0), and sending the literal "default" would 403
 * for a user whose tenants don't include it — so treat that placeholder as
 * "let the server decide", which the request interceptor then fills in with
 * the active tenant when one is selected. */
function tenantParam(tenantId?: string): Record<string, string> {
  return tenantId && tenantId !== "default" ? { tenant_id: tenantId } : {};
}

export type RunSummary = {
  run_id: string;
  /** Owning tenant (ROADMAP P0); "default" for runs written before tagging. */
  tenant_id: string;
  profile: string | null;
  started_at: string | null;
  alive_hosts: number | null;
  open_host_port_pairs: number | null;
  potential_vulnerabilities: number | null;
  /** Subset of `potential_vulnerabilities` the scanner could not confirm —
   * `exposure` observations and unverified `keyword_cve` hits. Null for runs
   * scanned before the field existed. */
  unconfirmed_findings: number | null;
  vulnerable_hosts: number | null;
  has_diff: boolean;
  has_summary: boolean;
};

export type RunDetail = {
  run_id: string;
  meta: Record<string, unknown>;
  summary: Record<string, unknown> | null;
  diff: Record<string, unknown> | null;
  artifacts: string[];
};

export type Vulnerability = {
  host: string | null;
  port: string | null;
  cve: string | null;
  cvss: number | null;
  cvss4: number | null;
  cvss4_vector: string | null;
  cvss4_severity: string | null;
  severity: string | null;
  script_id: string | null;
  country: string | null;
  city: string | null;
  country_iso: string | null;
  /** Scanner finding taxonomy: "version_cve" (confirmed), "keyword_cve"
   * (unverified NVD keyword hit), "exposure" (reachable service, no CVE),
   * "tls". Null for nuclei/NSE findings. */
  finding_class: string | null;
  confidence: number | null;
  requires_confirmation: boolean;
  epss: number | null;
  in_kev: boolean;
  /** Prioritisation computed by the API (risk_scoring mvp-2). */
  contextual_score: number | null;
  cisa_decision: string | null;
  risk_explanation: string | null;
};

export type AliveHost = {
  host: string;
  hostname: string | null;
  names: string[];
  country: string | null;
  city: string | null;
  country_iso: string | null;
  /** GeoIP coordinates of the *network*, not the machine — typically a city or
   * country centre. Null for a Country-only GeoIP database, a private address,
   * or a run scanned before the scanner recorded them; the Geo Map falls back
   * to the country centroid and says so. */
  latitude: number | null;
  longitude: number | null;
  os_name: string | null;
  os_accuracy: number | null;
  asn: string | null;
  asn_org: string | null;
  vulnerability_count: number;
};

export type PortAggregate = {
  port: string;
  protocol: string | null;
  host_count: number;
  vulnerability_count: number;
  hosts: string[];
  services: string[];
};

export type ScanIntent = "inventory" | "vuln" | "full" | "delta";

export type JobInfo = {
  job_id: string;
  /** `claimed` = an agent holds the job but has not reported starting it. */
  status: "queued" | "claimed" | "running" | "succeeded" | "failed" | "cancelled";
  run_id: string | null;
  mode: string;
  started_at: string | null;
  finished_at: string | null;
  exit_code: number | null;
  error: string | null;
  requested_by: string;
  target_counts?: Record<string, number> | null;
  execution?: "local" | "agent";
  assigned_agent_id?: string | null;
  tenant_id?: string | null;
  /** Set when the scan succeeded but the asset-registry upsert did not run, so
   * a clean-looking job with an empty asset list has a visible reason. */
  asset_upsert_error?: string | null;
  /** Hand-outs to an executor. Above 1 means an earlier attempt's lease
   * expired and the job was requeued. */
  attempts?: number;
  /** Persisted start options (intent, mode, delta, wordlist provenance, …). */
  scan_options?: Record<string, unknown> | null;
};

export type ScheduleScanOptions = {
  mode: "safe" | "balanced" | "fast" | "test";
  intent?: ScanIntent | null;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo: boolean;
};

export type ScheduleTargets = {
  ranges: string | null;
  domains: string | null;
  ports: string | null;
  ports_udp: string | null;
};

export type ScanSchedule = {
  schedule_id: string;
  tenant_id: string;
  name: string;
  enabled: boolean;
  cron: string | null;
  interval_seconds: number | null;
  scan_options: ScheduleScanOptions;
  targets: ScheduleTargets;
  next_run_at: string | null;
  last_run_at: string | null;
  last_job_id: string | null;
  created_at: string | null;
  created_by: string | null;
};

export type CreateScheduleBody = {
  tenant_id?: string;
  name: string;
  cron?: string | null;
  interval_seconds?: number | null;
  mode: "safe" | "balanced" | "fast" | "test";
  intent?: ScanIntent | null;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo?: boolean;
  ranges?: string | null;
  domains?: string | null;
  ports?: string | null;
  ports_udp?: string | null;
};

export type UpdateScheduleBody = Partial<
  Omit<CreateScheduleBody, "tenant_id"> & { enabled: boolean }
>;

export type AgentInfo = {
  agent_id: string;
  hostname: string;
  version: string;
  labels: Record<string, string>;
  status: "idle" | "busy" | "error" | "stale";
  current_job_id: string | null;
  detail: string | null;
  registered_at: string | null;
  last_seen_at: string | null;
  online: boolean;
  tenant_id?: string | null;
};

export type TenantInfo = {
  tenant_id: string;
  name: string;
  status: "active" | "disabled";
  created_at: string | null;
};

export type AssetStatus = "active" | "stale" | "decommissioned";

export type AssetIdentifier = {
  identifier_type: string;
  identifier_value: string;
};

export type AssetSummary = {
  asset_id: string;
  status: AssetStatus;
  first_seen: string;
  last_seen: string;
  primary_identifier: string | null;
  identifier_count: number;
  asset_criticality: number | null;
};

export type AssetDetail = {
  asset_id: string;
  tenant_id: string;
  status: AssetStatus;
  first_seen: string;
  last_seen: string;
  owner_email: string | null;
  business_unit: string | null;
  asset_criticality: number | null;
  identifiers: AssetIdentifier[];
  tags: Record<string, string>;
};

export type UpdateAssetBody = {
  owner_email?: string | null;
  business_unit?: string | null;
  asset_criticality?: number | null;
  status?: "decommissioned";
};

export type EndpointReconciliationStatus = "linked" | "conflict" | "unlinked";

export type EndpointDeviceInfo = {
  device_id: string;
  tenant_id: string;
  agent_id: string;
  asset_id: string | null;
  hostname: string;
  os_family: string | null;
  os_name: string | null;
  os_version: string | null;
  os_arch: string | null;
  agent_version: string;
  labels: Record<string, string>;
  reconciliation_status: EndpointReconciliationStatus;
  /** Server-derived staleness (OCTO_ENDPOINT_STALE_HOURS, Agent_plan.md S9). */
  status: "active" | "stale";
  first_seen: string | null;
  last_seen: string | null;
  last_inventory_at: string | null;
  latest_snapshot_id: string | null;
};

export type EndpointSoftwareItemInfo = {
  name: string;
  version: string | null;
  publisher: string | null;
  architecture: string | null;
  source: string;
  install_location: string | null;
};

export type EndpointSoftwareChangeInfo = {
  device_id: string;
  snapshot_id: string;
  event_type: "installed" | "removed" | "updated";
  display_name: string;
  old_version: string | null;
  new_version: string | null;
  observed_at: string | null;
};

export type EndpointSoftwareChangeFeedItem = EndpointSoftwareChangeInfo & {
  hostname: string;
  asset_id: string | null;
};

export type ProvisioningKeyInfo = {
  key_id: string;
  tenant_id: string;
  label: string;
  created_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  key?: string | null;
};

export type ToolVersion = {
  name: string;
  version: string | null;
  error: string | null;
  /** Phase 5: true for tools not required on the default Pulse path (e.g. nmap). */
  optional?: boolean;
};

export type EnrichmentDb = {
  name: string;
  present: boolean;
  path: string;
  size_bytes: number | null;
  modified_at: string | null;
  age_days: number | null;
};

export type ScanConfigSummary = {
  profiles: string[];
  nse_profiles: string[];
  /** service_probe.backend: pulse | nmap | hybrid */
  service_backend?: string;
  stages: Record<string, boolean>;
};

export type RuntimeInfo = {
  allow_scan_start: boolean;
  job_execution_mode: string;
  nats_enabled: boolean;
  clickhouse_enabled: boolean;
  postgres_enabled: boolean;
  ch_ingest_enabled: boolean;
  asset_stale_days: number;
  endpoint_inventory_enabled: boolean;
  endpoint_stale_hours: number;
};

/** Endpoint-inventory footprint and retention posture (Agent_plan.md S9). */
export type EndpointInventoryStatus = {
  enabled: boolean;
  devices_total: number | null;
  devices_stale: number | null;
  stale_hours: number;
  retention_enabled: boolean;
  snapshot_retention_days: number;
  change_retention_days: number;
  retention_interval_seconds: number;
  retention_last_run_at: string | null;
};

export type InventoryCounts = {
  tenants: number | null;
  agents_total: number | null;
  agents_online: number | null;
};

export type SystemStatus = {
  app_version: string;
  tools: ToolVersion[];
  enrichment: EnrichmentDb[];
  scan_config: ScanConfigSummary;
  runtime: RuntimeInfo;
  inventory: InventoryCounts;
  endpoint_inventory: EndpointInventoryStatus;
};

export async function login(username: string, password: string) {
  try {
    const { data } = await api.post<{
      access_token: string;
      role: Role;
      username: string;
    }>("/auth/login", { username, password });
    setAccessToken(data.access_token);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchMe() {
  try {
    const { data } = await api.get<Me>("/auth/me");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Uniform envelope returned by every paginated list endpoint (ROADMAP P3.2). */
export type Page<T> = {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
};

export type PageParams = {
  offset?: number;
  limit?: number;
  q?: string;
  sort?: string;
  order?: "asc" | "desc";
};

/** Only sends the params the caller actually set, so the server defaults stay authoritative. */
function pageSearchParams(page?: PageParams, base?: Record<string, string>): URLSearchParams {
  const params = new URLSearchParams(base);
  if (page?.offset != null) params.set("offset", String(page.offset));
  if (page?.limit != null) params.set("limit", String(page.limit));
  if (page?.q) params.set("q", page.q);
  if (page?.sort) params.set("sort", page.sort);
  if (page?.order) params.set("order", page.order);
  return params;
}

export async function fetchRuns(page?: PageParams) {
  try {
    const { data } = await api.get<Page<RunSummary>>(`/runs?${pageSearchParams(page)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchRun(runId: string) {
  try {
    const { data } = await api.get<RunDetail>(`/runs/${encodeURIComponent(runId)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchVulns(
  runId: string,
  limit = 5000,
  host?: string | null,
  port?: string | null,
) {
  try {
    const params = new URLSearchParams({ limit: String(limit) });
    if (host) params.set("host", host);
    if (port) params.set("port", port);
    const { data } = await api.get<Vulnerability[]>(
      `/runs/${encodeURIComponent(runId)}/vulnerabilities?${params}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchHosts(runId: string, limit = 10000) {
  try {
    const { data } = await api.get<AliveHost[]>(
      `/runs/${encodeURIComponent(runId)}/hosts?limit=${limit}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchPorts(runId: string, limit = 10000) {
  try {
    const { data } = await api.get<PortAggregate[]>(
      `/runs/${encodeURIComponent(runId)}/ports?limit=${limit}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Encode each path segment but keep the "/" separators for the :path route param. */
function encodeArtifactPath(path: string): string {
  return path
    .split("/")
    .map(encodeURIComponent)
    .join("/");
}

/** Raw text of a run artifact (JSON/TXT/MD) for in-UI preview. Kept as a plain
 * string (no JSON.parse) so JSON artifacts render as formatted source. */
export async function fetchArtifactText(runId: string, path: string) {
  try {
    const { data } = await api.get<string>(
      `/runs/${encodeURIComponent(runId)}/artifacts/${encodeArtifactPath(path)}`,
      { responseType: "text", transformResponse: (value) => value },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Programmatically trigger a browser "Save as" for an in-memory blob. */
export function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/** Download a run artifact (binary-safe, e.g. summary.pdf). Fetches as a blob
 * via axios so the Authorization interceptor applies — a plain <a href> would
 * not carry the bearer token. */
export async function downloadArtifact(runId: string, path: string) {
  try {
    const { data } = await api.get<Blob>(
      `/runs/${encodeURIComponent(runId)}/download/${encodeArtifactPath(path)}`,
      { responseType: "blob" },
    );
    triggerBrowserDownload(data, path.split("/").pop() || "artifact");
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAgents(page?: PageParams) {
  try {
    const { data } = await api.get<Page<AgentInfo>>(`/agents?${pageSearchParams(page)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchJobs(page?: PageParams) {
  try {
    const { data } = await api.get<Page<JobInfo>>(`/jobs?${pageSearchParams(page)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type WordlistKind = "subdomain" | "bucket";

export type WordlistInfo = {
  wordlist_id: string;
  tenant_id: string;
  name: string;
  kind: WordlistKind;
  line_count: number;
  sha256: string;
  created_at: string | null;
  created_by: string | null;
};

// The request interceptor attaches the active tenant to every call, so these
// need no explicit tenant param — list/upload/delete all act in the caller's
// current tenant, the same way jobs and schedules do.
export async function fetchWordlists() {
  try {
    const { data } = await api.get<WordlistInfo[]>("/wordlists");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function uploadWordlist(input: {
  file: File;
  kind: WordlistKind;
  name?: string;
}) {
  try {
    const form = new FormData();
    form.append("file", input.file);
    form.append("kind", input.kind);
    if (input.name) form.append("name", input.name);
    const { data } = await api.post<WordlistInfo>("/wordlists", form);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteWordlist(wordlistId: string) {
  try {
    await api.delete(`/wordlists/${wordlistId}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function startScan(body: {
  mode: string;
  intent?: ScanIntent | null;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo?: boolean;
  ranges?: string;
  domains?: string;
  ports?: string;
  ports_udp?: string;
  tenant_id?: string;
  wordlist_id?: string;
}) {
  try {
    const { data } = await api.post<JobInfo>("/jobs", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchSchedules(tenantId?: string, page?: PageParams) {
  try {
    const params = pageSearchParams(page, tenantParam(tenantId));
    const { data } = await api.get<Page<ScanSchedule>>(`/schedules?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createSchedule(body: CreateScheduleBody) {
  try {
    const { data } = await api.post<ScanSchedule>("/schedules", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function updateSchedule(scheduleId: string, body: UpdateScheduleBody) {
  try {
    const { data } = await api.patch<ScanSchedule>(
      `/schedules/${encodeURIComponent(scheduleId)}`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteSchedule(scheduleId: string) {
  try {
    await api.delete(`/schedules/${encodeURIComponent(scheduleId)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Cross-run asset inventory (Phase 7) — distinct from the per-run hosts/ports/vulns above. */
export async function fetchAssets(
  opts?: { tenantId?: string; status?: AssetStatus | ""; unowned?: boolean },
  page?: PageParams,
) {
  try {
    const params = pageSearchParams(page, tenantParam(opts?.tenantId));
    if (opts?.status) params.set("status", opts.status);
    if (opts?.unowned) params.set("unowned", "true");
    const { data } = await api.get<Page<AssetSummary>>(`/assets?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAssetSummary() {
  try {
    const { data } = await api.get<AssetInventorySummary>("/assets/summary");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAsset(assetId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.get<AssetDetail>(`/assets/${encodeURIComponent(assetId)}?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** All Lariska endpoint devices for a tenant (optional filter by linked asset). */
export async function fetchEndpointDevices(opts?: {
  tenantId?: string;
  assetId?: string;
}) {
  try {
    const params = new URLSearchParams(tenantParam(opts?.tenantId));
    if (opts?.assetId) params.set("asset_id", opts.assetId);
    const { data } = await api.get<EndpointDeviceInfo[]>(`/endpoint/devices?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Endpoint/software inventory from the Lariska agent (Agent_plan.md S1-S7),
 * scoped to the network-scan asset it reconciled to — distinct from
 * fetchAssets/fetchAsset above. */
export async function fetchEndpointDevicesForAsset(assetId: string, tenantId = "default") {
  return fetchEndpointDevices({ tenantId, assetId });
}

export async function fetchAssetSoftware(assetId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.get<EndpointSoftwareItemInfo[]>(
      `/assets/${encodeURIComponent(assetId)}/software?${params}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchEndpointDeviceChanges(deviceId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.get<EndpointSoftwareChangeInfo[]>(
      `/endpoint/devices/${encodeURIComponent(deviceId)}/changes?${params}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Cross-device recent software-change feed (installed/removed/updated),
 * newest first — the global counterpart to fetchEndpointDeviceChanges. */
export async function fetchRecentSoftwareChanges(opts?: {
  tenantId?: string;
  limit?: number;
}) {
  try {
    const params = new URLSearchParams(tenantParam(opts?.tenantId));
    params.set("limit", String(opts?.limit ?? 50));
    const { data } = await api.get<EndpointSoftwareChangeFeedItem[]>(
      `/endpoint/changes?${params}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchSystemStatus() {
  try {
    const { data } = await api.get<SystemStatus>("/system");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type ConfigResponse = {
  editable_paths: string[];
  defaults: Record<string, unknown>;
  effective: Record<string, unknown>;
  overrides: Record<string, unknown>;
};

export async function fetchConfig() {
  try {
    const { data } = await api.get<ConfigResponse>("/config");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Replace the installation-wide scanner-config overrides (admin only).
 * `overrides` is a flat dot-path → value map of only the settings that differ
 * from the base config; an empty object clears all overrides. */
export async function updateConfig(overrides: Record<string, unknown>) {
  try {
    const { data } = await api.put<ConfigResponse>("/config", { overrides });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Operator-only partial update of an asset (owner/business unit/criticality,
 * or a one-way decommission). Backed by PATCH /api/assets/{id}. */
export async function updateAsset(assetId: string, body: UpdateAssetBody, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.patch<AssetDetail>(
      `/assets/${encodeURIComponent(assetId)}?${params}`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchTenants() {
  try {
    const { data } = await api.get<TenantInfo[]>("/tenants");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createTenant(body: { name: string; tenant_id?: string }) {
  try {
    const { data } = await api.post<TenantInfo>("/tenants", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createProvisioningKey(tenantId: string, label = "") {
  try {
    const { data } = await api.post<ProvisioningKeyInfo>(
      `/tenants/${encodeURIComponent(tenantId)}/provisioning-keys`,
      { label },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Persistent finding across runs (#145). Distinct from `Vulnerability`, which
 * is a *run's* observation read off disk. */
export type VulnLifecycleState =
  | "OPEN"
  | "ACKNOWLEDGED"
  | "PLANNED"
  | "FIXING"
  | "VERIFYING"
  | "CLOSED";

export type SlaState = "on_track" | "due_soon" | "breached" | "accepted" | "none";

export type TrackedVulnerability = {
  vuln_id: string;
  tenant_id: string;
  asset_id: string;
  finding_key: string;
  cve: string | null;
  script_id: string | null;
  title: string;
  port: string | null;
  severity: string;
  risk_level: string | null;
  contextual_score: number | null;
  cvss: number | null;
  state: VulnLifecycleState;
  state_changed_at: string | null;
  state_changed_by: string | null;
  assignee: string | null;
  owner_team: string | null;
  due_at: string | null;
  sla_days: number | null;
  sla_source: string | null;
  sla_state: SlaState;
  exception_until: string | null;
  exception_reason: string | null;
  exception_by: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  sla_started_at: string | null;
  first_seen_run_id: string | null;
  last_seen_run_id: string | null;
  observation_count: number;
  reopen_count: number;
  closed_at: string | null;
  ticket_system: string | null;
  ticket_key: string | null;
  ticket_url: string | null;
};

export type TicketSystem = "jira" | "servicenow" | "smax" | "defectdojo" | "other";

export type VulnerabilityTicketBody = {
  system: TicketSystem;
  key?: string | null;
  url?: string | null;
  note?: string | null;
};

export type VulnerabilityEventInfo = {
  id: number;
  vuln_id: string;
  tenant_id: string;
  occurred_at: string | null;
  kind: string;
  from_state: string | null;
  to_state: string | null;
  actor: string | null;
  note: string | null;
  detail: Record<string, unknown>;
};

export type NistRiskLevel = "very_low" | "low" | "moderate" | "high" | "very_high";

export type VulnerabilitySummary = {
  total: number;
  open_total: number;
  untriaged: number;
  unassigned: number;
  estate_risk: NistRiskLevel | null;
  by_state: Record<string, number>;
  by_severity_open: Record<string, number>;
  by_risk_level_open: Record<string, number>;
  by_sla: Record<string, number>;
  breached: number;
  worst_breached_severity: string | null;
  generated_at: string | null;
};

export type AssetInventorySummary = {
  total: number;
  unowned: number;
  by_status: Record<string, number>;
  by_criticality: Record<string, number>;
  generated_at: string | null;
};

export type VulnerabilityListFilters = {
  state?: VulnLifecycleState | "";
  open_only?: boolean;
  severity?: string;
  asset_id?: string;
  assignee?: string;
  unassigned?: boolean;
  sla?: SlaState | "";
  stale_days?: number;
};

export type VulnerabilityTransitionBody = {
  state: VulnLifecycleState;
  note?: string | null;
};

export type VulnerabilityAssignBody = {
  assignee?: string | null;
  owner_team?: string | null;
  note?: string | null;
};

export type VulnerabilityExceptionBody = {
  until: string;
  reason: string;
};

export async function fetchTrackedVulnerabilities(
  filters?: VulnerabilityListFilters,
  page?: PageParams,
) {
  try {
    const params = pageSearchParams(page);
    if (filters?.state) params.set("state", filters.state);
    if (filters?.open_only) params.set("open_only", "true");
    if (filters?.severity) params.set("severity", filters.severity);
    if (filters?.asset_id) params.set("asset_id", filters.asset_id);
    if (filters?.assignee) params.set("assignee", filters.assignee);
    if (filters?.unassigned) params.set("unassigned", "true");
    if (filters?.sla) params.set("sla", filters.sla);
    if (filters?.stale_days != null) params.set("stale_days", String(filters.stale_days));
    const { data } = await api.get<Page<TrackedVulnerability>>(`/vulnerabilities?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchVulnerabilitySummary() {
  try {
    const { data } = await api.get<VulnerabilitySummary>("/vulnerabilities/summary");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchTrackedVulnerability(vulnId: string) {
  try {
    const { data } = await api.get<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchVulnerabilityEvents(vulnId: string, page?: PageParams) {
  try {
    const { data } = await api.get<Page<VulnerabilityEventInfo>>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/events?${pageSearchParams(page)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchVulnerabilityActivity(page?: PageParams) {
  try {
    const { data } = await api.get<Page<VulnerabilityEventInfo>>(
      `/vulnerabilities/events?${pageSearchParams(page)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function transitionVulnerability(vulnId: string, body: VulnerabilityTransitionBody) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/transition`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function assignVulnerability(vulnId: string, body: VulnerabilityAssignBody) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/assign`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function setVulnerabilityException(vulnId: string, body: VulnerabilityExceptionBody) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/exception`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function clearVulnerabilityException(vulnId: string) {
  try {
    const { data } = await api.delete<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/exception`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function commentOnVulnerability(vulnId: string, note: string) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/comment`,
      { note },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function setVulnerabilityTicket(vulnId: string, body: VulnerabilityTicketBody) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/ticket`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function clearVulnerabilityTicket(vulnId: string) {
  try {
    const { data } = await api.delete<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/ticket`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}
