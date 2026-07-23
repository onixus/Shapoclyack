import axios from "axios";

const TOKEN_KEY = "shapoclyack_access_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
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
};

export type RunSummary = {
  run_id: string;
  profile: string | null;
  started_at: string | null;
  alive_hosts: number | null;
  open_host_port_pairs: number | null;
  potential_vulnerabilities: number | null;
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
};

export type AliveHost = {
  host: string;
  hostname: string | null;
  names: string[];
  country: string | null;
  city: string | null;
  country_iso: string | null;
  os_name: string | null;
  os_accuracy: number | null;
  vulnerability_count: number;
};

export type PortAggregate = {
  port: string;
  protocol: string | null;
  host_count: number;
  vulnerability_count: number;
  hosts: string[];
};

export type JobInfo = {
  job_id: string;
  status: "queued" | "running" | "succeeded" | "failed";
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
};

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
};

export type AssetDetail = {
  asset_id: string;
  tenant_id: string;
  status: AssetStatus;
  first_seen: string;
  last_seen: string;
  owner_email: string | null;
  business_unit: string | null;
  identifiers: AssetIdentifier[];
  tags: Record<string, string>;
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

export async function fetchRuns() {
  try {
    const { data } = await api.get<RunSummary[]>("/runs");
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

export async function fetchAgents() {
  try {
    const { data } = await api.get<AgentInfo[]>("/agents");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchJobs() {
  try {
    const { data } = await api.get<JobInfo[]>("/jobs");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function startScan(body: {
  mode: string;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo?: boolean;
  ranges?: string;
  domains?: string;
  ports?: string;
  ports_udp?: string;
  tenant_id?: string;
}) {
  try {
    const { data } = await api.post<JobInfo>("/jobs", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Cross-run asset inventory (Phase 7) — distinct from the per-run hosts/ports/vulns above. */
export async function fetchAssets(opts?: {
  tenantId?: string;
  status?: AssetStatus | "";
  q?: string;
  limit?: number;
}) {
  try {
    const params = new URLSearchParams({ tenant_id: opts?.tenantId || "default" });
    if (opts?.status) params.set("status", opts.status);
    if (opts?.q) params.set("q", opts.q);
    params.set("limit", String(opts?.limit ?? 500));
    const { data } = await api.get<AssetSummary[]>(`/assets?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAsset(assetId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams({ tenant_id: tenantId });
    const { data } = await api.get<AssetDetail>(`/assets/${encodeURIComponent(assetId)}?${params}`);
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
