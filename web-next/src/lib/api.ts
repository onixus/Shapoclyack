import axios from "axios";

const TOKEN_KEY = "octo_man_access_token";

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

export type ProvisioningKeyInfo = {
  key_id: string;
  tenant_id: string;
  label: string;
  created_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  key?: string | null;
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

export async function fetchVulns(runId: string, limit = 5000, host?: string | null, port?: string | null) {
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
