export type Role = "viewer" | "operator" | "admin";

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
};

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null,
): Promise<T> {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const payload = await response.json();
      detail = payload.detail || detail;
    } catch {
      /* ignore */
    }
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

export function login(username: string, password: string) {
  return request<{
    access_token: string;
    role: Role;
    username: string;
  }>("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function fetchMe(token: string) {
  return request<{ username: string; role: Role }>("/api/auth/me", {}, token);
}

export function fetchRuns(token: string) {
  return request<RunSummary[]>("/api/runs", {}, token);
}

export function fetchRun(token: string, runId: string) {
  return request<RunDetail>(`/api/runs/${encodeURIComponent(runId)}`, {}, token);
}

export function fetchVulns(
  token: string,
  runId: string,
  limit = 5000,
  host?: string | null,
  port?: string | null,
) {
  const params = new URLSearchParams({ limit: String(limit) });
  if (host) {
    params.set("host", host);
  }
  if (port) {
    params.set("port", port);
  }
  return request<Vulnerability[]>(
    `/api/runs/${encodeURIComponent(runId)}/vulnerabilities?${params}`,
    {},
    token,
  );
}

export function fetchHosts(token: string, runId: string, limit = 10000) {
  return request<AliveHost[]>(
    `/api/runs/${encodeURIComponent(runId)}/hosts?limit=${limit}`,
    {},
    token,
  );
}

export function fetchPorts(token: string, runId: string, limit = 10000) {
  return request<PortAggregate[]>(
    `/api/runs/${encodeURIComponent(runId)}/ports?limit=${limit}`,
    {},
    token,
  );
}

export function fetchJobs(token: string) {
  return request<JobInfo[]>("/api/jobs", {}, token);
}

export function fetchAgents(token: string) {
  return request<AgentInfo[]>("/api/agents", {}, token);
}

export function startScan(
  token: string,
  body: {
    mode: string;
    delta: boolean;
    skip_nse: boolean;
    notify: boolean;
    export_defectdojo?: boolean;
    ranges?: string;
    domains?: string;
    ports?: string;
    ports_udp?: string;
  },
) {
  return request<JobInfo>(
    "/api/jobs",
    {
      method: "POST",
      body: JSON.stringify(body),
    },
    token,
  );
}
