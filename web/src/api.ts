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
  severity: string | null;
  script_id: string | null;
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

export function fetchVulns(token: string, runId: string) {
  return request<Vulnerability[]>(
    `/api/runs/${encodeURIComponent(runId)}/vulnerabilities?limit=100`,
    {},
    token,
  );
}

export function fetchJobs(token: string) {
  return request<JobInfo[]>("/api/jobs", {}, token);
}

export function startScan(
  token: string,
  body: { mode: string; delta: boolean; skip_nse: boolean; notify: boolean },
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
