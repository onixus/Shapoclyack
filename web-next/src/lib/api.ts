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

/** Operator-only screenshot manifest (P4.4). Pixels can still hold PII. */
export type ScreenshotItem = {
  host: string | null;
  port: number | string | null;
  scheme: string | null;
  url: string | null;
  file: string;
  redacted_fields: number;
  available: boolean;
};

export type ScreenshotManifest = {
  skipped_reason: string | null;
  captured_count: number;
  redacted_fields: number;
  truncated: boolean;
  retention_days: number;
  items: ScreenshotItem[];
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
  /** P4.3: operator-set. Never inferred from a public IP or ASN. */
  owner_email?: string | null;
  business_unit?: string | null;
  asset_id?: string | null;
  registrable_domain?: string | null;
  ownership_source?: string | null;
};

export type PortAggregate = {
  port: string;
  protocol: string | null;
  host_count: number;
  vulnerability_count: number;
  hosts: string[];
  services: string[];
};

export type ScanIntent = "inventory" | "vuln" | "full" | "delta" | "org_profile";

export type ControlFinding = {
  id: string;
  domain?: string | null;
  severity: "critical" | "high" | "medium" | "low" | string;
  detail?: string | null;
};

export type ControlCoverage = {
  checked: number;
  total: number;
};

export type ControlStatus = "ok" | "weak" | "fail" | "not_checked" | "error";

export type ControlItem = {
  control: string;
  title: string;
  status: ControlStatus;
  impact: "critical" | "high" | "medium" | "low" | string;
  coverage: ControlCoverage;
  findings_by_severity: Record<string, number>;
  top_findings: ControlFinding[];
  evidence: string[];
  why: string;
  risk_level: string;
};

export type OrgProfileControlsSummary = {
  overall_verdict: ControlStatus;
  overall_risk: string;
  controls: ControlItem[];
  evaluated_at?: string | null;
};

export type RelatedDomainEvidence = {
  source: string;
  indicator?: string | null;
  detail?: string | null;
};

export type RelatedDomainCandidate = {
  domain: string;
  status: "confirmed" | "candidate";
  confidence: number;
  sources: string[];
  evidence: RelatedDomainEvidence[];
};

export type RelatedDomainsSummary = {
  status: string;
  seed_domains: string[];
  confirmed_count: number;
  candidate_count: number;
  total_candidates: number;
  truncated: boolean;
  auto_merged: boolean;
  merge_into_scope?: boolean;
  merged_domains: string[];
  disclaimer: string;
  candidates: RelatedDomainCandidate[];
  evaluated_at?: string | null;
};

export type OrgProfileDetail = {
  run_id: string;
  seed_domains: string[];
  ownership?: Record<string, unknown> | null;
  /** True when `ownership` was withheld because the caller is a viewer. */
  ownership_restricted?: boolean;
  related_domains?: RelatedDomainsSummary | null;
  controls?: OrgProfileControlsSummary | null;
  promoted_domains: string[];
  generated_at?: string | null;
};

export type PromoteDomainResponse = {
  domain: string;
  promoted: boolean;
  message: string;
  promoted_at?: string | null;
};

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
  metrics?: {
    cpu_percent?: number;
    memory_used_mb?: number;
    memory_total_mb?: number;
    memory_percent?: number;
    disk_free_gb?: number;
    disk_total_gb?: number;
    disk_percent?: number;
    uptime_seconds?: number;
    os?: string;
    release?: string;
    arch?: string;
    load_1m?: number;
    load_5m?: number;
  };
  capabilities?: string[];
  is_outdated?: boolean;
  latest_version?: string;
  upgrade_requested?: boolean;
};

export type AgentFleetSummary = {
  total_agents: number;
  online_agents: number;
  busy_agents: number;
  stale_agents: number;
  error_agents: number;
  outdated_agents: number;
  latest_version: string;
  by_tenant: Record<string, number>;
};

export type AgentDeploySSHRequest = {
  host: string;
  port?: number;
  username?: string;
  password?: string;
  private_key?: string;
  tenant_id?: string;
  agent_id?: string;
  install_dir?: string;
  use_docker?: boolean;
  /** SHA256 fingerprint the operator read off the target itself. Required the
   * first time this tenant deploys to a host; afterwards the stored pin is what
   * is checked. Without it the API refuses rather than trusting any key. */
  expected_host_key?: string | null;
};

export type AgentSSHHostKeyInfo = {
  host: string;
  port: number;
  key_type: string;
  fingerprint: string;
  /** True when this is the tenant's stored key. False means it was just read
   * off the wire and is a claim by whoever answered, not yet trusted. */
  pinned: boolean;
  pinned_at: string | null;
};

export type AgentDeployStatusResponse = {
  deploy_id: string;
  status: "queued" | "connecting" | "installing" | "verifying" | "completed" | "failed";
  stage: string;
  progress_percent: number;
  logs: string[];
  agent_id: string | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
};

export type AgentDeploymentSnippetResponse = {
  tenant_id: string;
  /** Plaintext only on the minting POST; null on the read-only GET. */
  provisioning_key: string | null;
  key_minted: boolean;
  server_url: string;
  systemd_oneliner: string;
  docker_run: string;
  docker_compose: string;
  kubernetes_yaml: string;
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
  owner_email: string | null;
  business_service: string | null;
  environment: string | null;
  exposure_level: string | null;
  open_findings: number;
  unassigned_findings: number;
  estate_risk: string | null;
};

export type AssetEnvironment = "production" | "staging" | "development" | "lab" | "other";
export type AssetDataClassification = "public" | "internal" | "confidential" | "restricted";
export type AssetExposureLevel = "internet" | "partner" | "internal" | "unknown";
export type AssetContextSource = "operator" | "cmdb" | "ad" | "other";

export type AssetRisk = {
  total: number;
  open_total: number;
  untriaged: number;
  unassigned: number;
  estate_risk: string | null;
  by_state: Record<string, number>;
  by_severity_open: Record<string, number>;
  by_risk_level_open: Record<string, number>;
  by_sla: Record<string, number>;
  breached: number;
  worst_breached_severity: string | null;
  generated_at: string | null;
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
  business_service: string | null;
  environment: string | null;
  data_classification: string | null;
  exposure_level: string | null;
  context_source: string | null;
  identifiers: AssetIdentifier[];
  tags: Record<string, string>;
  /** P4.2: named IP↔FQDN evidence. shared/not merged on purpose. */
  identity_links?: AssetIdentityLink[];
  risk: AssetRisk | null;
};

export type AssetIdentityLink = {
  ip: string;
  fqdn: string;
  sources: string[];
  confidence: string;
  shared: boolean;
  merged: boolean;
};

export type AssetContextEvent = {
  id: number;
  asset_id: string;
  tenant_id: string;
  occurred_at: string | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  actor: string | null;
  source: string | null;
};

export type UpdateAssetBody = {
  owner_email?: string | null;
  business_unit?: string | null;
  asset_criticality?: number | null;
  business_service?: string | null;
  environment?: AssetEnvironment | null;
  data_classification?: AssetDataClassification | null;
  exposure_level?: AssetExposureLevel | null;
  context_source?: AssetContextSource | null;
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

/** Four-valued on purpose: "unknown" is a first-class answer, so an endpoint
 * the matcher could not assess never renders as clean
 * (docs/software-cve-matching.md). */
export type SoftwareCveMatchStatus = "vulnerable" | "fixed" | "not_applicable" | "unknown";

export type SoftwareCveMatchInfo = {
  device_id: string;
  hostname: string | null;
  snapshot_id: string | null;
  /** Empty on an ``unknown`` row, which is about a package set, not a CVE. */
  cve_id: string;
  status: SoftwareCveMatchStatus;
  /** The distribution's own word, never a CVSS score re-derived client-side. */
  severity: string;
  source_package: string;
  installed_package: string;
  installed_version: string | null;
  fixed_version: string | null;
  advisory_id: string | null;
  advisory_url: string | null;
  provider: string;
  distro: string | null;
  distro_release: string | null;
  purl: string | null;
  cpe23: string | null;
  unknown_reason: string | null;
  feed_date: string | null;
  evidence: Record<string, unknown>;
  matched_at: string | null;
};

export type SoftwareCveMatchRunSummary = {
  device_id: string;
  snapshot_id: string | null;
  distro: string | null;
  distro_release: string | null;
  packages_total: number;
  packages_assessed: number;
  packages_unassessed: number;
  matches: number;
  by_status: Record<string, number>;
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
  stale?: boolean;
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

export async function fetchRunControls(runId: string) {
  try {
    const { data } = await api.get<OrgProfileControlsSummary>(
      `/runs/${encodeURIComponent(runId)}/controls`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchOrgProfile(runId: string) {
  try {
    const { data } = await api.get<OrgProfileDetail>(
      `/runs/${encodeURIComponent(runId)}/org-profile`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function promoteRelatedDomain(runId: string, domain: string) {
  try {
    const { data } = await api.post<PromoteDomainResponse>(
      `/runs/${encodeURIComponent(runId)}/related-domains/${encodeURIComponent(domain)}/promote`,
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

/** Operator-only screenshot manifest. Viewers 403. */
export async function fetchScreenshots(runId: string) {
  try {
    const { data } = await api.get<ScreenshotManifest>(
      `/runs/${encodeURIComponent(runId)}/screenshots`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Raw PNG bytes for an operator-only screenshot. Caller owns the blob URL. */
export async function fetchScreenshotBlob(runId: string, path: string) {
  try {
    const { data } = await api.get<Blob>(
      `/runs/${encodeURIComponent(runId)}/download/${encodeArtifactPath(path)}`,
      { responseType: "blob" },
    );
    return data;
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

export async function fetchAgentSummary() {
  try {
    const { data } = await api.get<AgentFleetSummary>("/agents/summary");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAgentDetail(agentId: string) {
  try {
    const { data } = await api.get<AgentInfo>(`/agents/${encodeURIComponent(agentId)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteAgent(agentId: string) {
  try {
    const { data } = await api.delete<{ status: string; agent_id: string }>(
      `/agents/${encodeURIComponent(agentId)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function triggerAgentUpgrade(agentId: string) {
  try {
    const { data } = await api.post<{ status: string; agent_id: string; target_version: string }>(
      `/agents/${encodeURIComponent(agentId)}/upgrade`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchAgentDeploymentSnippets() {
  try {
    const { data } = await api.get<AgentDeploymentSnippetResponse>("/agent/deployment-command");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createAgentDeploymentKey(label?: string) {
  try {
    const { data } = await api.post<AgentDeploymentSnippetResponse>(
      "/agent/deployment-command",
      { label: label ?? "" },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function probeAgentSSHHostKey(host: string, port: number) {
  try {
    const { data } = await api.post<AgentSSHHostKeyInfo>("/agent/deploy/ssh/host-key", {
      host,
      port,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deployAgentSSH(body: AgentDeploySSHRequest) {
  try {
    const { data } = await api.post<AgentDeployStatusResponse>("/agent/deploy/ssh", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchDeployStatus(deployId: string) {
  try {
    const { data } = await api.get<AgentDeployStatusResponse>(
      `/agent/deploy/${encodeURIComponent(deployId)}/status`,
    );
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
  opts?: {
    tenantId?: string;
    status?: AssetStatus | "";
    unowned?: boolean;
    exposure?: AssetExposureLevel | "";
  },
  page?: PageParams,
) {
  try {
    const params = pageSearchParams(page, tenantParam(opts?.tenantId));
    if (opts?.status) params.set("status", opts.status);
    if (opts?.unowned) params.set("unowned", "true");
    if (opts?.exposure) params.set("exposure", opts.exposure);
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

export async function fetchAssetContextEvents(assetId: string, tenantId = "default", page?: PageParams) {
  try {
    const params = pageSearchParams(page, tenantParam(tenantId));
    const { data } = await api.get<Page<AssetContextEvent>>(
      `/assets/${encodeURIComponent(assetId)}/events?${params}`,
    );
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

/** Vendor-advisory CVE matches for one endpoint (ROADMAP Track E M1). */
export async function fetchEndpointCveMatches(deviceId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.get<SoftwareCveMatchInfo[]>(
      `/endpoint/devices/${encodeURIComponent(deviceId)}/cve-matches?${params}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Re-run the matcher for one endpoint against the advisory data on disk.
 * Requires operator; the rows are derived and replaced wholesale. */
export async function refreshEndpointCveMatches(deviceId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.post<SoftwareCveMatchRunSummary>(
      `/endpoint/devices/${encodeURIComponent(deviceId)}/cve-matches/refresh?${params}`,
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

export type TenantPosture = {
  tenant_id: string;
  name: string;
  status: string;
  estate_risk: string | null;
  open_total: number;
  unassigned: number;
  breached: number;
  in_kev_open: number;
  unowned_assets: number;
  declared_internet_assets: number;
};

export async function fetchTenantPosture() {
  try {
    const { data } = await api.get<TenantPosture[]>("/tenants/posture");
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
  cwe: string[];
  script_id: string | null;
  title: string;
  port: string | null;
  severity: string;
  risk_level: string | null;
  contextual_score: number | null;
  cvss: number | null;
  in_kev: boolean;
  exploit_maturity: string | null;
  network_exposure: string | null;
  network_exposure_source: string | null;
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
  /** Set by the ingest path when a dispatched verification run did not
   * re-observe the finding. Never settable through the API. */
  machine_verified?: boolean;
  verification_job_id?: string | null;
  last_verified_at?: string | null;
  /** verified_remediated | manual | ticket_resolved. */
  closure_reason?: string | null;
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
  closed_total?: number;
  machine_verified_closed?: number;
  manual_closed?: number;
  /** Share of closures a scan confirmed, 0-100. */
  machine_verification_rate?: number;
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
  in_kev?: boolean;
};

export type VulnerabilityTransitionBody = {
  state: VulnLifecycleState;
  note?: string | null;
  closure_reason?: string | null;
  machine_verified?: boolean;
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
    if (filters?.in_kev) params.set("in_kev", "true");
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

export async function triggerVulnVerification(vulnId: string) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/verify`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function syncVulnTicket(vulnId: string) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/ticket/sync`,
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



export type RiskScoreSnapshot = {
  snapshot_id: string;
  tenant_id: string;
  recorded_at: string | null;
  estate_risk: NistRiskLevel | null;
  open_total: number;
  total: number;
  untriaged: number;
  unassigned: number;
  breached: number;
  worst_breached_severity: string | null;
  by_severity_open: Record<string, number>;
  by_risk_level_open: Record<string, number>;
  by_state: Record<string, number>;
  by_sla: Record<string, number>;
  source: string;
};

export async function fetchRiskHistory(params?: {
  since?: string;
  until?: string;
  limit?: number;
}) {
  try {
    const sp = new URLSearchParams();
    if (params?.since) sp.set("since", params.since);
    if (params?.until) sp.set("until", params.until);
    if (params?.limit) sp.set("limit", String(params.limit));
    const qs = sp.toString();
    const { data } = await api.get<RiskScoreSnapshot[]>(
      `/vulnerabilities/risk-history${qs ? `?${qs}` : ""}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function triggerRiskSnapshot() {
  try {
    const { data } = await api.post<RiskScoreSnapshot>(
      "/vulnerabilities/risk-history/snapshot",
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}


/** Whether this installation offers single sign-on (ROADMAP Track E).
 * Deliberately unauthenticated and deliberately not the issuer: the login form
 * renders before anyone is signed in, and the provider URL names the
 * customer's identity vendor. */
export type SsoStatus = {
  enabled: boolean;
  login_url: string;
};

/** An API that predates SSO answers 404, and an unreachable one answers
 * nothing; both read as "no SSO" rather than an error worth showing on a login
 * form. The button is an enhancement — password login has to keep working when
 * this call fails. */
export async function fetchSsoStatus(): Promise<SsoStatus> {
  const fallback: SsoStatus = { enabled: false, login_url: "/api/auth/oidc/login" };
  try {
    const { data } = await api.get<SsoStatus>("/auth/sso");
    return data ?? fallback;
  } catch {
    return fallback;
  }
}

/** A non-interactive API credential (ROADMAP Track E). `token` is present only
 * in the create response — only a hash is stored, so it can never be read
 * back. */
export type ServiceTokenInfo = {
  token_id: string;
  tenant_id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  role: Role;
  status: "active" | "expired" | "revoked";
  created_by: string | null;
  created_at: string | null;
  expires_at: string | null;
  last_used_at: string | null;
  revoked_at: string | null;
  token?: string | null;
};

export async function fetchServiceTokens(tenantId: string) {
  try {
    const { data } = await api.get<ServiceTokenInfo[]>(
      `/tenants/${encodeURIComponent(tenantId)}/service-tokens`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createServiceToken(
  tenantId: string,
  body: { name: string; scopes: string[]; role: Role; expires_in_days?: number },
) {
  try {
    const { data } = await api.post<ServiceTokenInfo>(
      `/tenants/${encodeURIComponent(tenantId)}/service-tokens`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function revokeServiceToken(tenantId: string, tokenId: string) {
  try {
    const { data } = await api.post<ServiceTokenInfo>(
      `/tenants/${encodeURIComponent(tenantId)}/service-tokens/${encodeURIComponent(tokenId)}/revoke`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

// --------------------------------------------------------------------------
// Compliance mapping & report factory (Sprint 4)
// --------------------------------------------------------------------------

export type ComplianceFrameworkInfo = {
  framework_id: string;
  name: string;
  version: string;
  /** What the catalogue deliberately leaves out. Rendered next to the score so
   * "82% of PCI DSS" is never read as "82% compliant". */
  scope_note: string;
  control_count: number;
};

export type ComplianceEvidenceItem = {
  kind: string;
  ref_id: string;
  label: string;
  severity: string;
  detail: string;
  signals: string[];
  accepted: boolean;
};

export type ComplianceControlStatus = {
  control_id: string;
  title: string;
  status: "passed" | "failed" | "not_assessed";
  rationale: string;
  signals: string[];
  /** Signal groups that fail the control only together, on the same evidence. */
  combinations: string[][];
  severity_floor: string;
  failing_count: number;
  accepted_count: number;
  evidence: ComplianceEvidenceItem[];
  not_assessed_reason: string | null;
  framework_id?: string | null;
};

export type CompliancePosture = {
  framework_id: string;
  name: string;
  version: string;
  scope_note: string;
  generated_at: string;
  asset_count: number;
  open_findings: number;
  controls_total: number;
  controls_assessed: number;
  controls_passed: number;
  controls_failed: number;
  controls_not_assessed: number;
  /** Share of the *assessed* controls that pass; null when nothing could be
   * assessed, which is not the same as 100%. */
  coverage_score: number | null;
  controls: ComplianceControlStatus[];
};

export async function fetchComplianceFrameworks() {
  try {
    const { data } = await api.get<ComplianceFrameworkInfo[]>("/compliance/frameworks");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchCompliancePosture(frameworkId: string) {
  try {
    const { data } = await api.get<CompliancePosture>(
      `/compliance/${encodeURIComponent(frameworkId)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchComplianceControl(frameworkId: string, controlId: string) {
  try {
    const { data } = await api.get<ComplianceControlStatus>(
      `/compliance/${encodeURIComponent(frameworkId)}/controls/${encodeURIComponent(controlId)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type TenantBrandingInfo = {
  tenant_id: string;
  org_name: string | null;
  primary_color: string | null;
  accent_color: string | null;
  logo_png: string | null;
  footer_text: string | null;
  contact_email: string | null;
  updated_at: string | null;
  updated_by: string | null;
};

export type ReportTemplateInfo = {
  template_id: string;
  tenant_id: string;
  name: string;
  kind: "executive" | "technical" | "compliance";
  framework_id: string | null;
  sections: Record<string, boolean>;
  created_at: string | null;
  created_by: string | null;
  updated_at: string | null;
};

export type ReportRecipient = { transport: "email" | "webhook"; target: string };

export type ReportScheduleInfo = {
  schedule_id: string;
  tenant_id: string;
  template_id: string;
  name: string;
  enabled: boolean;
  cron: string;
  format: "pdf" | "html" | "json";
  recipients: ReportRecipient[];
  next_run_at: string | null;
  last_run_at: string | null;
  last_report_id: string | null;
  created_at: string | null;
  created_by: string | null;
};

export type GeneratedReportInfo = {
  report_id: string;
  tenant_id: string;
  template_id: string | null;
  schedule_id: string | null;
  kind: string;
  format: "pdf" | "html" | "json";
  status: "pending" | "ready" | "failed";
  title: string;
  size_bytes: number;
  error: string | null;
  /** One entry per recipient — "sent" is not true when three of four bounced. */
  delivery: { transport: string | null; target: string | null; status: string; error: string | null }[];
  generated_at: string | null;
  generated_by: string | null;
};

export async function fetchBranding() {
  try {
    const { data } = await api.get<TenantBrandingInfo>("/reports/branding");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function updateBranding(body: Partial<Omit<TenantBrandingInfo, "tenant_id">>) {
  try {
    const { data } = await api.put<TenantBrandingInfo>("/reports/branding", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchReportTemplates() {
  try {
    const { data } = await api.get<ReportTemplateInfo[]>("/reports/templates");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type CreateReportTemplateBody = {
  name: string;
  kind: ReportTemplateInfo["kind"];
  framework_id?: string | null;
  sections?: Record<string, boolean>;
};

export async function createReportTemplate(body: CreateReportTemplateBody) {
  try {
    const { data } = await api.post<ReportTemplateInfo>("/reports/templates", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteReportTemplate(templateId: string) {
  try {
    await api.delete(`/reports/templates/${encodeURIComponent(templateId)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchReportSchedules() {
  try {
    const { data } = await api.get<ReportScheduleInfo[]>("/reports/schedules");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type CreateReportScheduleBody = {
  template_id: string;
  name: string;
  cron: string;
  format: ReportScheduleInfo["format"];
  recipients: ReportRecipient[];
  enabled?: boolean;
};

export async function createReportSchedule(body: CreateReportScheduleBody) {
  try {
    const { data } = await api.post<ReportScheduleInfo>("/reports/schedules", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteReportSchedule(scheduleId: string) {
  try {
    await api.delete(`/reports/schedules/${encodeURIComponent(scheduleId)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchGeneratedReports(limit = 50) {
  try {
    const { data } = await api.get<GeneratedReportInfo[]>("/reports", { params: { limit } });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type GenerateReportBody = {
  template_id?: string | null;
  kind?: ReportTemplateInfo["kind"];
  framework_id?: string | null;
  format?: GeneratedReportInfo["format"];
  title?: string | null;
};

export async function generateReport(body: GenerateReportBody) {
  try {
    const { data } = await api.post<GeneratedReportInfo>("/reports/generate", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Fetched as a blob through axios so the bearer token is attached — a plain
 * <a href> would download an HTML 401 page instead. */
export async function downloadGeneratedReport(report: GeneratedReportInfo) {
  try {
    const { data } = await api.get<Blob>(
      `/reports/${encodeURIComponent(report.report_id)}/download`,
      { responseType: "blob" },
    );
    triggerBrowserDownload(data, `${report.report_id}.${report.format}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteGeneratedReport(reportId: string) {
  try {
    await api.delete(`/reports/${encodeURIComponent(reportId)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}
