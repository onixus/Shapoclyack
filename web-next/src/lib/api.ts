import axios from "axios";
import { isStepUpRefusal, useStepUpStore } from "@/lib/step-up";
import type { AxiosError } from "axios";

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
    // A 403 that means "prove the second factor again" (#315), rather than
    // "your role does not reach this". The session is fine and nothing about
    // signing out would help, so this raises the re-verify dialog instead —
    // and still rejects, because the request itself did not happen.
    const detail = error?.response?.data?.detail;
    if (isStepUpRefusal(error?.response?.status, detail)) {
      useStepUpStore.getState().request(String(detail));
    }
    return Promise.reject(error);
  },
);

/** The field a pydantic error points at, spelled the way the sender wrote the
 * payload: `["body", "entries", 0, "value"]` reads back as `entries[0].value`.
 * "body" is where the payload is, not a field anybody named. */
function errorLocation(loc: unknown[]): string {
  return loc
    .filter((part) => part !== "body")
    .reduce<string>(
      (path, part) =>
        typeof part === "number" ? `${path}[${part}]` : path ? `${path}.${part}` : String(part),
      "",
    );
}

/** A schema violation arrives as a list of `{loc, msg}` rather than as the
 * string a handler raises — a scan-scope value over 255 characters or a scope
 * of more than 1000 entries (#226) is refused that way. Stringified as JSON it
 * reaches the toast as unreadable machinery, so flatten it into the lines it
 * was already made of. Returns null for a shape that is not that, which is
 * then left to the caller to render as it did before. */
function pydanticErrorMessage(detail: unknown[]): string | null {
  if (detail.length === 0) return null;
  const lines: string[] = [];
  for (const item of detail) {
    if (!item || typeof item !== "object") return null;
    const { loc, msg } = item as { loc?: unknown; msg?: unknown };
    if (typeof msg !== "string") return null;
    const where = Array.isArray(loc) ? errorLocation(loc) : "";
    lines.push(where ? `${where}: ${msg}` : msg);
  }
  return lines.join("; ");
}

/** The correlation id the API put on the response, when there is one worth
 * showing (#330). Only for a server-side failure: a 422 already says what the
 * user typed wrong, while a 500 says nothing an operator can act on without
 * the id to grep the API logs for. Reading it cross-origin depends on the
 * `expose_headers` the API sets; absent that, or on a network error with no
 * response at all, this is null and the message is unchanged. */
function serverErrorRequestId(error: AxiosError): string | null {
  const response = error.response;
  if (!response || response.status < 500) return null;
  const headers = response.headers as unknown;
  const value =
    typeof (headers as { get?: (name: string) => unknown })?.get === "function"
      ? (headers as { get: (name: string) => unknown }).get("x-request-id")
      : (headers as Record<string, unknown> | undefined)?.["x-request-id"];
  return typeof value === "string" && value ? value : null;
}

function apiErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const requestId = serverErrorRequestId(error);
    const suffix = requestId ? ` (request id: ${requestId})` : "";
    const detail = error.response?.data?.detail;
    if (typeof detail === "string") return `${detail}${suffix}`;
    if (Array.isArray(detail)) {
      const flattened = pydanticErrorMessage(detail);
      if (flattened) return `${flattened}${suffix}`;
    }
    if (detail != null) return `${JSON.stringify(detail)}${suffix}`;
    return `${error.message}${suffix}`;
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
  /** The role held *inside* `default_tenant` and what it grants (#318). Since
   * #318 the global `role` above is no longer the whole answer: the same
   * account can be an auditor in one tenant and a scope-approver in another,
   * so the pages gate on these rather than on the role name. Optional: an API
   * older than #318 does not send them, and the callers fall back to the role.
   */
  tenant_role?: string;
  permissions?: string[];
  /** Which tenant `tenant_role`/`permissions` describe. The request
   * interceptor below attaches the tenant the switcher is on to every call,
   * `/auth/me` included, so this is the tenant those two are about — not
   * necessarily `default_tenant`. Absent on an API older than #318. */
  scoped_tenant?: string;
  /** Second-factor state (#315): whether the account has enrolled, whether
   * this installation requires it of the account's role, and whether *this
   * session* is confined to the enrolment flow until it does. */
  mfa_enabled?: boolean;
  mfa_required?: boolean;
  mfa_pending?: boolean;
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
  /** Which side of the perimeter the scan looked at (see lib/scan-surface.ts);
   * null for a run recorded before the marker existed. */
  surface?: "external" | "internal" | "mixed" | null;
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
/** Matrix-level verdict. "partial" = some controls passed, others were never
 * evaluated — distinct from "ok" so an unevaluated control cannot read as a
 * pass. An individual control never carries it. */
export type OverallVerdict = ControlStatus | "partial";

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
  overall_verdict: OverallVerdict;
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
  /** Candidate domains contributed per source. An enabled source at 0 states
   * its coverage, rather than implying there is nothing out there. */
  sources_evaluated?: Record<string, number>;
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
  /** `claimed` = an agent holds the job but has not reported starting it;
   * `cancelling` = the API has asked the agent running it to stop and has not
   * been told it did yet (#360). */
  status:
    | "queued"
    | "claimed"
    | "running"
    | "cancelling"
    | "succeeded"
    | "failed"
    | "cancelled";
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
  /** Top-level mirror of `scan_options.surface`. */
  surface?: "external" | "internal" | "mixed" | null;
  /** Whether the operator declared the surface or the server derived it from the targets. */
  surface_source?: "operator" | "derived" | null;
};

/** `GET /api/jobs/summary`: one grouped count instead of paging the list. */
export type JobSurfaceCounts = { running: number; queued: number; total: number };
export type JobSummary = {
  by_status: Record<string, number>;
  running: number;
  /** queued + claimed */
  queued: number;
  by_surface: Record<"external" | "internal" | "mixed" | "unknown", JobSurfaceCounts>;
  generated_at: string | null;
};

export type ScheduleScanOptions = {
  mode: "safe" | "balanced" | "fast" | "test";
  intent?: ScanIntent | null;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo: boolean;
  surface?: "external" | "internal" | "mixed" | null;
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
  surface?: "external" | "internal" | "mixed" | null;
  ranges?: string | null;
  domains?: string | null;
  ports?: string | null;
  ports_udp?: string | null;
};

export type UpdateScheduleBody = Partial<
  Omit<CreateScheduleBody, "tenant_id"> & { enabled: boolean }
>;

export type AgentLifecycleStatus = "active" | "disabled" | "quarantined";

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
  /** What an operator decided about this agent (#308), as opposed to `status`
   * above, which is what the agent last reported about itself. A non-active
   * agent still heartbeats — it just cannot claim work or upload results. */
  lifecycle_status?: AgentLifecycleStatus;
  lifecycle_reason?: string | null;
  lifecycle_message?: string | null;
  /** How many *other* agents registered with the same provisioning key — the
   * blast radius of a delete with `revoke_key` (#308). Only the single-agent
   * read fills it in; in the fleet list it is absent. */
  other_agents_on_key?: number;
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
  /** `suspended` is the one non-active state, and the word is the API's:
   * `disabled` is an account and an agent, never a tenant (#318). A suspended
   * tenant refuses every request from a non-platform-admin, and drops out of
   * this listing for them, so only a platform admin ever sees the value. */
  status: "active" | "suspended";
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
  /** The tracked finding this match produced, or null. Only a `vulnerable`
   * match with a published fix becomes one. */
  vuln_id: string | null;
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

export type PatchGapItem = {
  installed_package: string;
  source_package: string;
  installed_version: string | null;
  /** Null when the published fixes could not be ordered — render no command,
   * because a guessed target may not close every CVE listed. */
  target_version: string | null;
  cve_ids: string[];
  cve_count: number;
  worst_severity: string;
  by_severity: Record<string, number>;
  distro: string | null;
  distro_release: string | null;
  upgrade_command: string | null;
};

export type DevicePatchGap = {
  device_id: string;
  hostname: string | null;
  packages_to_upgrade: number;
  cves_closed_by_upgrade: number;
  /** Vulnerable, but the vendor published no fix. Counted, never a command. */
  unfixed_findings: number;
  worst_severity: string;
  combined_upgrade_command: string | null;
  gaps: PatchGapItem[];
};

export type TenantPatchGapDevice = {
  device_id: string;
  hostname: string | null;
  packages_to_upgrade: number;
  cves_closed_by_upgrade: number;
  unfixed_findings: number;
  worst_severity: string;
};

export type TenantPatchGap = {
  tenant_id: string;
  devices_with_gaps: number;
  packages_to_upgrade: number;
  cves_closed_by_upgrade: number;
  unfixed_findings: number;
  devices: TenantPatchGapDevice[];
  truncated: boolean;
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
  /**
   * The build's verdict on whether this file is a corpus or a placeholder,
   * against the per-dataset floor in scripts/enrichment_manifest.py. Age and
   * entry count cannot answer it: the committed advisory seed is present, has
   * the build's mtime and a non-zero count whether it holds eight advisories or
   * four hundred thousand. `null` means no manifest was found — "nothing
   * recorded", which is not the same claim as `false`.
   */
  usable?: boolean | null;
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

/** What `POST /auth/login` answers, which is now one of two things (#315).
 *
 * A completed login carries `access_token`; one that still owes a second
 * factor carries `mfa_required` and `mfa_token` and *no* session token. The
 * third shape is a completed login of an account this installation requires a
 * factor of and which has not enrolled: a session **and** `mfa_required`, which
 * the console reads as "go straight to the setup page". */
export type LoginResult = {
  access_token: string | null;
  role: Role | null;
  username: string;
  mfa_required: boolean;
  mfa_token: string | null;
  /** Seconds the challenge token is good for. */
  expires_in: number | null;
};

export async function login(username: string, password: string): Promise<LoginResult> {
  try {
    const { data } = await api.post<LoginResult>("/auth/login", { username, password });
    // Only a real session is stored. Storing the challenge token would put a
    // credential that opens one endpoint into the slot every request reads
    // from, and every one of those requests would 401.
    if (data.access_token) setAccessToken(data.access_token);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Present the second factor: the login's second leg, or a step-up (#315).
 *
 * With `mfa_token` this completes a login; without it the current session is
 * re-verified and the token it returns carries a fresh `mfa_verified_at`,
 * which is what the credential-issuing endpoints check. Either way the session
 * token that comes back replaces the one this browser holds. */
export async function verifyMfa(body: {
  mfa_token?: string | null;
  code?: string;
  recovery_code?: string;
}): Promise<LoginResult> {
  try {
    const { data } = await api.post<LoginResult>("/auth/mfa/verify", {
      mfa_token: body.mfa_token ?? undefined,
      code: body.code || undefined,
      recovery_code: body.recovery_code || undefined,
    });
    if (data.access_token) setAccessToken(data.access_token);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Second-factor state of one account. Carries nothing secret (#315). */
export type MfaStatus = {
  username: string;
  enabled: boolean;
  enabled_at: string | null;
  setup_pending: boolean;
  recovery_codes_remaining: number;
  required: boolean;
  stepup_minutes: number;
  /** Whether confirming an enrolment will ask for the password. False for an
   * SSO-provisioned account, which has none to give. */
  password_required: boolean;
};

export type MfaSetup = {
  secret: string;
  otpauth_uri: string;
  algorithm: string;
  digits: number;
  period: number;
};

export async function fetchMfaStatus(): Promise<MfaStatus> {
  try {
    const { data } = await api.get<MfaStatus>("/auth/mfa");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Start enrolment. The response is the only place the secret is readable, so
 * the caller must render it (or its URI) rather than fetching it again. */
export async function setupTotp(): Promise<MfaSetup> {
  try {
    const { data } = await api.post<MfaSetup>("/auth/mfa/totp/setup");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Confirm enrolment with a code and the account's password. Returns the ten
 * recovery codes, once.
 *
 * The password is what stops a stolen session enrolling its own authenticator
 * and locking the owner out; it is omitted only for an account that has none,
 * which `MfaStatus.password_required` reports. */
export async function confirmTotp(code: string, password?: string): Promise<string[]> {
  try {
    const { data } = await api.post<{ recovery_codes: string[] }>("/auth/mfa/totp/confirm", {
      code,
      password: password || undefined,
    });
    return data.recovery_codes ?? [];
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function disableMfa(body: {
  password: string;
  code?: string;
  recovery_code?: string;
}): Promise<MfaStatus> {
  try {
    const { data } = await api.post<MfaStatus>("/auth/mfa/disable", {
      password: body.password,
      code: body.code || undefined,
      recovery_code: body.recovery_code || undefined,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Clear another account's second factor and end its sessions. Admin only. */
export async function resetUserMfa(username: string): Promise<MfaStatus> {
  try {
    const { data } = await api.post<MfaStatus>(
      `/users/${encodeURIComponent(username)}/mfa/reset`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** What the server made of a sign-out, for a caller that has to tell the user.
 *
 * `already-ended` and `ended` are both "the token is dead"; `uncertain` is the
 * one the console must not render as a completed sign-out. */
export type LogoutOutcome = "ended" | "already-ended" | "uncertain";

/** End this session on the server, then forget the token locally (#314).
 *
 * The local token is dropped whatever happens — a browser that cannot reach
 * the API must still be able to walk away from a session — but the outcome is
 * reported rather than swallowed. Swallowing it meant that a 500 or a dropped
 * connection left the token live on the server while the console said "you are
 * signed out", which is the one failure a user cannot see and cannot act on.
 *
 * A 401 or 403 is not a failure: the session was already gone, or the
 * credential was never a session (a service token cannot touch `auth`), which
 * is the outcome the caller asked for. Anything else — including the 400 a
 * pre-#314 token with no `jti` gets — is retried as "end every session of this
 * account", which needs no `jti` and is the honest superset of the request. */
export async function logout(): Promise<LogoutOutcome> {
  let outcome: LogoutOutcome = "ended";
  try {
    await api.post("/auth/logout");
  } catch (error) {
    const status = axios.isAxiosError(error) ? error.response?.status : undefined;
    if (status === 401 || status === 403) {
      outcome = "already-ended";
    } else {
      outcome = (await revokeAllQuietly()) ? "ended" : "uncertain";
    }
  }
  setAccessToken(null);
  return outcome;
}

/** The fallback path of `logout()`: succeeded or not, no message to render. */
async function revokeAllQuietly(): Promise<boolean> {
  try {
    await api.post("/auth/sessions/revoke-all");
    return true;
  } catch {
    return false;
  }
}

/** Sign out of every session of this account, this one included (#314).
 *
 * Throws rather than reporting an outcome: this one is an explicit action with
 * a button behind it, so a failure is a message the user reads and a retry
 * they choose, and the local token is kept because nothing was ended. */
export async function revokeAllSessions() {
  try {
    await api.post("/auth/sessions/revoke-all");
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
  setAccessToken(null);
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

/** Server-side list filter shared by jobs and runs: `unknown` selects rows the
 * server could not classify (pre-field jobs, runs without a marker). */
export type ScanListFilters = {
  surface?: "external" | "internal" | "mixed" | "unknown";
};

function scanFilterParams(filters?: ScanListFilters): Record<string, string> | undefined {
  return filters?.surface ? { surface: filters.surface } : undefined;
}

export async function fetchRuns(page?: PageParams, filters?: ScanListFilters) {
  try {
    const params = pageSearchParams(page, scanFilterParams(filters));
    const { data } = await api.get<Page<RunSummary>>(`/runs?${params}`);
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

/**
 * Withdraw a promotion: the tenant's next scan no longer carries the domain.
 * Keyed on the tenant, not on a run — the run that proposed the domain may be
 * gone by the time the operator changes their mind.
 */
export async function withdrawPromotedDomain(domain: string) {
  try {
    const { data } = await api.delete<PromoteDomainResponse>(
      `/promoted-domains/${encodeURIComponent(domain)}`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Encode each path segment but keep the "/" separators for the :path route param. */
function encodeArtifactPath(path: string): string {
  return path.split("/").map(encodeURIComponent).join("/");
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

/** Deregister an agent, and with `revokeKey` also revoke the provisioning key
 * it registered with (#308) — without that the host still holds the key and a
 * live JWT, and re-registers on its next poll. */
export async function deleteAgent(agentId: string, revokeKey = false) {
  try {
    const { data } = await api.delete<{
      status: string;
      agent_id: string;
      provisioning_key_id: string | null;
      key_revoked: boolean;
      other_agents_on_key: number;
    }>(`/agents/${encodeURIComponent(agentId)}?revoke_key=${revokeKey}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function updateAgentStatus(
  agentId: string,
  status: AgentLifecycleStatus,
  reason = "",
) {
  try {
    const { data } = await api.patch<AgentInfo>(`/agents/${encodeURIComponent(agentId)}`, {
      status,
      reason,
    });
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
    const { data } = await api.post<AgentDeploymentSnippetResponse>("/agent/deployment-command", {
      label: label ?? "",
    });
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

export async function fetchJobs(page?: PageParams, filters?: ScanListFilters) {
  try {
    const params = pageSearchParams(page, scanFilterParams(filters));
    const { data } = await api.get<Page<JobInfo>>(`/jobs?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchJobSummary() {
  try {
    const { data } = await api.get<JobSummary>("/jobs/summary");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchJob(jobId: string) {
  try {
    const { data } = await api.get<JobInfo>(`/jobs/${encodeURIComponent(jobId)}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Cancel a job that has not started (ROADMAP P1.3). The API answers 409 for
 * one already running or finished — cancellation prevents execution, it does
 * not stop a scan in flight. */
export async function cancelJob(jobId: string) {
  try {
    const { data } = await api.post<JobInfo>(`/jobs/${encodeURIComponent(jobId)}/cancel`);
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

export async function uploadWordlist(input: { file: File; kind: WordlistKind; name?: string }) {
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

export type StartScanBody = {
  mode: string;
  intent?: ScanIntent | null;
  delta: boolean;
  skip_nse: boolean;
  notify: boolean;
  export_defectdojo?: boolean;
  /** Operator's declared surface; the server derives one from the targets when omitted. */
  surface?: "external" | "internal" | "mixed" | null;
  ranges?: string;
  domains?: string;
  ports?: string;
  ports_udp?: string;
  tenant_id?: string;
  wordlist_id?: string;
};

export async function startScan(
  body: StartScanBody,
  options?: {
    /** Sent as `Idempotency-Key` (ROADMAP P1.5): a retry after a timeout must
     * not queue a second scan of the same targets. */
    idempotencyKey?: string;
  },
) {
  try {
    const headers = options?.idempotencyKey
      ? { "Idempotency-Key": options.idempotencyKey }
      : undefined;
    const { data } = await api.post<JobInfo>("/jobs", body, { headers });
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

// --------------------------------------------------------------------------
// Maintenance windows and the change freeze (#352)
// --------------------------------------------------------------------------

export type MaintenanceWindowKind = "blackout" | "allowed";
export type MaintenanceScopeKind = "tenant" | "asset_group";

/** One recurring period in which scanning is forbidden (`blackout`) or the
 * only one in which it is allowed (`allowed`).
 *
 * `dtstart_local` is wall clock in `timezone` and carries no offset on
 * purpose — it is "22:00 where the customer is", which is a different instant
 * in January and in July. The fields the console renders as instants are
 * `open_until` and `next_start_at`, which the API has already resolved to UTC. */
export type MaintenanceWindow = {
  window_id: string;
  tenant_id: string;
  name: string;
  kind: MaintenanceWindowKind;
  enabled: boolean;
  timezone: string;
  rrule: string;
  dtstart_local: string;
  duration_minutes: number;
  scope_kind: MaintenanceScopeKind;
  asset_group: string | null;
  scope_targets: string[];
  note: string;
  created_at: string | null;
  created_by: string | null;
  updated_at: string | null;
  updated_by: string | null;
  /** Only in the calendar view (`GET /maintenance-windows`). */
  open_now?: boolean | null;
  open_until?: string | null;
  next_start_at?: string | null;
};

/** What a scan started right now would be told. `retry_at` is null when the
 * block has no knowable end — a change freeze — which is why the banner says
 * "until an admin lifts it" rather than naming a time. */
export type MaintenanceAdmission = {
  allowed: boolean;
  reason: string;
  detail: string;
  window_id: string;
  window_name: string;
  retry_at: string | null;
};

export type MaintenanceCalendar = {
  tenant_id: string;
  change_freeze: boolean;
  change_freeze_note: string;
  change_freeze_at: string | null;
  change_freeze_by: string | null;
  admission: MaintenanceAdmission;
  windows: MaintenanceWindow[];
};

export async function fetchMaintenanceCalendar(tenantId?: string) {
  try {
    const { data } = await api.get<MaintenanceCalendar>("/maintenance-windows", {
      params: tenantId ? { tenant_id: tenantId } : undefined,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type ChangeFreezeState = Pick<
  MaintenanceCalendar,
  "tenant_id" | "change_freeze" | "change_freeze_note" | "change_freeze_at" | "change_freeze_by"
>;

/** Freezes or thaws the caller's tenant. Admin-only on the API; the note is
 * what the refusal quotes back at whoever tries to start a scan. */
export async function setChangeFreeze(
  body: { change_freeze: boolean; note?: string },
  tenantId?: string,
) {
  try {
    const { data } = await api.put<ChangeFreezeState>(
      "/change-freeze",
      { change_freeze: body.change_freeze, note: body.note ?? "" },
      { params: tenantId ? { tenant_id: tenantId } : undefined },
    );
    return data;
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

export async function fetchAssetContextEvents(
  assetId: string,
  tenantId = "default",
  page?: PageParams,
) {
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
export async function fetchEndpointDevices(opts?: { tenantId?: string; assetId?: string }) {
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
export async function fetchRecentSoftwareChanges(opts?: { tenantId?: string; limit?: number }) {
  try {
    const params = new URLSearchParams(tenantParam(opts?.tenantId));
    params.set("limit", String(opts?.limit ?? 50));
    const { data } = await api.get<EndpointSoftwareChangeFeedItem[]>(`/endpoint/changes?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Estate-wide patch gap: what is outstanding, worst devices first
 * (ROADMAP Track E M2). Derived from the matcher's rows on read. */
export async function fetchPatchGaps(tenantId = "default", limit = 50) {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    params.set("limit", String(limit));
    const { data } = await api.get<TenantPatchGap>(`/endpoint/patch-gaps?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** One endpoint's outstanding upgrades and the command that applies them. */
export async function fetchDevicePatchGap(deviceId: string, tenantId = "default") {
  try {
    const params = new URLSearchParams(tenantParam(tenantId));
    const { data } = await api.get<DevicePatchGap>(
      `/endpoint/devices/${encodeURIComponent(deviceId)}/patch-gap?${params}`,
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
  "OPEN" | "ACKNOWLEDGED" | "PLANNED" | "FIXING" | "VERIFYING" | "CLOSED";

export type SlaState = "on_track" | "due_soon" | "breached" | "accepted" | "none";

/** Which observer found it. A software finding comes from the endpoint
 * inventory: it has an installed package where a scan finding has a port, and
 * a network re-scan cannot verify it. */
export type VulnerabilitySource = "scan" | "endpoint_software";

export type TrackedVulnerability = {
  vuln_id: string;
  tenant_id: string;
  asset_id: string;
  finding_key: string;
  source: VulnerabilitySource;
  /** The endpoint it was observed on. Null for every scan finding. */
  device_id: string | null;
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
  /** When the linked ticket was last read back by the sync poller or the Sync
   * button — the attempt, not necessarily a success (#347). */
  ticket_synced_at?: string | null;
  /** Why the last read failed, or null after one that worked. A broken link
   * (renamed key, revoked token) is visible here instead of only in the
   * server's log. */
  ticket_sync_error?: string | null;
  /** The tracker's own status at that read ("Done", "6", "Active"). The poller
   * applies a suggestion only when it changes, so it is also the answer to
   * "why did the last poll leave this finding where it was". */
  ticket_remote_status?: string | null;
  /** Set by the ingest path when a dispatched verification run did not
   * re-observe the finding. Never settable through the API. */
  machine_verified?: boolean;
  verification_job_id?: string | null;
  last_verified_at?: string | null;
  /** verified_remediated | patched | manual | ticket_resolved | false_positive. */
  closure_reason?: string | null;
  /** False-positive verdict, an expiring attribute of the finding rather than a
   * state of its own. `fp_suppressed` is the server's derived answer to "does a
   * re-observation still leave this closed" — the verdict *and* an unexpired
   * `fp_suppress_until` — so the console never has to compute it from a clock
   * it does not share with the API. */
  fp_reason?: string | null;
  fp_marked_by?: string | null;
  fp_marked_at?: string | null;
  fp_evidence?: Record<string, unknown>;
  fp_suppress_until?: string | null;
  fp_observations?: number;
  fp_suppressed?: boolean;
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
  /** Open findings by observed network exposure: external / internal / unknown
   * (NULL counted as unknown). Absent from an API older than this field. */
  by_network_exposure_open?: Record<string, number>;
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
  source?: VulnerabilitySource | "";
  assignee?: string;
  unassigned?: boolean;
  sla?: SlaState | "";
  stale_days?: number;
  in_kev?: boolean;
  /** Observed exposure of the finding's host; "unknown" also matches NULL. */
  network_exposure?: NetworkExposure | "";
};

export type NetworkExposure = "external" | "internal" | "unknown";

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

/** Body for the false-positive verdict. `suppress_days` is bounded 1-365 by the
 * API rather than optional-and-unbounded, so "suppress this forever" has no
 * spelling; `evidence` is free-form because no fixed shape fits every detector,
 * and it is what makes the verdict re-checkable by whoever inherits it. */
export type VulnerabilityFalsePositiveBody = {
  reason: string;
  suppress_days?: number;
  evidence?: Record<string, unknown>;
};

/** Ids one bulk request may carry — `bulk_actions.MAX_BULK_IDS` on the server,
 * which refuses more with a 422. Mirrored here so the table's select-all stops
 * at the ceiling instead of building a request that cannot be sent. */
export const MAX_BULK_IDS = 200;

/** One id's fate inside a batch. `outcome` is the single-id endpoint's status
 * code in words: `not_found` is its 404 (which is also what another tenant's id
 * gets — a write scope never confirms existence), `conflict` its 409, `invalid`
 * its 422. */
export type BulkActionItemResult = {
  id: string;
  ok: boolean;
  outcome: "ok" | "not_found" | "conflict" | "invalid";
  error: string | null;
};

/** A batch is a partial success by design, so the response is a report and the
 * status is 200 even when `failed` is nonzero. `replayed` means the answer came
 * from the `Idempotency-Key` record of an earlier identical request. */
export type BulkActionReport = {
  action: string;
  requested: number;
  succeeded: number;
  failed: number;
  results: BulkActionItemResult[];
  replayed: boolean;
};

/** The verbs `POST /vulnerabilities/bulk` accepts, each carrying the same body
 * its single-finding endpoint takes. `exception` and `false_positive` need
 * tenant admin there and here — bulk is not a cheaper door. */
export type BulkVulnerabilityBody =
  | { action: "assign"; vuln_ids: string[]; payload: VulnerabilityAssignBody }
  | { action: "transition"; vuln_ids: string[]; payload: VulnerabilityTransitionBody }
  | { action: "exception"; vuln_ids: string[]; payload: VulnerabilityExceptionBody }
  | { action: "ticket"; vuln_ids: string[]; payload: VulnerabilityTicketBody }
  | {
      action: "false_positive";
      vuln_ids: string[];
      payload: VulnerabilityFalsePositiveBody;
    };

export type BulkAssetBody = {
  action: "context";
  asset_ids: string[];
  payload: UpdateAssetBody;
};

/** A fresh `Idempotency-Key` for one bulk submission. Called once per
 * submission and not once per attempt — see `useSubmissionKey` in
 * `hooks/use-bulk-actions.ts`, which holds the value against the body it names
 * so a retried click carries the key the first attempt did. Every call here
 * returns a new value, so calling it per attempt would name every attempt a
 * different batch. */
export function newBulkIdempotencyKey(): string {
  const random =
    typeof crypto !== "undefined" && "randomUUID" in crypto
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2);
  return `console:bulk:${random}`;
}

export async function bulkVulnerabilityAction(
  body: BulkVulnerabilityBody,
  options?: { idempotencyKey?: string },
) {
  try {
    const headers = options?.idempotencyKey
      ? { "Idempotency-Key": options.idempotencyKey }
      : undefined;
    const { data } = await api.post<BulkActionReport>("/vulnerabilities/bulk", body, { headers });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function bulkAssetAction(
  body: BulkAssetBody,
  options?: { idempotencyKey?: string },
) {
  try {
    const headers = options?.idempotencyKey
      ? { "Idempotency-Key": options.idempotencyKey }
      : undefined;
    const { data } = await api.post<BulkActionReport>("/assets/bulk", body, { headers });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

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
    if (filters?.source) params.set("source", filters.source);
    if (filters?.assignee) params.set("assignee", filters.assignee);
    if (filters?.unassigned) params.set("unassigned", "true");
    if (filters?.sla) params.set("sla", filters.sla);
    if (filters?.in_kev) params.set("in_kev", "true");
    if (filters?.network_exposure) params.set("network_exposure", filters.network_exposure);
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

export async function setVulnerabilityFalsePositive(
  vulnId: string,
  body: VulnerabilityFalsePositiveBody,
) {
  try {
    const { data } = await api.post<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/false-positive`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function clearVulnerabilityFalsePositive(vulnId: string) {
  try {
    const { data } = await api.delete<TrackedVulnerability>(
      `/vulnerabilities/${encodeURIComponent(vulnId)}/false-positive`,
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
    const { data } = await api.post<RiskScoreSnapshot>("/vulnerabilities/risk-history/snapshot");
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
  /** What password login is for on this installation (#315). Only ever a
   * mode — the break-glass account names stay server-side. */
  local_login: "enabled" | "break-glass" | "disabled";
};

/** An API that predates SSO answers 404, and an unreachable one answers
 * nothing; both read as "no SSO" rather than an error worth showing on a login
 * form. The button is an enhancement — password login has to keep working when
 * this call fails. */
export async function fetchSsoStatus(): Promise<SsoStatus> {
  const fallback: SsoStatus = {
    enabled: false,
    login_url: "/api/auth/oidc/login",
    // An API that predates #315 does not answer this field, and its password
    // form works: "enabled" is the reading that keeps the login page usable.
    local_login: "enabled",
  };
  try {
    const { data } = await api.get<SsoStatus>("/auth/sso");
    return { ...fallback, ...(data ?? {}) };
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
// Approved scanning scope per tenant (#226)
// --------------------------------------------------------------------------

export type ScanScopeEffect = "allow" | "deny";
export type ScanScopeKind = "cidr" | "domain";

/** One stored allow/deny entry of a tenant's approved scanning scope (#226),
 * with the approval it was written under. `value` is a CIDR, a domain suffix
 * covering itself and its subdomains, or the literal `*` wildcard. */
export type ScanScopeEntry = {
  id: number;
  tenant_id: string;
  effect: ScanScopeEffect;
  kind: ScanScopeKind;
  value: string;
  note: string;
  approved_by: string;
  approved_at: string | null;
};

/** What a caller sends. The API stamps the rest: a scope is approved by
 * somebody, and that somebody is the authenticated admin, not a form field. */
export type ScanScopeEntryInput = {
  effect: ScanScopeEffect;
  kind: ScanScopeKind;
  value: string;
  note?: string;
};

export async function fetchScanScope(tenantId: string) {
  try {
    const { data } = await api.get<ScanScopeEntry[]>(
      `/tenants/${encodeURIComponent(tenantId)}/scan-scope`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Replaces the whole scope, which is what the API offers: a scope is
 * evaluated as a set (deny beats allow), so there is no partial update that is
 * safe to enforce halfway. An empty list is accepted and means "scans
 * nothing". */
export async function replaceScanScope(tenantId: string, entries: ScanScopeEntryInput[]) {
  try {
    const { data } = await api.put<ScanScopeEntry[]>(
      `/tenants/${encodeURIComponent(tenantId)}/scan-scope`,
      { entries },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Related domains this tenant's operators promoted into scope (org_profile
 * M4). Read-only here: it is the admin's cross-check on the scope above, since
 * every scan carries these in addition to its own targets. */
export type PromotedDomainInfo = {
  tenant_id: string;
  domain: string;
  source_run_id: string;
  promoted_by: string;
  promoted_at: string;
};

export async function fetchPromotedDomains(tenantId: string) {
  try {
    const { data } = await api.get<PromotedDomainInfo[]>(
      `/tenants/${encodeURIComponent(tenantId)}/promoted-domains`,
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
  /** Findings an unexpired false-positive verdict is holding out of the active
   * population this posture was assessed from. Reported beside the score and
   * never subtracted from it. */
  suppressed_findings: number;
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
  delivery: {
    transport: string | null;
    target: string | null;
    status: string;
    error: string | null;
  }[];
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

// ---------------------------------------------------------------------------
// Adoption metrics (ROADMAP Track E, "What to measure")
// ---------------------------------------------------------------------------

export type AdoptionFindings = {
  open: number;
  accepted_open: number;
  /** Remediation closures only. Findings closed as never having been real are
   * `false_positive_in_window` instead, and are excluded from every share and
   * median below — otherwise the quarterly control question is answerable by
   * relabelling noise. */
  closed_in_window: number;
  false_positive_in_window: number;
  machine_verified_closed: number;
  /** Shares are percentages 0-100, or null when there is nothing to divide by. */
  machine_verified_share: number | null;
  closed_within_sla_share: number | null;
  mttr_hours: number | null;
  mttr_hours_by_severity: Record<string, number | null>;
  reopened_share: number | null;
  open_per_asset: number | null;
};

export type AdoptionAssets = {
  active: number;
  with_owner_share: number | null;
  with_context_share: number | null;
  scanned_recently_share: number | null;
  dual_source_share: number | null;
  coverage_days: number;
  unowned: number;
};

export type AdoptionNoiseSource = {
  /** A detector's `script_id`, `unknown` for advisory matches that have none,
   * or — in `by_origin` — the observer: `scan` or `endpoint_software`. */
  source: string;
  closed: number;
  false_positive: number;
  /** `null` below `source_threshold` closures: one verdict out of one closure
   * is a data point, not a 100% error rate. The counts are always there. */
  false_positive_share: number | null;
};

export type AdoptionFalsePositives = {
  in_window: number;
  share_of_closures: number | null;
  by_severity: Record<string, number>;
  by_source: AdoptionNoiseSource[];
  by_origin: AdoptionNoiseSource[];
  source_threshold: number;
  suppressions_active: number;
  suppressions_lapsed: number;
  overridden_in_window: number;
  median_hours_to_verdict: number | null;
};

/** `scan_history_reason` is why the two scan shares are withheld
 * (`no_scan_history`, `partial_scan_history` — migration 0035 has no backfill,
 * so the columns fill one run at a time). `scope_unbounded_reason` is why scope
 * coverage is: `no_scope`, `no_measurable_scope` (every approval is a wildcard
 * or a domain suffix), or the scan-history reason.
 *
 * Scope coverage counts **approvals reached**, not addresses: a share of an
 * address space read 2.9% for a fully scanned /22 and could not tell an empty
 * subnet from an unscanned one. `scope_uncovered_entries` names the approved
 * ranges no scan has reached, capped — `measurable_entries` has the total. */
export type AdoptionCoverage = {
  coverage_days: number;
  assets_with_scan_history: number;
  scan_history_share: number | null;
  scan_history_reason: string | null;
  scanned_share: number | null;
  vuln_scanned_share: number | null;
  approved_entries: number;
  denied_entries: number;
  measurable_entries: number;
  unmeasurable_entries: string[];
  scope_covered_entries: number | null;
  scope_covered_share: number | null;
  scope_uncovered_entries: string[];
  scope_unbounded_reason: string | null;
};

export type AdoptionAnalyst = { analyst: string; closed: number; machine_verified: number };

export type AdoptionOnboarding = {
  tenant_created_at: string | null;
  first_successful_scan_at: string | null;
  first_tracked_finding_at: string | null;
  hours_to_first_scan: number | null;
  hours_to_first_finding: number | null;
};

export type AdoptionEnrichmentDataset = {
  name: string;
  present: boolean;
  age_days: number | null;
  stale: boolean;
};

export type AdoptionMetrics = {
  tenant_id: string;
  window_days: number;
  generated_at: string;
  findings: AdoptionFindings;
  /** Added after the page shipped, and optional here for the same reason the
   * API defaults them: an older server answers without either block and the
   * page has to keep rendering the rest. */
  false_positives?: AdoptionFalsePositives;
  assets: AdoptionAssets;
  coverage?: AdoptionCoverage | null;
  analysts: AdoptionAnalyst[];
  onboarding: AdoptionOnboarding;
  enrichment: AdoptionEnrichmentDataset[];
};

export async function fetchAdoption(windowDays = 90) {
  try {
    const { data } = await api.get<AdoptionMetrics>("/adoption", {
      params: { window_days: windowDays },
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

// ---------------------------------------------------------------------------
// Usage metering and quotas
// ---------------------------------------------------------------------------

/** One metered resource. `limit: null` is an unlimited quota, and then there is
 * nothing to be remaining of and nothing to take a ratio against — both come
 * back null rather than as 0 or 100%. `used_ratio` is a fraction 0..1. */
export type UsageResource = {
  used: number;
  limit: number | null;
  remaining: number | null;
  used_ratio: number | null;
  over_limit: boolean;
};

export type UsageScanMonth = { month: string; scans: number };

export type QuotaSource = "tenant" | "default";

export type TenantUsage = {
  tenant_id: string;
  period_start: string;
  period_end: string;
  /** "tenant" when an operator set the quota, "default" when it is inherited. */
  quota_source: QuotaSource;
  enforced: boolean;
  note: string | null;
  updated_at: string | null;
  updated_by: string | null;
  assets: UsageResource;
  scans: UsageResource;
  scan_history: UsageScanMonth[];
};

export async function fetchUsage(historyMonths = 12) {
  try {
    const { data } = await api.get<TenantUsage>("/usage", {
      params: { history_months: historyMonths },
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type TenantUsageRow = {
  tenant_id: string;
  name: string;
  status: string;
  quota_source: QuotaSource;
  assets: UsageResource;
  scans: UsageResource;
};

export type FleetUsage = {
  period_start: string;
  period_end: string;
  tenants: TenantUsageRow[];
};

/** Platform admin only — 403 for everyone else, so the caller gates the query
 * on `is_platform_admin` rather than letting it fire and fail. */
export async function fetchFleetUsage() {
  try {
    const { data } = await api.get<FleetUsage>("/usage/tenants");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type TenantQuota = {
  tenant_id: string;
  max_assets: number | null;
  max_scans_per_month: number | null;
  quota_source: QuotaSource;
  note: string | null;
  updated_at: string | null;
  updated_by: string | null;
};

export type TenantQuotaUpdate = {
  max_assets: number | null;
  max_scans_per_month: number | null;
  note?: string;
};

export async function fetchTenantQuota(tenantId: string) {
  try {
    const { data } = await api.get<TenantQuota>(`/tenants/${encodeURIComponent(tenantId)}/quota`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** A null (or absent) ceiling is how the API spells "unlimited". */
export async function updateTenantQuota(tenantId: string, body: TenantQuotaUpdate) {
  try {
    const { data } = await api.put<TenantQuota>(
      `/tenants/${encodeURIComponent(tenantId)}/quota`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Drops the tenant's own quota row so it follows the platform default again —
 * the only way back to `quota_source: "default"`. 204, platform admin only. */
export async function deleteTenantQuota(tenantId: string) {
  try {
    await api.delete(`/tenants/${encodeURIComponent(tenantId)}/quota`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

// ---------------------------------------------------------------------------
// Integrations: outbound webhooks and ticket transports
// ---------------------------------------------------------------------------

/** `webhook` is the signed HMAC POST; the other three build a native
 * create-issue call for the tracker (api/services/integrations/tickets.py). */
export type WebhookTransport = "webhook" | "jira" | "servicenow" | "defectdojo";

/** Event kinds a subscription may filter on. An empty list means "every *asset*
 * kind" — the audit trail and the workflow events are opt-in, so an existing
 * unfiltered subscription does not start receiving them on upgrade.
 *
 * The first five are the asset events (`api/services/asset_events.py`
 * EVENT_KINDS). The next eight are the remediation-workflow events (#349,
 * `api/services/workflow_events.py` WORKFLOW_EVENT_KINDS). `audit.*` is the
 * whole administrative trail (#328) — the API also accepts one exact action
 * (`audit.user.role_change`), which the console deliberately does not offer as
 * twenty-odd more checkboxes; a subscription that names one is shown and
 * preserved, just not composed here. */
export const WEBHOOK_EVENT_KINDS = [
  "new_asset",
  "new_open_port",
  "new_cve",
  "cert_expiring",
  "decommissioned_host",
  "sla_due_soon",
  "sla_breached",
  "exception_expiring",
  "vuln_state_changed",
  "vuln_assigned",
  "scan_failed",
  "report_generated",
  "agent_offline",
  "audit.*",
] as const;

export type WebhookEventKind = (typeof WEBHOOK_EVENT_KINDS)[number];

export type WebhookSeverity = "low" | "medium" | "high" | "critical";

export type WebhookInfo = {
  subscription_id: string;
  tenant_id: string;
  name: string;
  url: string;
  enabled: boolean;
  event_kinds: string[];
  min_severity: string | null;
  has_secret: boolean;
  headers: Record<string, string>;
  transport: WebhookTransport;
  /** Adapter knobs: `project_key`/`issue_type`, `table`, or `test_id`. */
  transport_config: Record<string, unknown>;
  created_at: string | null;
  created_by: string | null;
  updated_at: string | null;
  last_delivery_at: string | null;
  last_status: string | null;
  /** Present only in the response that created or rotated it — write-only after. */
  secret?: string | null;
};

/** One delivery: queue entry, DLQ row and audit record in the same shape. */
export type WebhookDelivery = {
  delivery_id: string;
  tenant_id: string;
  subscription_id: string;
  event_id: string;
  event_kind: string;
  status: string;
  attempts: number;
  next_attempt_at: string | null;
  last_status_code: number | null;
  last_error: string | null;
  created_at: string | null;
  updated_at: string | null;
  delivered_at: string | null;
};

export type CreateWebhookBody = {
  name: string;
  url: string;
  event_kinds?: string[];
  min_severity?: WebhookSeverity | null;
  /** Omitted on a `webhook` transport = the API generates the signing secret.
   * Required on a ticket transport unless an Authorization header is set. */
  secret?: string;
  headers?: Record<string, string>;
  enabled?: boolean;
  transport?: WebhookTransport;
  transport_config?: Record<string, unknown>;
};

export type UpdateWebhookBody = {
  name?: string;
  url?: string;
  enabled?: boolean;
  event_kinds?: string[];
  min_severity?: WebhookSeverity | null;
  headers?: Record<string, string>;
  transport?: WebhookTransport;
  transport_config?: Record<string, unknown>;
  /** New HMAC secret or tracker token; omitted = keep the current one. Never echoed back. */
  secret?: string;
};

/** `null` says the webhook router is not mounted — `OCTO_WEBHOOKS_ENABLED` is
 * off on this installation, so there is nothing to list rather than an error to
 * report. Two spellings of the same thing reach us: a plain 404 from the API,
 * and a 200 carrying the exported console's `index.html`, because a build that
 * serves the SPA answers every unregistered path from `spa_fallback`
 * (api/app.py). Anything that is not a page envelope is that second one. */
export async function fetchWebhooks(page?: PageParams) {
  try {
    const params = pageSearchParams(page);
    const { data } = await api.get<Page<WebhookInfo>>(`/webhooks?${params}`);
    return Array.isArray(data?.items) ? data : null;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null;
    throw new Error(apiErrorMessage(error));
  }
}

export async function createWebhook(body: CreateWebhookBody) {
  try {
    const { data } = await api.post<WebhookInfo>("/webhooks", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function updateWebhook(subscriptionId: string, body: UpdateWebhookBody) {
  try {
    const { data } = await api.patch<WebhookInfo>(
      `/webhooks/${encodeURIComponent(subscriptionId)}`,
      body,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteWebhook(subscriptionId: string) {
  try {
    await api.delete(`/webhooks/${encodeURIComponent(subscriptionId)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** New HMAC signing secret, returned once. Refused by the API for a ticket
 * transport, where `secret` holds the tracker's API token. */
export async function rotateWebhookSecret(subscriptionId: string) {
  try {
    const { data } = await api.post<WebhookInfo>(
      `/webhooks/${encodeURIComponent(subscriptionId)}/rotate-secret`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Queues a signed `test` delivery. 202: the ping is queued, not answered —
 * the outcome shows up in the deliveries list one dispatcher tick later. */
export async function testWebhook(subscriptionId: string) {
  try {
    const { data } = await api.post<WebhookDelivery>(
      `/webhooks/${encodeURIComponent(subscriptionId)}/test`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** `null` for the same reason as `fetchWebhooks`. `status` is the queue state:
 * pending, delivered, or dead — the dead-letter queue. */
export async function fetchWebhookDeliveries(page?: PageParams, filters?: { status?: string }) {
  try {
    const params = pageSearchParams(page, filters?.status ? { status: filters.status } : undefined);
    const { data } = await api.get<Page<WebhookDelivery>>(`/webhooks/deliveries?${params}`);
    return Array.isArray(data?.items) ? data : null;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response?.status === 404) return null;
    throw new Error(apiErrorMessage(error));
  }
}

/** Takes one delivery back out of the DLQ; the dispatcher picks it up next tick. */
export async function retryWebhookDelivery(deliveryId: string) {
  try {
    const { data } = await api.post<WebhookDelivery>(
      `/webhooks/deliveries/${encodeURIComponent(deliveryId)}/retry`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

// ---------------------------------------------------------------------------
// Console accounts, tenant membership and the sign-in trail (#156, #157)
// ---------------------------------------------------------------------------

/** A console account. Carries no password material by construction — the API
 * has no field for one, so nothing here can leak a hash. */
export type UserInfo = {
  username: string;
  role: Role;
  disabled: boolean;
  /** False for an account backfilled from an orphan membership: it exists and
   * can be granted tenants, but cannot sign in until an admin sets a password. */
  has_password: boolean;
  created_at: string | null;
  updated_at: string | null;
  disabled_at: string | null;
  password_changed_at: string | null;
  created_by: string | null;
  /** Tenant ids the account is a member of; a platform admin needs none. */
  tenants?: string[];
  is_platform_admin?: boolean;
  email: string | null;
  email_verified: boolean;
  sso_linked: boolean;
};

export type CreateUserBody = {
  username: string;
  password: string;
  role: Role;
  /** Set in the same transaction as the account. */
  email?: string | null;
};

export async function fetchUsers() {
  try {
    const { data } = await api.get<UserInfo[]>("/users");
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** The API owns the rules (username shape, password length): the caller shows
 * whatever it refuses with rather than re-implementing them here. */
export async function createUser(body: CreateUserBody) {
  try {
    const { data } = await api.post<UserInfo>("/users", body);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Admin reset — deliberately does not take the old password, which is the
 * case the reset exists for. */
export async function setUserPassword(username: string, password: string) {
  try {
    const { data } = await api.put<UserInfo>(`/users/${encodeURIComponent(username)}/password`, {
      password,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function setUserRole(username: string, role: Role) {
  try {
    const { data } = await api.put<UserInfo>(`/users/${encodeURIComponent(username)}/role`, {
      role,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** `verified` is an administrative assertion: it is what makes the account
 * eligible to be linked to an SSO identity by address (Track E). */
export async function setUserEmail(username: string, email: string | null, verified: boolean) {
  try {
    const { data } = await api.put<UserInfo>(`/users/${encodeURIComponent(username)}/email`, {
      email,
      verified,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function setUserDisabled(username: string, disabled: boolean) {
  try {
    const { data } = await api.put<UserInfo>(`/users/${encodeURIComponent(username)}/disabled`, {
      disabled,
    });
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function deleteUser(username: string) {
  try {
    await api.delete(`/users/${encodeURIComponent(username)}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Rotate your own password. Any role — the current one is re-verified even
 * though the caller already holds a token. */
export async function changeOwnPassword(currentPassword: string, newPassword: string) {
  try {
    await api.post("/auth/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export type AuthEventOutcome = "success" | "failure" | "locked" | "denied" | "trust_change";

/** One recorded access decision (#157, #226, #241): a login, a scan or deploy
 * target refused by the tenant's approved scope, or an SSH host-key pin an
 * admin set or removed. `client_ip` is empty for the decisions taken in the
 * service layer, which have no request to read it from. */
export type AuthEventInfo = {
  id: number;
  occurred_at: string | null;
  username: string;
  client_ip: string;
  outcome: AuthEventOutcome;
  reason: string | null;
  detail: string | null;
};

/** Always newest-first: this is a log, and the API takes no sort for it. */
export async function fetchAuthEvents(page?: PageParams, outcome?: AuthEventOutcome) {
  try {
    const params = pageSearchParams(page, outcome ? { outcome } : undefined);
    const { data } = await api.get<Page<AuthEventInfo>>(`/auth/events?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** What kind of principal made a change (#327). A service token and the console
 * account that minted it can carry the same name; only this tells them apart. */
export type AuditActorType = "user" | "service_token" | "agent" | "system";

/** One recorded administrative change (#327): an account created or disabled, a
 * membership granted, a credential minted or revoked, a scan scope replaced, a
 * report downloaded. `tenant_id` is null for a platform-level act, which only a
 * platform admin sees. `before`/`after` arrive with every credential-shaped
 * field already replaced by `[redacted]` on the server. */
export type AuditEventInfo = {
  id: number;
  occurred_at: string | null;
  tenant_id: string | null;
  actor: string;
  actor_type: AuditActorType;
  action: string;
  resource_type: string;
  resource_id: string;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  client_ip: string;
  user_agent: string;
  request_id: string | null;
};

/** The trail's filters. All exact matches: "every change to *this* token" is the
 * question an audit asks, and a substring match is how the wrong row gets read
 * as the right one. `from`/`to` are ISO instants. */
export type AuditFilters = {
  tenantId?: string;
  actor?: string;
  action?: string;
  resourceType?: string;
  resourceId?: string;
  from?: string;
  to?: string;
};

function auditFilterParams(filters?: AuditFilters): Record<string, string> {
  const params: Record<string, string> = {};
  if (filters?.tenantId) params.tenant_id = filters.tenantId;
  if (filters?.actor) params.actor = filters.actor;
  if (filters?.action) params.action = filters.action;
  if (filters?.resourceType) params.resource_type = filters.resourceType;
  if (filters?.resourceId) params.resource_id = filters.resourceId;
  if (filters?.from) params.from = filters.from;
  if (filters?.to) params.to = filters.to;
  return params;
}

/** Always newest-first: this is a log, and the API takes no sort for it. */
export async function fetchAuditEvents(page?: PageParams, filters?: AuditFilters) {
  try {
    const params = pageSearchParams(page, auditFilterParams(filters));
    const { data } = await api.get<Page<AuditEventInfo>>(`/audit?${params}`);
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Export every matching event, not the page on screen. Fetched as a blob via
 * axios so the Authorization interceptor applies — a plain <a href> would not
 * carry the bearer token. */
export async function downloadAuditExport(
  format: "csv" | "ndjson",
  filters?: AuditFilters,
) {
  try {
    const params = new URLSearchParams({ ...auditFilterParams(filters), format });
    const { data } = await api.get<Blob>(`/audit?${params}`, { responseType: "blob" });
    triggerBrowserDownload(data, `audit-events.${format}`);
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** One user's access to one tenant (ROADMAP P0). The role inside the tenant
 * can differ from the account's global role. */
export type MembershipInfo = {
  username: string;
  tenant_id: string;
  role: Role;
  created_at: string | null;
  created_by: string | null;
};

export async function fetchTenantMembers(tenantId: string) {
  try {
    const { data } = await api.get<MembershipInfo[]>(
      `/tenants/${encodeURIComponent(tenantId)}/members`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** Grant or re-grant one user access to one tenant. Idempotent, so the same
 * call is both "add" and "change the role". */
export async function grantMembership(tenantId: string, username: string, role: Role) {
  try {
    const { data } = await api.put<MembershipInfo>(
      `/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(username)}`,
      { role },
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function revokeMembership(tenantId: string, username: string) {
  try {
    await api.delete(
      `/tenants/${encodeURIComponent(tenantId)}/members/${encodeURIComponent(username)}`,
    );
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/** The plaintext key is never in this list: it exists once, in the response to
 * the create call the agent deployment dialog makes. */
export async function fetchProvisioningKeys(tenantId: string) {
  try {
    const { data } = await api.get<ProvisioningKeyInfo[]>(
      `/tenants/${encodeURIComponent(tenantId)}/provisioning-keys`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function revokeProvisioningKey(tenantId: string, keyId: string) {
  try {
    const { data } = await api.post<ProvisioningKeyInfo>(
      `/tenants/${encodeURIComponent(tenantId)}/provisioning-keys/${encodeURIComponent(keyId)}/revoke`,
    );
    return data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}
