import { api, apiErrorMessage, type Page, type PageParams, type VulnerabilityListFilters } from "@/lib/api";

/**
 * Aggregated problems and remediation campaigns (#579).
 *
 * A problem is a *view* over tracked findings; a campaign is a durable effort
 * over a frozen snapshot of them. Neither owns a finding's state, owner, SLA or
 * exception — see docs/remediation-campaigns.md.
 */

export const PROBLEM_SORTS = [
  "risk",
  "severity",
  "instances",
  "assets",
  "breached",
  "kev",
  "last_seen",
  "due",
] as const;
export type ProblemSort = (typeof PROBLEM_SORTS)[number];

export type ProblemKind = "cve" | "tpl" | "script" | "unknown";

export type ProblemRow = {
  problem_key: string;
  kind: ProblemKind;
  cve: string | null;
  title: string;
  instances: number;
  assets: number;
  /** Worst instance (maximum), never an average. */
  severity: string;
  contextual_score: number | null;
  cvss: number | null;
  /** Not stored with findings: always null, i.e. unknown. */
  epss: number | null;
  kev_instances: number;
  in_kev: boolean;
  first_seen_at: string | null;
  last_seen_at: string | null;
  states: Record<string, number>;
  machine_verified: number;
  owners: {
    unassigned_instances: number;
    assignees: { name: string; instances: number }[];
    teams: { name: string; instances: number }[];
  };
  sla: { breached: number; due_soon: number; earliest_due_at: string | null };
  exposure: {
    external: number;
    internal: number;
    unknown: number;
    sources: Record<string, number>;
    basis: Record<string, number>;
  };
};

export type ProblemAggregates = {
  problems: number;
  instances: number;
  assets: number;
  breached_instances: number;
  kev_instances: number;
  unassigned_instances: number;
  machine_verified_instances: number;
};

export type ProblemPage = Page<ProblemRow> & {
  aggregates: ProblemAggregates;
  as_of: string;
  semantics: Record<string, string>;
};

export type ProblemDrift = {
  expected_instances: number;
  actual_instances: number;
  differs: boolean;
  changed_since_as_of: number;
  explanation: string | null;
};

/** The filters the findings list and the problem list share, as query params. */
export function findingFilterParams(
  filters: VulnerabilityListFilters | undefined,
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!filters) return out;
  if (filters.state) out.state = filters.state;
  if (filters.open_only) out.open_only = "true";
  if (filters.severity) out.severity = filters.severity;
  if (filters.asset_id) out.asset_id = filters.asset_id;
  if (filters.source) out.source = filters.source;
  if (filters.finding_type) out.finding_type = filters.finding_type;
  if (filters.detector_source) out.detector_source = filters.detector_source;
  if (filters.assignee) out.assignee = filters.assignee;
  if (filters.unassigned) out.unassigned = "true";
  if (filters.sla) out.sla = filters.sla;
  if (filters.in_kev) out.in_kev = "true";
  if (filters.network_exposure) out.network_exposure = filters.network_exposure;
  if (filters.stale_days != null) out.stale_days = String(filters.stale_days);
  return out;
}

function pageParams(page?: PageParams): Record<string, string | number> {
  const out: Record<string, string | number> = {};
  if (page?.offset != null) out.offset = page.offset;
  if (page?.limit != null) out.limit = page.limit;
  if (page?.q) out.q = page.q;
  if (page?.sort) out.sort = page.sort;
  if (page?.order) out.order = page.order;
  return out;
}

async function call<T>(promise: Promise<{ data: T }>): Promise<T> {
  try {
    return (await promise).data;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export const problemsApi = {
  list: (filters?: VulnerabilityListFilters, page?: PageParams) =>
    call(
      api.get<ProblemPage>("/problems", {
        params: { ...findingFilterParams(filters), ...pageParams(page) },
      }),
    ),
  instances: (
    problemKey: string,
    filters?: VulnerabilityListFilters,
    page?: PageParams,
    drift?: { as_of: string; expected_instances: number },
  ) =>
    call(
      api.get<Page<unknown> & { drift: ProblemDrift | null }>("/problems/instances", {
        params: {
          ...findingFilterParams(filters),
          ...pageParams(page),
          problem_key: problemKey,
          ...(drift ?? {}),
        },
      }),
    ),
};

// --------------------------------------------------------------------------
// Campaigns
// --------------------------------------------------------------------------

export const CAMPAIGN_CATEGORIES = [
  "open",
  "fixing",
  "awaiting_verification",
  "verified",
  "accepted_risk",
  "false_positive",
  "closed_unverified",
  "unavailable",
] as const;
export type CampaignCategory = (typeof CAMPAIGN_CATEGORIES)[number];
export type CampaignStatus = "active" | "completed" | "cancelled";

export type CampaignSelection = {
  problem_keys?: string[];
  vuln_ids?: string[];
  filters?: Record<string, unknown>;
};

export type CampaignProgress = {
  total: number;
  excluded: number;
  categories: Record<CampaignCategory, number>;
  unresolved: number;
  recurred: number;
  assets: number;
  tickets: { linked_findings: number; distinct_tickets: number };
};

export type Campaign = {
  campaign_id: string;
  name: string;
  description: string;
  owner: string | null;
  due_at: string | null;
  status: CampaignStatus;
  status_changed_at: string | null;
  completed_at: string | null;
  reopen_count: number;
  past_due: boolean;
  composition_hash: string;
  snapshot_size: number;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  progress: CampaignProgress;
  replayed?: boolean;
};

export type CampaignPreview = {
  total: number;
  assets: number;
  problems: { problem_key: string; title: string; instances: number; assets: number }[];
  composition_hash: string;
  already_in_other_campaigns: number;
  skipped: { id: string; reason: string }[];
  items: {
    vuln_id: string;
    asset_id: string;
    problem_key: string;
    cve: string | null;
    title: string;
    severity: string;
    state: string;
  }[];
  truncated: boolean;
  as_of: string;
};

export type CampaignCreateBody = {
  name: string;
  description?: string;
  owner?: string | null;
  due_at?: string | null;
  selection: CampaignSelection;
  composition_hash?: string;
};

export type CampaignMember = {
  vuln_id: string;
  status: "included" | "excluded";
  category: CampaignCategory;
  problem_key: string;
  asset_id: string;
  cve: string | null;
  title: string;
  severity: string;
  state: string;
  assignee: string | null;
  due_at: string | null;
  sla_state: string;
  machine_verified: boolean;
  closure_reason: string | null;
  reopen_count: number;
  recurred: boolean;
  ticket_system: string | null;
  ticket_key: string | null;
  ticket_url: string | null;
  added_by: string | null;
  added_at: string;
  add_reason: string | null;
  excluded_by: string | null;
  excluded_at: string | null;
  exclude_reason: string | null;
  last_verify: { requested_at: string | null; outcome: string | null; detail: string | null };
  verification: { kind: string; at: string; note: string | null; gaps: string[] | null } | null;
};

export type CampaignEvent = {
  id: number;
  occurred_at: string;
  kind: string;
  actor: string | null;
  reason: string | null;
  detail: Record<string, unknown>;
};

export type MembershipReport = {
  results: { id: string; outcome: string; detail?: string }[];
  added?: number;
  readded?: number;
  excluded?: number;
  campaign: Campaign;
};

export type VerifyReport = {
  results: { id: string; outcome: string; detail?: string; job_id?: string }[];
  summary: Record<string, number>;
  campaign: Campaign;
  replayed?: boolean;
};

const BASE = "/remediation-campaigns";

function withKey(key?: string) {
  return key ? { headers: { "Idempotency-Key": key } } : undefined;
}

export const campaignsApi = {
  preview: (selection: CampaignSelection) =>
    call(api.post<CampaignPreview>(`${BASE}/preview`, selection)),
  create: (body: CampaignCreateBody, idempotencyKey?: string) =>
    call(api.post<Campaign>(BASE, body, withKey(idempotencyKey))),
  list: (page?: PageParams, status?: CampaignStatus) =>
    call(api.get<Page<Campaign>>(BASE, { params: { ...pageParams(page), ...(status ? { status } : {}) } })),
  get: (id: string) => call(api.get<Campaign>(`${BASE}/${encodeURIComponent(id)}`)),
  update: (
    id: string,
    body: Partial<Pick<Campaign, "name" | "description" | "owner" | "due_at">>,
  ) => call(api.patch<Campaign>(`${BASE}/${encodeURIComponent(id)}`, body)),
  members: (
    id: string,
    page?: PageParams,
    options?: { status?: "included" | "excluded"; category?: CampaignCategory | ""; problem_key?: string },
  ) =>
    call(
      api.get<Page<CampaignMember>>(`${BASE}/${encodeURIComponent(id)}/members`, {
        params: {
          ...pageParams(page),
          ...(options?.status ? { status: options.status } : {}),
          ...(options?.category ? { category: options.category } : {}),
          ...(options?.problem_key ? { problem_key: options.problem_key } : {}),
        },
      }),
    ),
  addMembers: (id: string, selection: CampaignSelection, reason: string) =>
    call(
      api.post<MembershipReport>(`${BASE}/${encodeURIComponent(id)}/members`, { selection, reason }),
    ),
  excludeMembers: (id: string, vulnIds: string[], reason: string) =>
    call(
      api.post<MembershipReport>(`${BASE}/${encodeURIComponent(id)}/members/exclude`, {
        vuln_ids: vulnIds,
        reason,
      }),
    ),
  events: (id: string, page?: PageParams) =>
    call(api.get<Page<CampaignEvent>>(`${BASE}/${encodeURIComponent(id)}/events`, { params: pageParams(page) })),
  verify: (id: string, vulnIds?: string[], idempotencyKey?: string) =>
    call(
      api.post<VerifyReport>(
        `${BASE}/${encodeURIComponent(id)}/verify`,
        vulnIds ? { vuln_ids: vulnIds } : {},
        withKey(idempotencyKey),
      ),
    ),
  cancel: (id: string, reason: string) =>
    call(api.post<Campaign>(`${BASE}/${encodeURIComponent(id)}/cancel`, { reason })),
  resume: (id: string, reason: string) =>
    call(api.post<Campaign>(`${BASE}/${encodeURIComponent(id)}/resume`, { reason })),
};

/** Selection a campaign is created from: the visible filters narrow what a
 * problem key expands to (open findings only unless the caller chose states). */
export function selectionFromFilters(
  problemKeys: string[],
  vulnIds: string[],
  filters: VulnerabilityListFilters | undefined,
): CampaignSelection {
  const params = findingFilterParams(filters);
  const narrowing: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params)) {
    if (key === "open_only") continue; // campaigns only take open findings anyway
    if (key === "unassigned" || key === "in_kev") narrowing[key] = true;
    else if (key === "stale_days") narrowing[key] = Number(value);
    else narrowing[key] = value;
  }
  return {
    ...(problemKeys.length ? { problem_keys: problemKeys } : {}),
    ...(vulnIds.length ? { vuln_ids: vulnIds } : {}),
    ...(problemKeys.length && Object.keys(narrowing).length ? { filters: narrowing } : {}),
  };
}
