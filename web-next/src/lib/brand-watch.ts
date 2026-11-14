import { api, apiErrorMessage } from "@/lib/api";

/**
 * Brand-watch console client. Separate from scan runs: candidates are names
 * the watch observed, never assets and never scan targets.
 *
 * The axios instance already attaches the bearer token and the active tenant.
 * Paths are relative to `NEXT_PUBLIC_API_BASE_URL` (default `/api`).
 */

export type BrandWatchSeverity = "informational" | "low" | "medium" | "high" | "critical";

/** Exact values accepted by POST …/candidates/{id}/disposition. */
export type BrandWatchDisposition = "open" | "false_positive" | "whitelisted" | "confirmed";

/**
 * Whether this principal may set a disposition. The API grants
 * `brand_watch.disposition` to the tenant admin. A missing permission list
 * hides the control.
 */
export function canSetBrandWatchDisposition(
  permissions: readonly string[] | null | undefined,
): boolean {
  return Boolean(permissions?.includes("brand_watch.disposition"));
}

/**
 * Whether this principal may create and approve a profile. The API grants
 * `brand_watch.write` to the tenant admin, not to an operator. A missing
 * permission list hides the form: showing it and collecting a 403 is worse
 * than waiting for a principal that names the permission.
 */
export function canWriteBrandWatch(
  permissions: readonly string[] | null | undefined,
): boolean {
  return Boolean(permissions?.includes("brand_watch.write"));
}

/** A watched brand: official names and the domains that are already ours. */
export type BrandWatchProfile = {
  id: string;
  name: string;
  approved: boolean;
  /** Present when the API says the profile is approved but HTTP is still off. */
  http_allowed?: boolean;
  official_domains: string[];
  created_at?: string | null;
  updated_at?: string | null;
};

/** Body for POST /brand-watch/profiles. Creating does not start a scan. */
export type BrandWatchProfileCreate = {
  name: string;
  official_domains: string[];
  /** The edited preview. Empty means the nightly rebuild may generate names. */
  watched_names: string[];
  /** Always false on create. Approval is a separate, explicit confirmation. */
  our_brand: false;
};

export type LookalikePreview = {
  names: { name: string; rule: string }[];
  truncated: boolean;
};

/**
 * One generated name for a profile. `name` is text, never HTML. Empty until
 * the daily rebuild; opening this list does not scan the name.
 */
export type BrandWatchCandidate = {
  id: string;
  profile_id?: string | null;
  name: string;
  state: string | null;
  disposition?: string | null;
  punycode?: string | null;
};

/** One name whose observation changed. `name` is text, never HTML. */
export type BrandWatchDiffRow = {
  id: string;
  profile_id?: string | null;
  name: string;
  previous_state: string | null;
  new_state: string | null;
  severity: string | null;
  mx_present: boolean | null;
  last_changed: string | null;
  disposition?: string | null;
  punycode?: string | null;
};

export type BrandWatchDiffQuery = {
  /** ISO-8601 instant. Relative windows are converted before the request. */
  since?: string | null;
};

/** Turn a console window into the ISO instant the API's datetime query wants. */
export function sinceInstant(window: string, now: Date = new Date()): string | null {
  const trimmed = window.trim();
  if (!trimmed) return null;
  const hours = trimmed === "24h" ? 24 : trimmed === "7d" ? 24 * 7 : trimmed === "30d" ? 24 * 30 : null;
  if (hours == null) return trimmed;
  return new Date(now.getTime() - hours * 60 * 60 * 1000).toISOString();
}

const SEVERITY_LABELS: Record<string, string> = {
  informational: "Informational",
  info: "Informational",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/** Display label for a diff-row severity. Unknown values stay as text. */
export function severityLabel(severity: string | null | undefined): string {
  if (severity == null || severity.trim() === "") return "—";
  const key = severity.trim().toLowerCase();
  return SEVERITY_LABELS[key] ?? severity.trim();
}

/**
 * How a candidate name is shown. Prefer the Unicode name; when the API also
 * sent a distinct punycode form, append it so an operator can see the IDNA
 * encoding without treating it as a second candidate.
 */
export function punycodeDisplay(name: string, punycode?: string | null): string {
  const label = name.trim();
  const encoded = punycode?.trim() ?? "";
  if (!encoded || encoded.toLowerCase() === label.toLowerCase()) return label;
  return `${label} (${encoded})`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asBool(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function unwrapList(data: unknown, keys: string[]): unknown[] {
  if (Array.isArray(data)) return data;
  const record = asRecord(data);
  if (!record) return [];
  for (const key of keys) {
    if (Array.isArray(record[key])) return record[key] as unknown[];
  }
  return [];
}

export function parseProfile(value: unknown): BrandWatchProfile | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = asString(record.id) ?? asString(record.profile_id);
  const name = asString(record.name);
  if (!id || name == null) return null;
  const approved =
    record.approved === true ||
    record.status === "approved" ||
    (typeof record.approved_at === "string" && record.approved_at.length > 0 && record.our_brand === true);
  return {
    id,
    name,
    approved,
    http_allowed: record.mode === "http_allowed",
    official_domains: asStringList(record.official_domains ?? record.domains),
    created_at: asString(record.created_at),
    updated_at: asString(record.updated_at),
  };
}

/** Non-empty lines, trimmed. Blank lines are not sent as domains or strings. */
export function linesToList(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function parseCandidate(value: unknown): BrandWatchCandidate | null {
  const record = asRecord(value);
  if (!record) return null;
  const id = asString(record.id) ?? asString(record.candidate_id);
  const name =
    asString(record.name) ??
    asString(record.name_unicode) ??
    asString(record.candidate) ??
    asString(record.domain);
  if (!id || name == null) return null;
  return {
    id,
    profile_id: asString(record.profile_id),
    name,
    state: asString(record.state),
    disposition: asString(record.disposition),
    punycode: asString(record.punycode) ?? asString(record.name_punycode),
  };
}

export function parseDiffRow(value: unknown): BrandWatchDiffRow | null {
  const record = asRecord(value);
  if (!record) return null;
  const payload = asRecord(record.payload);
  const id = asString(record.id) ?? asString(record.candidate_id);
  const name =
    asString(record.name) ??
    asString(payload?.name) ??
    asString(record.candidate) ??
    asString(record.domain);
  if (!id || name == null) return null;
  return {
    id,
    profile_id: asString(record.profile_id),
    name,
    previous_state:
      asString(record.previous_state) ??
      asString(record.previous) ??
      asString(payload?.from_state),
    new_state:
      asString(record.new_state) ??
      asString(record.state) ??
      asString(payload?.to_state),
    severity: asString(record.severity) ?? asString(payload?.severity),
    mx_present: asBool(record.mx_present),
    last_changed: asString(record.last_changed) ?? asString(record.changed_at),
    disposition: asString(record.disposition),
    punycode: asString(record.punycode) ?? asString(record.name_punycode),
  };
}

export async function fetchBrandWatchProfiles(): Promise<BrandWatchProfile[]> {
  try {
    const { data } = await api.get<unknown>("/brand-watch/profiles");
    return unwrapList(data, ["items", "profiles"]).flatMap((item) => {
      const parsed = parseProfile(item);
      return parsed ? [parsed] : [];
    });
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchBrandWatchDiff(
  query: BrandWatchDiffQuery = {},
): Promise<BrandWatchDiffRow[]> {
  try {
    const { data } = await api.get<unknown>("/brand-watch/diff", {
      params: query.since ? { since: query.since } : undefined,
    });
    return unwrapList(data, ["items", "diff", "changes"]).flatMap((item) => {
      const parsed = parseDiffRow(item);
      return parsed ? [parsed] : [];
    });
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function previewLookalikeNames(domains: string[]): Promise<LookalikePreview> {
  try {
    const { data } = await api.post<unknown>("/brand-watch/preview", {
      official_domains: domains,
    });
    const record = data as { names?: unknown; truncated?: unknown };
    const names = Array.isArray(record?.names)
      ? record.names.flatMap((item) => {
          if (!item || typeof item !== "object") return [];
          const row = item as { name?: unknown; rule?: unknown };
          const name = typeof row.name === "string" ? row.name.trim() : "";
          if (!name) return [];
          return [{ name, rule: typeof row.rule === "string" ? row.rule : "" }];
        })
      : [];
    return { names, truncated: record?.truncated === true };
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function createBrandWatchProfile(
  body: BrandWatchProfileCreate,
): Promise<BrandWatchProfile> {
  try {
    const { data } = await api.post<unknown>("/brand-watch/profiles", {
      name: body.name,
      official_domains: body.official_domains,
      watched_names: body.watched_names,
      our_brand: false,
    });
    const parsed = parseProfile(data);
    if (!parsed) throw new Error("Profile was not returned.");
    return parsed;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

/**
 * Confirm that the listed domains belong to this tenant. `our_brand` must be
 * true; the API refuses an approval that does not say so.
 */
export async function approveBrandWatchProfile(profileId: string): Promise<BrandWatchProfile> {
  try {
    const { data } = await api.post<unknown>(
      `/brand-watch/profiles/${encodeURIComponent(profileId)}/approve`,
      { our_brand: true },
    );
    const parsed = parseProfile(data);
    if (!parsed) throw new Error("Profile was not returned.");
    return parsed;
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function fetchBrandWatchCandidates(profileId: string): Promise<BrandWatchCandidate[]> {
  try {
    const { data } = await api.get<unknown>(
      `/brand-watch/profiles/${encodeURIComponent(profileId)}/candidates`,
    );
    return unwrapList(data, ["items", "candidates"]).flatMap((item) => {
      const parsed = parseCandidate(item);
      return parsed ? [parsed] : [];
    });
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}

export async function setCandidateDisposition(
  candidateId: string,
  disposition: BrandWatchDisposition,
): Promise<void> {
  try {
    await api.post(`/brand-watch/candidates/${encodeURIComponent(candidateId)}/disposition`, {
      disposition,
    });
  } catch (error) {
    throw new Error(apiErrorMessage(error));
  }
}
