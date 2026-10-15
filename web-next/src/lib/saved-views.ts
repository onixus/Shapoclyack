import axios from "axios";
import { api } from "@/lib/api";

export type ViewPage = "assets" | "vulnerabilities";
export type ViewState = {
  version: 1;
  search: string;
  sort: string | null;
  order: "asc" | "desc";
  filters: Record<string, string | boolean>;
};
export type SavedView = {
  view_id: string;
  name: string;
  page: ViewPage;
  state: ViewState;
  compatible: boolean;
};

export async function fetchViews(page: ViewPage, tenant: string, signal?: AbortSignal) {
  return (
    await api.get<SavedView[]>("/saved-views", { params: { page, tenant_id: tenant }, signal })
  ).data;
}
export async function createView(page: ViewPage, name: string, state: ViewState, tenant: string) {
  return (
    await api.post<SavedView>(
      "/saved-views",
      { page, name, state },
      { params: { tenant_id: tenant } },
    )
  ).data;
}
export async function renameView(id: string, name: string, tenant: string) {
  return (
    await api.patch<SavedView>(
      `/saved-views/${encodeURIComponent(id)}`,
      { name },
      { params: { tenant_id: tenant } },
    )
  ).data;
}
export async function deleteView(id: string, tenant: string) {
  await api.delete(`/saved-views/${encodeURIComponent(id)}`, { params: { tenant_id: tenant } });
}

/** Filter values the API accepts in a saved view (api/services/saved_views.py). */
export const VIEW_FILTER_CHOICES = {
  state: ["OPEN", "ACKNOWLEDGED", "PLANNED", "FIXING", "VERIFYING", "CLOSED"],
  severity: ["critical", "high", "medium", "low", "unknown"],
  sla: ["on_track", "due_soon", "breached", "accepted", "none"],
  source: ["scan", "endpoint_software", "retro_match"],
  findingType: ["cve", "misconfiguration", "exposure"],
  detector: ["nuclei", "pulse", "pulse-plugin", "nmap-nse"],
  exposure: ["external", "internal", "unknown"],
} as const;

/**
 * Normalise a deep-link value (``?severity=HIGH``) to one the saved-view schema
 * accepts: trimmed, case-folded to the canonical spelling, and empty when the
 * value is unknown, so saving the view cannot be refused with a 422.
 */
export function pickFilter<K extends keyof typeof VIEW_FILTER_CHOICES>(
  key: K,
  raw: string | null | undefined,
): (typeof VIEW_FILTER_CHOICES)[K][number] | "" {
  const value = (raw || "").trim().toLowerCase();
  const match = VIEW_FILTER_CHOICES[key].find((choice) => choice.toLowerCase() === value);
  return (match ?? "") as (typeof VIEW_FILTER_CHOICES)[K][number] | "";
}

export type ViewFailure = "limit" | "duplicate" | "invalid" | "gone" | "generic";

/** Which refusal the API gave, so the console can say why instead of "try again". */
export function viewFailure(error: unknown): ViewFailure {
  const status = axios.isAxiosError(error) ? error.response?.status : undefined;
  if (status === 400) return "limit";
  if (status === 409) return "duplicate";
  if (status === 422) return "invalid";
  if (status === 404) return "gone";
  return "generic";
}
