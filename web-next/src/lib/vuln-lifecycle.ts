import type { SlaState, TrackedVulnerability, VulnLifecycleState } from "@/lib/api";

/** Happy-path order — must match `api/services/vuln_states.py` ORDER. */
export const VULN_STATES: readonly VulnLifecycleState[] = [
  "OPEN",
  "ACKNOWLEDGED",
  "PLANNED",
  "FIXING",
  "VERIFYING",
  "CLOSED",
] as const;

export const SLA_STATES: readonly SlaState[] = [
  "on_track",
  "due_soon",
  "breached",
  "accepted",
  "none",
] as const;

/**
 * Legal moves, copied from `api/services/vuln_states.py` TRANSITIONS so the
 * UI can hide illegal buttons without a round-trip. The API remains the
 * authority — a 409 is still possible if the finding moved under us.
 */
export const VULN_TRANSITIONS: Record<VulnLifecycleState, readonly VulnLifecycleState[]> = {
  OPEN: ["ACKNOWLEDGED", "PLANNED", "FIXING", "CLOSED"],
  ACKNOWLEDGED: ["PLANNED", "FIXING", "CLOSED"],
  PLANNED: ["ACKNOWLEDGED", "FIXING", "CLOSED"],
  FIXING: ["PLANNED", "VERIFYING", "CLOSED"],
  VERIFYING: ["FIXING", "CLOSED"],
  CLOSED: ["OPEN"],
};

/** Next happy-path state, or reopen from CLOSED. */
export const VULN_PRIMARY_NEXT: Record<VulnLifecycleState, VulnLifecycleState> = {
  OPEN: "ACKNOWLEDGED",
  ACKNOWLEDGED: "PLANNED",
  PLANNED: "FIXING",
  FIXING: "VERIFYING",
  VERIFYING: "CLOSED",
  CLOSED: "OPEN",
};

export const VULN_TRANSITION_LABEL: Record<VulnLifecycleState, string> = {
  OPEN: "Reopen",
  ACKNOWLEDGED: "Acknowledge",
  PLANNED: "Plan",
  FIXING: "Start fix",
  VERIFYING: "Verify",
  CLOSED: "Close",
};

export function legalTransitions(state: VulnLifecycleState): readonly VulnLifecycleState[] {
  return VULN_TRANSITIONS[state] ?? [];
}

/** Static-export friendly detail URL (no dynamic `[vulnId]` segment). */
export function vulnDetailHref(vulnId: string, tenantId?: string | null): string {
  const params = new URLSearchParams({ vulnId });
  if (tenantId && tenantId !== "default") params.set("tenantId", tenantId);
  return `/vulnerabilities/view?${params}`;
}

export function vulnListHref(filters?: {
  assetId?: string;
  sla?: SlaState;
  state?: VulnLifecycleState;
}): string {
  const params = new URLSearchParams();
  if (filters?.assetId) params.set("assetId", filters.assetId);
  if (filters?.sla) params.set("sla", filters.sla);
  if (filters?.state) params.set("state", filters.state);
  const query = params.toString();
  return query ? `/vulnerabilities?${query}` : "/vulnerabilities";
}

export function findingLabel(
  vuln: Pick<TrackedVulnerability, "cve" | "script_id" | "title">,
): string {
  return vuln.cve || vuln.script_id || vuln.title || "finding";
}

export function assetDetailHref(assetId: string, tenantId?: string | null): string {
  const params = new URLSearchParams({ assetId });
  if (tenantId && tenantId !== "default") params.set("tenantId", tenantId);
  return `/assets/view?${params}`;
}
