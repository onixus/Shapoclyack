import type { NistRiskLevel, SlaState, TrackedVulnerability, VulnLifecycleState } from "@/lib/api";

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

/** Worst-last, matching `api/services/nist_risk.py` LEVELS. */
export const NIST_RISK_LEVELS: readonly NistRiskLevel[] = [
  "very_low",
  "low",
  "moderate",
  "high",
  "very_high",
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
  severity?: string;
  unassigned?: boolean;
}): string {
  const params = new URLSearchParams();
  if (filters?.assetId) params.set("assetId", filters.assetId);
  if (filters?.sla) params.set("sla", filters.sla);
  if (filters?.state) params.set("state", filters.state);
  if (filters?.severity) params.set("severity", filters.severity);
  if (filters?.unassigned) params.set("unassigned", "1");
  const query = params.toString();
  return query ? `/vulnerabilities?${query}` : "/vulnerabilities";
}

/** What an analyst should do next on this finding — SLA and ownership first. */
export function requiredAction(
  vuln: Pick<TrackedVulnerability, "state" | "assignee" | "sla_state">,
): string {
  if (vuln.sla_state === "breached") return "SLA breached";
  if (!vuln.assignee) return "Assign owner";
  if (vuln.state === "CLOSED") return "None";
  return VULN_TRANSITION_LABEL[VULN_PRIMARY_NEXT[vuln.state]];
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
