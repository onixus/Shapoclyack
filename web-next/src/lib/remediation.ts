import type { TrackedVulnerability, VulnLifecycleState } from "@/lib/api";
import { VULN_STATES, legalTransitions } from "@/lib/vuln-lifecycle";

export const BOARD_OPEN_LIMIT = 500;
export const BOARD_CLOSED_LIMIT = 80;

export function groupByState(
  items: TrackedVulnerability[],
): Record<VulnLifecycleState, TrackedVulnerability[]> {
  const grouped = Object.fromEntries(VULN_STATES.map((state) => [state, [] as TrackedVulnerability[]])) as Record<
    VulnLifecycleState,
    TrackedVulnerability[]
  >;
  for (const item of items) {
    (grouped[item.state] ?? grouped.OPEN).push(item);
  }
  return grouped;
}

export function canDropOn(from: VulnLifecycleState, to: VulnLifecycleState): boolean {
  return from !== to && legalTransitions(from).includes(to);
}

export const TICKET_SYSTEMS: { value: "jira" | "servicenow" | "smax" | "defectdojo" | "other"; label: string }[] = [
  { value: "jira", label: "Jira" },
  { value: "servicenow", label: "ServiceNow" },
  { value: "smax", label: "SMAX" },
  { value: "defectdojo", label: "DefectDojo" },
  { value: "other", label: "Other" },
];
