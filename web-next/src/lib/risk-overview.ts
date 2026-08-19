import type { NistRiskLevel, VulnerabilitySummary } from "@/lib/api";
import { RISK_LEVEL_STATUS } from "@/lib/config/statuses";

export function estateRiskColor(level: NistRiskLevel | null | undefined): string {
  if (level === "very_high" || level === "high") return "rose";
  if (level === "moderate") return "amber";
  if (level === "low" || level === "very_low") return "emerald";
  return "slate";
}

/** Label for the estate-risk tile. `none` = no open work; `unset` = open
 * findings that have no NIST level yet; `…` while the summary has not arrived. */
export function estateRiskLabel(summary: VulnerabilitySummary | undefined): string {
  if (!summary) return "…";
  if (summary.estate_risk) return RISK_LEVEL_STATUS[summary.estate_risk].label;
  return summary.open_total === 0 ? "none" : "unset";
}
