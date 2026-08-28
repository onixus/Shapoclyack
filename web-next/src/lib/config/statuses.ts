import type {
  AgentInfo,
  AssetContextSource,
  AssetDataClassification,
  AssetEnvironment,
  AssetExposureLevel,
  AssetStatus,
  EndpointReconciliationStatus,
  JobInfo,
  NistRiskLevel,
  SlaState,
  TenantInfo,
  VulnLifecycleState,
} from "@/lib/api";
import type { Severity } from "@/lib/run-data";

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

export type StatusStyle = {
  label: string;
  variant?: BadgeVariant;
  /** Color override applied on top of the Badge variant. */
  className?: string;
};

// Canonical palette shared by every status family:
// Theme-adaptive classes with high contrast in both light and dark modes (WCAG AA).
const SUCCESS = "bg-emerald-500/10 text-emerald-800 dark:bg-emerald-500/20 dark:text-emerald-300 border border-emerald-500/30 font-semibold";
const IN_PROGRESS = "bg-amber-500/10 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300 border border-amber-500/30 font-semibold";
const DANGER = "bg-rose-500/10 text-rose-800 dark:bg-rose-500/20 dark:text-rose-300 border border-rose-500/30 font-semibold";
const INFO_SKY = "bg-sky-500/10 text-sky-800 dark:bg-sky-500/20 dark:text-sky-300 border border-sky-500/30 font-semibold";
const INFO_INDIGO = "bg-indigo-500/10 text-indigo-800 dark:bg-indigo-500/20 dark:text-indigo-300 border border-indigo-500/30 font-semibold";
const INFO_ORANGE = "bg-orange-500/10 text-orange-800 dark:bg-orange-500/20 dark:text-orange-300 border border-orange-500/30 font-semibold";
const INFO_VIOLET = "bg-violet-500/10 text-violet-800 dark:bg-violet-500/20 dark:text-violet-300 border border-violet-500/30 font-semibold";
const MUTED = "bg-muted text-muted-foreground border border-border font-medium";

export const JOB_STATUS: Record<JobInfo["status"], StatusStyle> = {
  succeeded: { label: "succeeded", className: SUCCESS },
  running: { label: "running", className: IN_PROGRESS },
  claimed: { label: "claimed", className: "bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-500/30 font-semibold" },
  failed: { label: "failed", variant: "destructive", className: DANGER },
  queued: { label: "queued", variant: "secondary", className: MUTED },
  cancelled: { label: "cancelled", variant: "secondary", className: MUTED },
};

export type AgentEffectiveStatus = AgentInfo["status"] | "offline";

export const AGENT_STATUS: Record<AgentEffectiveStatus, StatusStyle> = {
  idle: { label: "idle", className: SUCCESS },
  busy: { label: "busy", className: IN_PROGRESS },
  error: { label: "error", variant: "destructive", className: DANGER },
  stale: { label: "stale", variant: "outline", className: "bg-amber-500/10 text-amber-800 dark:text-amber-300 border border-amber-500/30" },
  offline: { label: "offline", variant: "secondary", className: MUTED },
};

/** Connectivity wins over the agent's self-reported status. */
export function agentEffectiveStatus(agent: AgentInfo): AgentEffectiveStatus {
  return agent.online ? agent.status : "offline";
}

export const SCHEDULE_ENABLED_STATUS: Record<"enabled" | "disabled", StatusStyle> = {
  enabled: { label: "enabled", className: SUCCESS },
  disabled: { label: "disabled", variant: "secondary", className: MUTED },
};

export const TENANT_STATUS: Record<TenantInfo["status"], StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  disabled: { label: "disabled", variant: "secondary", className: MUTED },
};

export const ASSET_STATUS: Record<AssetStatus, StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  stale: { label: "stale", className: IN_PROGRESS },
  decommissioned: { label: "decommissioned", className: MUTED },
};

/** Operator-set business criticality (0–4). Keyed by the raw int the API stores. */
export const ASSET_CRITICALITY: Record<number, StatusStyle> = {
  0: { label: "none", variant: "secondary", className: MUTED },
  1: { label: "low", className: INFO_SKY },
  2: { label: "medium", className: IN_PROGRESS },
  3: { label: "high", className: INFO_ORANGE },
  4: { label: "critical", className: `${DANGER} font-bold` },
};

/** Operator- or CMDB-set environment (#146). */
export const ASSET_ENVIRONMENT: Record<AssetEnvironment, StatusStyle> = {
  production: { label: "production", className: `${DANGER} font-semibold` },
  staging: { label: "staging", className: IN_PROGRESS },
  development: { label: "development", className: INFO_SKY },
  lab: { label: "lab", variant: "secondary", className: MUTED },
  other: { label: "other", variant: "secondary", className: MUTED },
};

export const ASSET_DATA_CLASSIFICATION: Record<AssetDataClassification, StatusStyle> = {
  public: { label: "public", variant: "secondary", className: MUTED },
  internal: { label: "internal", className: INFO_SKY },
  confidential: { label: "confidential", className: IN_PROGRESS },
  restricted: { label: "restricted", className: `${DANGER} font-semibold` },
};

/** Operator-set posture, not a scan measurement (#171 is the network fact). */
export const ASSET_EXPOSURE: Record<AssetExposureLevel, StatusStyle> = {
  internet: { label: "internet", className: `${DANGER} font-semibold` },
  partner: { label: "partner", className: IN_PROGRESS },
  internal: { label: "internal", className: INFO_SKY },
  unknown: { label: "unknown", variant: "secondary", className: MUTED },
};

export const ASSET_CONTEXT_SOURCE: Record<AssetContextSource, StatusStyle> = {
  operator: { label: "operator", className: INFO_SKY },
  cmdb: { label: "CMDB", className: INFO_INDIGO },
  ad: { label: "AD", className: INFO_INDIGO },
  other: { label: "other", variant: "secondary", className: MUTED },
};

export const ENDPOINT_RECONCILIATION_STATUS: Record<EndpointReconciliationStatus, StatusStyle> = {
  linked: { label: "linked", className: SUCCESS },
  conflict: { label: "conflict", variant: "destructive", className: `${DANGER} font-semibold` },
  unlinked: { label: "unlinked", variant: "secondary", className: MUTED },
};

export const SOFTWARE_CHANGE_STATUS: Record<"installed" | "removed" | "updated", StatusStyle> = {
  installed: { label: "installed", className: SUCCESS },
  removed: { label: "removed", variant: "destructive", className: `${DANGER} font-semibold` },
  updated: { label: "updated", className: IN_PROGRESS },
};

export const SEVERITY_STATUS: Record<Severity, StatusStyle & { tremorColor: string }> = {
  critical: { label: "critical", className: `${DANGER} font-bold`, tremorColor: "rose" },
  high: { label: "high", className: `${INFO_ORANGE} font-semibold`, tremorColor: "orange" },
  medium: { label: "medium", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: INFO_SKY, tremorColor: "sky" },
  unknown: { label: "unknown", variant: "secondary", className: MUTED, tremorColor: "slate" },
};

/** Happy-path order, matching `api/services/vuln_states.py` ORDER. */
export const VULN_LIFECYCLE_STATUS: Record<VulnLifecycleState, StatusStyle> = {
  OPEN: { label: "open", className: INFO_SKY },
  ACKNOWLEDGED: { label: "acknowledged", className: IN_PROGRESS },
  PLANNED: { label: "planned", className: INFO_INDIGO },
  FIXING: { label: "fixing", className: INFO_ORANGE },
  VERIFYING: { label: "verifying", className: INFO_VIOLET },
  CLOSED: { label: "closed", className: SUCCESS },
};

export const SLA_STATUS: Record<SlaState, StatusStyle> = {
  on_track: { label: "on track", className: SUCCESS },
  due_soon: { label: "due soon", className: IN_PROGRESS },
  breached: {
    label: "breached",
    variant: "destructive",
    className: `${DANGER} font-bold`,
  },
  accepted: {
    label: "accepted risk",
    className: INFO_INDIGO,
  },
  none: { label: "no SLA", variant: "secondary", className: MUTED },
};

/** NIST SP 800-30 qualitative levels — worst-last, matching `nist_risk.LEVELS`. */
export const RISK_LEVEL_STATUS: Record<NistRiskLevel, StatusStyle & { tremorColor: string }> = {
  very_high: {
    label: "very high",
    className: `${DANGER} font-bold`,
    tremorColor: "rose",
  },
  high: {
    label: "high",
    className: `${INFO_ORANGE} font-semibold`,
    tremorColor: "orange",
  },
  moderate: { label: "moderate", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: INFO_SKY, tremorColor: "sky" },
  very_low: {
    label: "very low",
    variant: "secondary",
    className: MUTED,
    tremorColor: "slate",
  },
};

