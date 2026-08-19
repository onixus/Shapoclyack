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
// success → emerald-600, in-progress → amber-500 (dark text for contrast),
// failure → destructive variant, neutral/off → secondary variant.
const SUCCESS = "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 font-semibold";
const IN_PROGRESS = "bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 font-semibold";

export const JOB_STATUS: Record<JobInfo["status"], StatusStyle> = {
  succeeded: { label: "succeeded", className: SUCCESS },
  running: { label: "running", className: IN_PROGRESS },
  // Held by an agent that has not reported starting yet: in flight, but not
  // yet scanning, so it reads as in-progress with a lighter treatment.
  claimed: { label: "claimed", className: "bg-amber-500/10 text-amber-400 border border-amber-500/30 font-semibold" },
  failed: { label: "failed", variant: "destructive", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  queued: { label: "queued", variant: "secondary", className: "bg-slate-800 text-slate-300 border border-slate-700 font-semibold" },
  cancelled: { label: "cancelled", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export type AgentEffectiveStatus = AgentInfo["status"] | "offline";

export const AGENT_STATUS: Record<AgentEffectiveStatus, StatusStyle> = {
  idle: { label: "idle", className: SUCCESS },
  busy: { label: "busy", className: IN_PROGRESS },
  error: { label: "error", variant: "destructive", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  stale: { label: "stale", variant: "outline", className: "bg-amber-500/10 text-amber-400 border border-amber-500/30" },
  offline: { label: "offline", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

/** Connectivity wins over the agent's self-reported status. */
export function agentEffectiveStatus(agent: AgentInfo): AgentEffectiveStatus {
  return agent.online ? agent.status : "offline";
}

export const SCHEDULE_ENABLED_STATUS: Record<"enabled" | "disabled", StatusStyle> = {
  enabled: { label: "enabled", className: SUCCESS },
  disabled: { label: "disabled", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const TENANT_STATUS: Record<TenantInfo["status"], StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  disabled: { label: "disabled", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const ASSET_STATUS: Record<AssetStatus, StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  stale: { label: "stale", className: IN_PROGRESS },
  decommissioned: { label: "decommissioned", className: "bg-slate-800 text-slate-400 border border-slate-700 font-normal" },
};

/** Operator-set business criticality (0–4). Keyed by the raw int the API stores. */
export const ASSET_CRITICALITY: Record<number, StatusStyle> = {
  0: { label: "none", variant: "secondary", className: "bg-slate-800 text-slate-400" },
  1: { label: "low", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30" },
  2: { label: "medium", className: IN_PROGRESS },
  3: { label: "high", className: "bg-orange-500/20 text-orange-300 border border-orange-500/30" },
  4: { label: "critical", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold" },
};

/** Operator- or CMDB-set environment (#146). */
export const ASSET_ENVIRONMENT: Record<AssetEnvironment, StatusStyle> = {
  production: { label: "production", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  staging: { label: "staging", className: IN_PROGRESS },
  development: { label: "development", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30" },
  lab: { label: "lab", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
  other: { label: "other", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const ASSET_DATA_CLASSIFICATION: Record<AssetDataClassification, StatusStyle> = {
  public: { label: "public", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
  internal: { label: "internal", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30" },
  confidential: { label: "confidential", className: IN_PROGRESS },
  restricted: { label: "restricted", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
};

/** Operator-set posture, not a scan measurement (#171 is the network fact). */
export const ASSET_EXPOSURE: Record<AssetExposureLevel, StatusStyle> = {
  internet: { label: "internet", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  partner: { label: "partner", className: IN_PROGRESS },
  internal: { label: "internal", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30" },
  unknown: { label: "unknown", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const ASSET_CONTEXT_SOURCE: Record<AssetContextSource, StatusStyle> = {
  operator: { label: "operator", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30" },
  cmdb: { label: "CMDB", className: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold" },
  ad: { label: "AD", className: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold" },
  other: { label: "other", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const ENDPOINT_RECONCILIATION_STATUS: Record<EndpointReconciliationStatus, StatusStyle> = {
  linked: { label: "linked", className: SUCCESS },
  conflict: { label: "conflict", variant: "destructive", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  unlinked: { label: "unlinked", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

export const SOFTWARE_CHANGE_STATUS: Record<"installed" | "removed" | "updated", StatusStyle> = {
  installed: { label: "installed", className: SUCCESS },
  removed: { label: "removed", variant: "destructive", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  updated: { label: "updated", className: IN_PROGRESS },
};

export const SEVERITY_STATUS: Record<Severity, StatusStyle & { tremorColor: string }> = {
  critical: { label: "critical", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold", tremorColor: "rose" },
  high: { label: "high", className: "bg-orange-500/20 text-orange-300 border border-orange-500/30 font-semibold", tremorColor: "orange" },
  medium: { label: "medium", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30", tremorColor: "sky" },
  unknown: { label: "unknown", variant: "secondary", className: "bg-slate-800 text-slate-400", tremorColor: "slate" },
};

/** Happy-path order, matching `api/services/vuln_states.py` ORDER. */
export const VULN_LIFECYCLE_STATUS: Record<VulnLifecycleState, StatusStyle> = {
  OPEN: { label: "open", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30 font-semibold" },
  ACKNOWLEDGED: { label: "acknowledged", className: IN_PROGRESS },
  PLANNED: { label: "planned", className: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold" },
  FIXING: { label: "fixing", className: "bg-orange-500/20 text-orange-300 border border-orange-500/30 font-semibold" },
  VERIFYING: { label: "verifying", className: "bg-violet-500/20 text-violet-300 border border-violet-500/30 font-semibold" },
  CLOSED: { label: "closed", className: SUCCESS },
};

export const SLA_STATUS: Record<SlaState, StatusStyle> = {
  on_track: { label: "on track", className: SUCCESS },
  due_soon: { label: "due soon", className: IN_PROGRESS },
  breached: {
    label: "breached",
    variant: "destructive",
    className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold",
  },
  accepted: {
    label: "accepted risk",
    className: "bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-semibold",
  },
  none: { label: "no SLA", variant: "secondary", className: "bg-slate-800 text-slate-400 border border-slate-700" },
};

/** NIST SP 800-30 qualitative levels — worst-last, matching `nist_risk.LEVELS`. */
export const RISK_LEVEL_STATUS: Record<NistRiskLevel, StatusStyle & { tremorColor: string }> = {
  very_high: {
    label: "very high",
    className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold",
    tremorColor: "rose",
  },
  high: {
    label: "high",
    className: "bg-orange-500/20 text-orange-300 border border-orange-500/30 font-semibold",
    tremorColor: "orange",
  },
  moderate: { label: "moderate", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30", tremorColor: "sky" },
  very_low: {
    label: "very low",
    variant: "secondary",
    className: "bg-slate-800 text-slate-400",
    tremorColor: "slate",
  },
};

