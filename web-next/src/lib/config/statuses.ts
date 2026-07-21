import type { AgentInfo, AssetStatus, JobInfo, TenantInfo } from "@/lib/api";
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
const SUCCESS = "bg-emerald-600 hover:bg-emerald-600";
const IN_PROGRESS = "bg-amber-500 hover:bg-amber-500 text-slate-900";

export const JOB_STATUS: Record<JobInfo["status"], StatusStyle> = {
  succeeded: { label: "succeeded", className: SUCCESS },
  running: { label: "running", className: IN_PROGRESS },
  failed: { label: "failed", variant: "destructive" },
  queued: { label: "queued", variant: "secondary" },
};

export type AgentEffectiveStatus = AgentInfo["status"] | "offline";

export const AGENT_STATUS: Record<AgentEffectiveStatus, StatusStyle> = {
  idle: { label: "idle", className: SUCCESS },
  busy: { label: "busy", className: IN_PROGRESS },
  error: { label: "error", variant: "destructive" },
  stale: { label: "stale", variant: "outline" },
  offline: { label: "offline", variant: "secondary" },
};

/** Connectivity wins over the agent's self-reported status. */
export function agentEffectiveStatus(agent: AgentInfo): AgentEffectiveStatus {
  return agent.online ? agent.status : "offline";
}

export const TENANT_STATUS: Record<TenantInfo["status"], StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  disabled: { label: "disabled", variant: "secondary" },
};

export const ASSET_STATUS: Record<AssetStatus, StatusStyle> = {
  active: { label: "active", className: SUCCESS },
  stale: { label: "stale", className: IN_PROGRESS },
  decommissioned: { label: "decommissioned", className: "bg-slate-400 hover:bg-slate-400" },
};

export const SEVERITY_STATUS: Record<Severity, StatusStyle & { tremorColor: string }> = {
  critical: { label: "critical", className: "bg-rose-700 hover:bg-rose-700", tremorColor: "rose" },
  high: { label: "high", className: "bg-orange-600 hover:bg-orange-600", tremorColor: "orange" },
  medium: { label: "medium", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: "bg-sky-600 hover:bg-sky-600", tremorColor: "sky" },
  unknown: { label: "unknown", variant: "secondary", tremorColor: "slate" },
};
