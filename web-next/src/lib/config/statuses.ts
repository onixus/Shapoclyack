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
const SUCCESS = "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/30 font-semibold";
const IN_PROGRESS = "bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30 font-semibold";

export const JOB_STATUS: Record<JobInfo["status"], StatusStyle> = {
  succeeded: { label: "succeeded", className: SUCCESS },
  running: { label: "running", className: IN_PROGRESS },
  failed: { label: "failed", variant: "destructive", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-semibold" },
  queued: { label: "queued", variant: "secondary", className: "bg-slate-800 text-slate-300 border border-slate-700 font-semibold" },
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

export const SEVERITY_STATUS: Record<Severity, StatusStyle & { tremorColor: string }> = {
  critical: { label: "critical", className: "bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold", tremorColor: "rose" },
  high: { label: "high", className: "bg-orange-500/20 text-orange-300 border border-orange-500/30 font-semibold", tremorColor: "orange" },
  medium: { label: "medium", className: IN_PROGRESS, tremorColor: "amber" },
  low: { label: "low", className: "bg-sky-500/20 text-sky-300 border border-sky-500/30", tremorColor: "sky" },
  unknown: { label: "unknown", variant: "secondary", className: "bg-slate-800 text-slate-400", tremorColor: "slate" },
};

