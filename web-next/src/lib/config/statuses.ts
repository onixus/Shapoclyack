import type {
  AgentInfo,
  AgentLifecycleStatus,
  AssetContextSource,
  AssetServiceMatchStatus,
  AssetDataClassification,
  AssetEnvironment,
  AssetExposureLevel,
  AssetStatus,
  AuthEventOutcome,
  EndpointReconciliationStatus,
  JobInfo,
  MaintenanceWindowKind,
  NistRiskLevel,
  RetroMatchConfidence,
  Role,
  ScanScopeEffect,
  SlaState,
  SoftwareCveMatchStatus,
  TenantDeletionState,
  TenantDeletionStepState,
  TenantInfo,
  VulnerabilitySource,
  VulnLifecycleState,
} from "@/lib/api";
import type { Severity } from "@/lib/run-data";

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline";

/** What a status means, independent of its colour. The badge draws the
 * tone's icon next to the word (APEX: a status is icon + word, colour only
 * repeats it); `severity` is the CVSS scale, which carries a label alone. */
export type StatusTone = "success" | "warning" | "danger" | "info" | "muted" | "severity";

export type StatusStyle = {
  label: string;
  variant?: BadgeVariant;
  /** Color override applied on top of the Badge variant. */
  className?: string;
  tone?: StatusTone;
};

// APEX semantic palette shared by every status family: a `*-subtle` plate
// with the text and icon in the status colour. Token values for both themes
// live in globals.css.
const SUCCESS = { className: "bg-success-subtle text-success border border-success/30 font-semibold", tone: "success" } as const;
const IN_PROGRESS = { className: "bg-warning-subtle text-warning border border-warning/30 font-semibold", tone: "warning" } as const;
const DANGER = { className: "bg-danger-subtle text-danger border border-danger/30 font-semibold", tone: "danger" } as const;
const INFO = { className: "bg-info-subtle text-info border border-info/30 font-semibold", tone: "info" } as const;
const MUTED = { className: "bg-muted text-muted-foreground border border-border font-medium", tone: "muted" } as const;

// The one CVSS scale (sev-critical … sev-info), shared with Pulse and APEX.
const SEV_CRITICAL = { className: "bg-sev-critical/10 text-sev-critical border border-sev-critical/40 font-bold", tone: "severity" } as const;
const SEV_HIGH = { className: "bg-sev-high/10 text-sev-high border border-sev-high/40 font-semibold", tone: "severity" } as const;
const SEV_MEDIUM = { className: "bg-sev-medium/10 text-sev-medium border border-sev-medium/40 font-semibold", tone: "severity" } as const;
const SEV_LOW = { className: "bg-sev-low/10 text-sev-low border border-sev-low/40 font-semibold", tone: "severity" } as const;
const SEV_INFO = { className: "bg-sev-info/10 text-sev-info border border-sev-info/40 font-medium", tone: "severity" } as const;

export const JOB_STATUS: Record<JobInfo["status"], StatusStyle> = {
  succeeded: { label: "succeeded", ...SUCCESS },
  running: { label: "running", ...IN_PROGRESS },
  claimed: { label: "claimed", ...IN_PROGRESS, },
  failed: { label: "failed", variant: "destructive", ...DANGER },
  queued: { label: "queued", variant: "secondary", ...MUTED },
  // Amber like `claimed`, not red: the scan is on its way down at an
  // operator's request, which is neither a failure nor finished (#360).
  cancelling: {
    label: "cancelling",
    ...IN_PROGRESS,
  },
  cancelled: { label: "cancelled", variant: "secondary", ...MUTED },
};

export type AgentEffectiveStatus = AgentInfo["status"] | "offline";

export const AGENT_STATUS: Record<AgentEffectiveStatus, StatusStyle> = {
  idle: { label: "idle", ...SUCCESS },
  busy: { label: "busy", ...IN_PROGRESS },
  error: { label: "error", variant: "destructive", ...DANGER },
  stale: { label: "stale", variant: "outline", ...IN_PROGRESS, },
  offline: { label: "offline", variant: "secondary", ...MUTED },
};

/** The operator's verdict (#308), shown next to — not instead of — the
 * reported status: a quarantined agent that is still heartbeating is idle
 * *and* quarantined, and an operator needs both facts to act on it. */
export const AGENT_LIFECYCLE_STATUS: Record<AgentLifecycleStatus, StatusStyle> = {
  active: { label: "active", ...SUCCESS },
  disabled: { label: "disabled", variant: "secondary", ...MUTED },
  quarantined: { label: "quarantined", variant: "destructive", ...DANGER },
};

/** Connectivity wins over the agent's self-reported status. */
export function agentEffectiveStatus(agent: AgentInfo): AgentEffectiveStatus {
  return agent.online ? agent.status : "offline";
}

export const SCHEDULE_ENABLED_STATUS: Record<"enabled" | "disabled", StatusStyle> = {
  enabled: { label: "enabled", ...SUCCESS },
  disabled: { label: "disabled", variant: "secondary", ...MUTED },
};

/** `suspended`, not `disabled`: that is the word the API serialises and the
 * one #318's enforcement refuses with. Danger rather than muted — a suspended
 * tenant is refusing every one of its people, which is a state to notice
 * rather than an "off" switch. Only a platform admin ever sees it: the tenant
 * listing drops suspended tenants for everyone else. */
export const TENANT_STATUS: Record<TenantInfo["status"], StatusStyle> = {
  active: { label: "active", ...SUCCESS },
  suspended: { label: "suspended", variant: "destructive", ...DANGER },
  // The deletion's two halves (#325): refused like a suspension, and on its
  // way out.
  pending_deletion: { label: "pending deletion", variant: "destructive", ...DANGER },
  deleting: { label: "deleting", variant: "destructive", ...DANGER },
};

/** One entry of the tenant deletion journal (#325). */
export const TENANT_DELETION_STATUS: Record<TenantDeletionState, StatusStyle> = {
  pending: { label: "pending", ...IN_PROGRESS },
  purging: { label: "purging", variant: "destructive", ...DANGER },
  blocked: { label: "blocked", variant: "destructive", ...DANGER },
  cancelled: { label: "cancelled", variant: "secondary", ...MUTED },
  completed: { label: "completed", ...SUCCESS },
};

/** One store of a tenant purge (#325). */
export const TENANT_DELETION_STEP_STATUS: Record<TenantDeletionStepState, StatusStyle> = {
  pending: { label: "pending", variant: "secondary", ...MUTED },
  running: { label: "running", ...IN_PROGRESS },
  waiting: { label: "waiting", ...IN_PROGRESS },
  failed: { label: "failed", variant: "destructive", ...DANGER },
  done: { label: "done", ...SUCCESS },
  skipped: { label: "skipped", variant: "secondary", ...MUTED },
};

/** An allow/deny entry of a tenant's approved scanning scope (#226). Deny is
 * the strong one — it wins over allow by overlap — so it reads as the danger
 * colour rather than as a muted "off". */
export const SCAN_SCOPE_EFFECT: Record<ScanScopeEffect, StatusStyle> = {
  allow: { label: "allow", ...SUCCESS },
  deny: { label: "deny", variant: "destructive", ...DANGER },
};

/** The polarity of a maintenance window (#352). A blackout forbids scanning
 * while it is open, so it reads as the danger colour; an `allowed` window is
 * the inverse — the only time scanning is permitted — and reads as success
 * even though its effect outside the window is a refusal. */
export const MAINTENANCE_WINDOW_KIND: Record<MaintenanceWindowKind, StatusStyle> = {
  blackout: { label: "blackout", variant: "destructive", ...DANGER },
  allowed: { label: "allowed", ...SUCCESS },
};

export const ASSET_STATUS: Record<AssetStatus, StatusStyle> = {
  active: { label: "active", ...SUCCESS },
  stale: { label: "stale", ...IN_PROGRESS },
  decommissioned: { label: "decommissioned", ...MUTED },
};

/** Operator-set business criticality (0–4). Keyed by the raw int the API stores. */
export const ASSET_CRITICALITY: Record<number, StatusStyle> = {
  0: { label: "none", variant: "secondary", ...MUTED },
  1: { label: "low", ...SEV_LOW },
  2: { label: "medium", ...SEV_MEDIUM },
  3: { label: "high", ...SEV_HIGH },
  4: { label: "critical", ...SEV_CRITICAL },
};

/** Operator- or CMDB-set environment (#146). */
export const ASSET_ENVIRONMENT: Record<AssetEnvironment, StatusStyle> = {
  production: { label: "production", ...DANGER },
  staging: { label: "staging", ...IN_PROGRESS },
  development: { label: "development", ...INFO },
  lab: { label: "lab", variant: "secondary", ...MUTED },
  other: { label: "other", variant: "secondary", ...MUTED },
};

export const ASSET_DATA_CLASSIFICATION: Record<AssetDataClassification, StatusStyle> = {
  public: { label: "public", variant: "secondary", ...MUTED },
  internal: { label: "internal", ...INFO },
  confidential: { label: "confidential", ...IN_PROGRESS },
  restricted: { label: "restricted", ...DANGER },
};

/** Operator-set posture, not a scan measurement (#171 is the network fact). */
export const ASSET_EXPOSURE: Record<AssetExposureLevel, StatusStyle> = {
  internet: { label: "internet", ...DANGER },
  partner: { label: "partner", ...IN_PROGRESS },
  internal: { label: "internal", ...INFO },
  unknown: { label: "unknown", variant: "secondary", ...MUTED },
};

export const ASSET_CONTEXT_SOURCE: Record<AssetContextSource, StatusStyle> = {
  operator: { label: "operator", ...INFO },
  cmdb: { label: "CMDB", ...INFO },
  ad: { label: "AD", ...INFO },
  other: { label: "other", variant: "secondary", ...MUTED },
};

export const ENDPOINT_RECONCILIATION_STATUS: Record<EndpointReconciliationStatus, StatusStyle> = {
  linked: { label: "linked", ...SUCCESS },
  conflict: { label: "conflict", variant: "destructive", ...DANGER },
  unlinked: { label: "unlinked", variant: "secondary", ...MUTED },
};

export const SOFTWARE_CHANGE_STATUS: Record<"installed" | "removed" | "updated", StatusStyle> = {
  installed: { label: "installed", ...SUCCESS },
  removed: { label: "removed", variant: "destructive", ...DANGER },
  updated: { label: "updated", ...IN_PROGRESS },
};

/** Software→CVE match statuses (ROADMAP Track E M1).
 *
 * ``unknown`` is styled as a warning rather than as muted on purpose: it means
 * the matcher could not assess the package at all, and an operator who reads it
 * as "nothing found" has drawn exactly the wrong conclusion. ``not_applicable``
 * is the muted one — the vendor answered, and the answer was "no". */
export const SOFTWARE_CVE_MATCH_STATUS: Record<SoftwareCveMatchStatus, StatusStyle> = {
  vulnerable: { label: "vulnerable", variant: "destructive", ...DANGER },
  fixed: { label: "fixed", ...SUCCESS },
  not_applicable: { label: "not applicable", variant: "secondary", ...MUTED },
  unknown: { label: "unknown", variant: "outline", ...IN_PROGRESS },
};

/** Which observer found a tracked finding (Track E, M3). Deliberately quiet
 * styling: the source is context for the row, not a severity signal. */
export const VULN_SOURCE_STATUS: Record<VulnerabilitySource, StatusStyle> = {
  scan: { label: "scan", variant: "outline", ...MUTED },
  endpoint_software: { label: "endpoint", variant: "outline", ...INFO },
  retro_match: { label: "retro match", variant: "outline", ...INFO },
};

/** How sure the retro matcher is (docs/retro-cve-matching.md). A vendor's own
 * statement outranks an NVD range, and "backport possible" is the muted one:
 * it is never a tracked finding, only a possible CVE on the service row. */
export const RETRO_MATCH_CONFIDENCE: Record<RetroMatchConfidence, StatusStyle> = {
  vendor_advisory: { label: "vendor advisory", variant: "outline", ...INFO },
  version_range: { label: "version range", variant: "outline", ...IN_PROGRESS },
  backport_possible: { label: "backport possible", variant: "secondary", ...MUTED },
};

/** Whether the retro matcher could assess a stored listener. Every reason it
 * could not is a warning, not muted — for the same cause as the software
 * matcher's `unknown`: an empty CVE list on such a row means "not asked", and
 * reading it as "clean" is exactly the wrong conclusion. */
export const ASSET_SERVICE_MATCH_STATUS: Record<AssetServiceMatchStatus, StatusStyle> = {
  matched: { label: "assessed", ...SUCCESS },
  unknown_product: { label: "unknown product", variant: "outline", ...IN_PROGRESS },
  no_version: { label: "no version", variant: "outline", ...IN_PROGRESS },
  lookalike: { label: "lookalike", variant: "outline", ...IN_PROGRESS },
  too_old: { label: "too old", variant: "outline", ...IN_PROGRESS },
  no_dataset: { label: "no dataset", variant: "outline", ...IN_PROGRESS },
};

/** A listener no sweep has reached yet (`match_status` null). */
export const ASSET_SERVICE_NOT_MATCHED: StatusStyle = {
  label: "not yet matched",
  variant: "secondary",
  ...MUTED,
};

export const SEVERITY_STATUS: Record<Severity, StatusStyle & { tremorColor: string }> = {
  critical: { label: "critical", ...SEV_CRITICAL, tremorColor: "rose" },
  high: { label: "high", ...SEV_HIGH, tremorColor: "orange" },
  medium: { label: "medium", ...SEV_MEDIUM, tremorColor: "yellow" },
  low: { label: "low", ...SEV_LOW, tremorColor: "blue" },
  unknown: { label: "unknown", ...SEV_INFO, tremorColor: "slate" },
};

/** Happy-path order, matching `api/services/vuln_states.py` ORDER. */
export const VULN_LIFECYCLE_STATUS: Record<VulnLifecycleState, StatusStyle> = {
  OPEN: { label: "open", ...INFO },
  ACKNOWLEDGED: { label: "acknowledged", ...IN_PROGRESS },
  PLANNED: { label: "planned", ...INFO },
  FIXING: { label: "fixing", ...IN_PROGRESS },
  VERIFYING: { label: "verifying", ...INFO },
  CLOSED: { label: "closed", ...SUCCESS },
};

/** Remediation campaign status (#579). `completed` is derived by the API and
 * means every member is verified, an accepted risk or a false positive. */
export const CAMPAIGN_STATUS: Record<string, StatusStyle> = {
  active: { label: "active", ...INFO },
  completed: { label: "completed", ...SUCCESS },
  cancelled: { label: "cancelled", variant: "secondary", ...MUTED },
};

export const SLA_STATUS: Record<SlaState, StatusStyle> = {
  on_track: { label: "on track", ...SUCCESS },
  due_soon: { label: "due soon", ...IN_PROGRESS },
  breached: {
    label: "breached",
    variant: "destructive",
    ...DANGER,
  },
  accepted: {
    label: "accepted risk",
    ...INFO,
  },
  none: { label: "no SLA", variant: "secondary", ...MUTED },
};

/** NIST SP 800-30 qualitative levels — worst-last, matching `nist_risk.LEVELS`. */
export const RISK_LEVEL_STATUS: Record<NistRiskLevel, StatusStyle & { tremorColor: string }> = {
  very_high: { label: "very high", ...SEV_CRITICAL, tremorColor: "rose" },
  high: { label: "high", ...SEV_HIGH, tremorColor: "orange" },
  moderate: { label: "moderate", ...SEV_MEDIUM, tremorColor: "yellow" },
  low: { label: "low", ...SEV_LOW, tremorColor: "blue" },
  very_low: { label: "very low", variant: "secondary", ...MUTED, tremorColor: "slate" },
};


/** Webhook delivery queue state. `dead` is the dead-letter queue — the retry
 * budget is spent or the receiver answered with something a retry cannot fix,
 * so it is a failure an admin has to act on rather than a transient one. */
export const WEBHOOK_DELIVERY_STATUS: Record<"pending" | "delivered" | "dead", StatusStyle> = {
  delivered: { label: "delivered", ...SUCCESS },
  pending: { label: "pending", ...IN_PROGRESS },
  dead: { label: "dead", variant: "destructive", ...DANGER },
};

/** The account's global role (#156). It is the fallback authority: a user's
 * role *inside* a tenant comes from their membership row and can differ. */
export const USER_ROLE_STATUS: Record<Role, StatusStyle> = {
  admin: { label: "admin", ...INFO },
  operator: { label: "operator", ...INFO },
  viewer: { label: "viewer", variant: "secondary", ...MUTED },
};

/** Whether the account can sign in. Disabling beats deleting — the memberships
 * and the history survive it — so it reads as muted rather than as a failure. */
export const ACCOUNT_STATUS: Record<"active" | "disabled" | "erased", StatusStyle> = {
  active: { label: "active", ...SUCCESS },
  disabled: { label: "disabled", variant: "secondary", ...MUTED },
  // A data-subject erasure's tombstone (#332): disabled for good.
  erased: { label: "erased", variant: "secondary", ...MUTED },
};

/** The account's second factor (#315). "pending" is a setup that was started
 * and never confirmed: the account still signs in with its password alone, so
 * it is a warning rather than a success. */
export const MFA_STATUS: Record<"on" | "off" | "pending", StatusStyle> = {
  on: { label: "mfa on", ...SUCCESS },
  off: { label: "mfa off", variant: "secondary", ...MUTED },
  pending: { label: "setup unfinished", ...IN_PROGRESS },
};

/** One decision in the auth trail (#157, #226, #241). `locked` is the rate
 * limiter refusing before the credentials were even checked, `denied` an
 * authenticated principal refused an action, `trust_change` an SSH host-key
 * pin an admin set or removed — neither an attempt nor a refusal. */
export const AUTH_EVENT_OUTCOME: Record<AuthEventOutcome, StatusStyle> = {
  success: { label: "success", ...SUCCESS },
  failure: { label: "failure", variant: "destructive", ...DANGER },
  locked: { label: "locked", ...IN_PROGRESS },
  denied: { label: "denied", variant: "destructive", ...DANGER },
  trust_change: { label: "trust change", ...INFO },
};

export const PROVISIONING_KEY_STATUS: Record<"active" | "revoked", StatusStyle> = {
  active: { label: "active", ...SUCCESS },
  revoked: { label: "revoked", variant: "secondary", ...MUTED },
};
