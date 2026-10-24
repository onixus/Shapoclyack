import { api } from "@/lib/api";

export type OperatorStatus = {
  provider: string;
  model: string;
  external_inference: boolean;
  runtime_status: string;
  quality_status: string;
  task_submission_enabled: boolean;
};
export type Citation = {
  source_id: string;
  source_hash: string;
  snapshot_id: string;
  source_type?: string;
  status?: string;
  observed_at?: string;
};
export type OperatorAnswer = {
  status: string;
  summary: string;
  reason?: string;
  citations?: Citation[];
  recommendations?: {
    source_id: string;
    category: string;
    proposed_priority: string;
    next_steps: string[];
  }[];
};
export type OperatorTask = {
  task_id: string;
  kind: string;
  run_id: string;
  status: string;
  cancel_requested: boolean;
  error: string | null;
  result: {
    quality_status?: string;
    analysis?: OperatorAnswer;
    answer?: { answer: OperatorAnswer };
  } | null;
};
export type OperatorSession = {
  session_id: string;
  tenant_id: string;
  username: string;
  created_at: string;
  tasks?: OperatorTask[];
  proposals?: OperatorProposal[];
};
export type ProposalAction = "start_scan" | "cancel_scan" | "verify_finding";
export type OperatorProposal = {
  proposal_id: string;
  session_id: string;
  tenant_id: string;
  username?: string;
  action: ProposalAction;
  arguments: Record<string, unknown>;
  arguments_sha256: string;
  expires_at: string;
  status: string;
  impact: unknown;
  execution: { execution_id: string; status: string; result?: unknown; error?: unknown } | null;
};
export type RemediationSource = Citation & {
  advisory_id?: string;
  provider?: string;
  feed_date?: string;
};
export type RemediationItem = {
  package: string;
  installed_version: string;
  target_version: string | null;
  distro: string;
  distro_release: string;
  architecture: string;
  status: string;
  cve_ids: string[];
  upgrade_command: string | null;
  sources: RemediationSource[];
  verification: { method: string; requires_confirmation: boolean };
  limitations: string[];
};
export type RemediationResult = {
  device_id: string;
  snapshot_id: string;
  state: string;
  quality_status: string;
  reason: string | null;
  items: RemediationItem[];
  truncated: boolean;
};

export type OperatorComparison = {
  status: string;
  quality_status: string;
  summary: string;
  reason: string;
  counts: Record<string, number>;
  citations: Citation[];
  diff_source?: {
    run_id: string;
    artifact: string;
    source_hash: string;
    snapshot_id: string;
  } | null;
};

const id = encodeURIComponent;
// Every request captures an explicit tenant. An interceptor's active tenant
// must never retarget a request that was prepared in a previous context.
const options = (tenant: string, signal?: AbortSignal) => {
  if (!tenant.trim()) throw new Error("Explicit tenant required");
  return { params: { tenant_id: tenant }, signal };
};
export const operatorApi = {
  async compare(
    tenant: string,
    previous: string,
    current: string,
    language: "ru" | "en",
    signal?: AbortSignal,
  ) {
    return (
      await api.get<OperatorComparison>("/operator/compare", {
        ...options(tenant, signal),
        params: { tenant_id: tenant, previous_run_id: previous, current_run_id: current, language },
      })
    ).data;
  },
  async status(tenant: string, signal?: AbortSignal) {
    return (await api.get<OperatorStatus>("/operator/status", options(tenant, signal))).data;
  },
  async sessions(tenant: string, signal?: AbortSignal) {
    return (
      await api.get<{ items: OperatorSession[]; total: number }>(
        "/operator/sessions",
        options(tenant, signal),
      )
    ).data;
  },
  async session(tenant: string, session: string, signal?: AbortSignal) {
    return (
      await api.get<OperatorSession>(`/operator/sessions/${id(session)}`, options(tenant, signal))
    ).data;
  },
  async createSession(tenant: string) {
    return (await api.post<OperatorSession>("/operator/sessions", {}, options(tenant))).data;
  },
  async submit(
    tenant: string,
    session: string,
    body: { tool: string; run_id: string; language: "ru" | "en" },
    key: string,
  ) {
    return (
      await api.post<OperatorTask>(`/operator/sessions/${id(session)}/tasks`, body, {
        ...options(tenant),
        headers: { "Idempotency-Key": key },
      })
    ).data;
  },
  async cancel(tenant: string, task: string) {
    return (await api.post<OperatorTask>(`/operator/tasks/${id(task)}/cancel`, {}, options(tenant)))
      .data;
  },
  async evidence(tenant: string, citation: Citation, signal?: AbortSignal) {
    const path =
      citation.source_type === "run"
        ? `/operator/evidence/runs/${id(citation.source_id)}/summary`
        : `/operator/evidence/${id(citation.source_id)}`;
    return (
      await api.get<Record<string, unknown>>(path, {
        ...options(tenant, signal),
        params: {
          tenant_id: tenant,
          snapshot_id: citation.snapshot_id,
          source_hash: citation.source_hash,
        },
      })
    ).data;
  },
  async prepare(
    tenant: string,
    session: string,
    action: ProposalAction,
    args: Record<string, unknown>,
  ) {
    return (
      await api.post<OperatorProposal>(
        `/operator/sessions/${id(session)}/proposals`,
        { action, arguments: args },
        options(tenant),
      )
    ).data;
  },
  async proposal(tenant: string, proposal: string, signal?: AbortSignal) {
    return (
      await api.get<OperatorProposal>(
        `/operator/proposals/${id(proposal)}`,
        options(tenant, signal),
      )
    ).data;
  },
  async confirm(tenant: string, proposal: string, hash: string) {
    return (
      await api.post<OperatorProposal>(
        `/operator/proposals/${id(proposal)}/confirm`,
        { arguments_sha256: hash },
        options(tenant),
      )
    ).data;
  },
  async remediation(tenant: string, device: string, language: "ru" | "en", signal?: AbortSignal) {
    return (
      await api.get<RemediationResult>(`/operator/remediation/devices/${id(device)}`, {
        ...options(tenant, signal),
        params: { tenant_id: tenant, language, limit: 50 },
      })
    ).data;
  },
  async remediationSource(
    tenant: string,
    device: string,
    citation: Citation,
    signal?: AbortSignal,
  ) {
    return (
      await api.get<Record<string, unknown>>(
        `/operator/remediation/devices/${id(device)}/sources/${id(citation.source_id)}`,
        {
          ...options(tenant, signal),
          params: {
            tenant_id: tenant,
            snapshot_id: citation.snapshot_id,
            source_hash: citation.source_hash,
          },
        },
      )
    ).data;
  },
};

export function operatorUnavailable(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 404;
}
export const operatorKey = (tenant: string, actor: string) =>
  ["local-operator", tenant, actor] as const;
export const activeTask = (task: OperatorTask) =>
  task.status === "queued" || task.status === "running";
