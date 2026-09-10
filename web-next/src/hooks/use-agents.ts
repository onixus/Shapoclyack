"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createAgentDeploymentKey,
  deleteAgent,
  deployAgentSSH,
  fetchAgentDeploymentSnippets,
  fetchAgentDetail,
  fetchAgents,
  fetchAgentSummary,
  fetchDeployStatus,
  probeAgentSSHHostKey,
  triggerAgentUpgrade,
  updateAgentStatus,
  type AgentDeploySSHRequest,
  type AgentLifecycleStatus,
  type PageParams,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useAgents(page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.agentsPage(page),
    queryFn: () => fetchAgents(page),
    refetchInterval: POLL_INTERVALS.agents,
  });
}

export function useAgentSummary() {
  return useQuery({
    queryKey: queryKeys.agentSummary,
    queryFn: fetchAgentSummary,
    refetchInterval: POLL_INTERVALS.agents,
  });
}

export function useAgentDetail(agentId: string | null) {
  return useQuery({
    queryKey: queryKeys.agentDetail(agentId || ""),
    queryFn: () => (agentId ? fetchAgentDetail(agentId) : null),
    enabled: Boolean(agentId),
    refetchInterval: POLL_INTERVALS.agents,
  });
}

export function useAgentSnippets() {
  return useQuery({
    queryKey: queryKeys.agentSnippets,
    queryFn: fetchAgentDeploymentSnippets,
    staleTime: 60_000,
  });
}

export function useCreateAgentDeploymentKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (label?: string) => createAgentDeploymentKey(label),
    onSuccess: (data) => {
      // Show the freshly minted key in place of the placeholder snippets.
      queryClient.setQueryData(queryKeys.agentSnippets, data);
    },
  });
}

export function useDeployStatus(deployId: string | null) {
  return useQuery({
    queryKey: queryKeys.deployStatus(deployId || ""),
    queryFn: () => (deployId ? fetchDeployStatus(deployId) : null),
    enabled: Boolean(deployId),
    refetchInterval: 1500,
  });
}

/** Read a target's SSH host key so the operator can verify it before deploying.
 * Deliberately not a query: it reaches out to a host the operator just typed,
 * so it happens when they ask for it and not on every keystroke. */
export function useProbeSSHHostKey() {
  return useMutation({
    mutationFn: ({ host, port }: { host: string; port: number }) =>
      probeAgentSSHHostKey(host, port),
  });
}

export function useDeploySSH() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: AgentDeploySSHRequest) => deployAgentSSH(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSummary });
    },
  });
}

export function useUpgradeAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => triggerAgentUpgrade(agentId),
    onSuccess: (_, agentId) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSummary });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentDetail(agentId) });
    },
    onError: (err: Error) => {
      toast.error("Failed to mark agent for upgrade", { description: err.message });
    },
  });
}

/** Disable, quarantine, or re-activate an agent (#308).
 *
 * The refreshed agent comes back in the response, so the detail drawer is
 * seeded from what the server stored rather than from what was asked for —
 * `reason` is trimmed and dropped entirely on a return to `active`. */
export function useUpdateAgentStatus() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      agentId,
      status,
      reason,
    }: {
      agentId: string;
      status: AgentLifecycleStatus;
      reason?: string;
    }) => updateAgentStatus(agentId, status, reason ?? ""),
    onSuccess: (agent) => {
      queryClient.setQueryData(queryKeys.agentDetail(agent.agent_id), agent);
      queryClient.invalidateQueries({ queryKey: queryKeys.agents });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSummary });
      toast.success(`Agent is now ${agent.lifecycle_status ?? "active"}`);
    },
    onError: (err: Error) => {
      toast.error("Failed to change agent state", { description: err.message });
    },
  });
}

export function useDeleteAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, revokeKey }: { agentId: string; revokeKey?: boolean }) =>
      deleteAgent(agentId, revokeKey ?? false),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSummary });
      // Said out loud rather than assumed: an agent registered before the key
      // was tracked has none to revoke, and an operator who ticked the box
      // would otherwise walk away believing the credential is dead.
      if (result.key_revoked) {
        toast.success("Agent deregistered and its provisioning key revoked");
      } else if (result.provisioning_key_id === null) {
        toast.success("Agent deregistered", {
          description: "No provisioning key on record for this agent — nothing to revoke",
        });
      } else {
        toast.success("Agent deregistered", {
          description: "Its provisioning key is still valid; revoke it to stop re-registration",
        });
      }
    },
    onError: (err: Error) => {
      toast.error("Failed to deregister agent", { description: err.message });
    },
  });
}
