"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  deleteAgent,
  deployAgentSSH,
  fetchAgentDeploymentSnippets,
  fetchAgentDetail,
  fetchAgents,
  fetchAgentSummary,
  fetchDeployStatus,
  triggerAgentUpgrade,
  type AgentDeploySSHRequest,
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

export function useDeployStatus(deployId: string | null) {
  return useQuery({
    queryKey: queryKeys.deployStatus(deployId || ""),
    queryFn: () => (deployId ? fetchDeployStatus(deployId) : null),
    enabled: Boolean(deployId),
    refetchInterval: 1500,
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
  });
}

export function useDeleteAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => deleteAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.agents });
      queryClient.invalidateQueries({ queryKey: queryKeys.agentSummary });
    },
  });
}
