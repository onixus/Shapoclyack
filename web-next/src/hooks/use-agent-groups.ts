"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createAgentGroup,
  deleteAgentGroup,
  fetchAgentGroups,
  setAgentGroup,
  type AgentGroupInfo,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** The tenant's agent groups (#361) — the vocabulary of the scan form and of
 * the approved scope. Readable at viewer rank; changing one needs
 * `agent.group.manage`, which is why the mutations below can 403. */
export function useAgentGroups(enabled: boolean = true) {
  return useQuery<AgentGroupInfo[]>({
    queryKey: queryKeys.agentGroups,
    queryFn: fetchAgentGroups,
    enabled,
  });
}

export function useCreateAgentGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { name: string; description?: string }) => createAgentGroup(input),
    onSuccess: async (group) => {
      toast.success("Agent group created", { description: group.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.agents });
    },
    onError: (err) => {
      toast.error("Could not create the group", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteAgentGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => deleteAgentGroup(name),
    onSuccess: async () => {
      toast.success("Agent group deleted");
      await queryClient.invalidateQueries({ queryKey: queryKeys.agents });
    },
    onError: (err) => {
      // The common failure is a 409: an agent, a live job or a scope entry
      // still names the group. The server's sentence says which, so it is
      // shown rather than replaced with a generic one.
      toast.error("Could not delete the group", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetAgentGroup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { agentId: string; group: string | null }) =>
      setAgentGroup(input.agentId, input.group),
    onSuccess: async (agent) => {
      toast.success(
        agent.agent_group
          ? `Agent moved to ${agent.agent_group}`
          : "Agent removed from its group",
      );
      await queryClient.invalidateQueries({ queryKey: queryKeys.agents });
    },
    onError: (err) => {
      toast.error("Could not change the group", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
