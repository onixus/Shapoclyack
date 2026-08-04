"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAgents, type PageParams } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useAgents(page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.agentsPage(page),
    queryFn: () => fetchAgents(page),
    refetchInterval: POLL_INTERVALS.agents,
  });
}
