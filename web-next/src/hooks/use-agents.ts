"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAgents } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useAgents() {
  return useQuery({
    queryKey: queryKeys.agents,
    queryFn: fetchAgents,
    refetchInterval: POLL_INTERVALS.agents,
  });
}
