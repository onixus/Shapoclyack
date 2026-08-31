"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchComplianceFrameworks, fetchCompliancePosture } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useComplianceFrameworks() {
  return useQuery({
    queryKey: queryKeys.complianceFrameworks,
    queryFn: fetchComplianceFrameworks,
    // The catalogue is code, not data: it cannot change while the console is
    // open, so it is fetched once per session rather than per page visit.
    staleTime: Infinity,
  });
}

export function useCompliancePosture(frameworkId: string | null) {
  return useQuery({
    queryKey: queryKeys.compliancePosture(frameworkId ?? ""),
    queryFn: () => fetchCompliancePosture(frameworkId as string),
    enabled: Boolean(frameworkId),
  });
}
