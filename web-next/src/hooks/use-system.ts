"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchSystemStatus } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useSystemStatus() {
  return useQuery({
    queryKey: queryKeys.system,
    queryFn: fetchSystemStatus,
  });
}
