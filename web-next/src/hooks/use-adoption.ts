"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAdoption } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useAdoption(windowDays: number) {
  return useQuery({
    queryKey: queryKeys.adoption(windowDays),
    queryFn: () => fetchAdoption(windowDays),
  });
}
