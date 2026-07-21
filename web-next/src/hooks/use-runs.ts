"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchHosts, fetchPorts, fetchRun, fetchRuns, fetchVulns } from "@/lib/api";
import { POLL_INTERVALS, VULN_FETCH_LIMIT } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useRuns(refetchInterval: number = POLL_INTERVALS.runs) {
  return useQuery({
    queryKey: queryKeys.runs,
    queryFn: fetchRuns,
    refetchInterval,
  });
}

export function useRunDetail(runId: string) {
  return useQuery({
    queryKey: queryKeys.run(runId),
    queryFn: () => fetchRun(runId),
    enabled: Boolean(runId),
  });
}

export function useRunHosts(runId: string) {
  return useQuery({
    queryKey: queryKeys.runHosts(runId),
    queryFn: () => fetchHosts(runId),
    enabled: Boolean(runId),
  });
}

export function useRunPorts(runId: string) {
  return useQuery({
    queryKey: queryKeys.runPorts(runId),
    queryFn: () => fetchPorts(runId),
    enabled: Boolean(runId),
  });
}

export function useRunVulns(
  runId: string,
  filters?: { host?: string | null; port?: string | null; limit?: number },
) {
  const host = filters?.host ?? null;
  const port = filters?.port ?? null;
  const limit = filters?.limit ?? VULN_FETCH_LIMIT;
  return useQuery({
    queryKey: queryKeys.runVulns(runId, { host, port }),
    queryFn: () => fetchVulns(runId, limit, host, port),
    enabled: Boolean(runId),
    staleTime: 30_000,
  });
}
