"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchHosts,
  fetchPorts,
  fetchRun,
  fetchRuns,
  fetchScreenshots,
  fetchVulns,
  type PageParams,
  type ScanListFilters,
} from "@/lib/api";
import { POLL_INTERVALS, VULN_FETCH_LIMIT } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

/** Paginated run list (ROADMAP P3.3). Callers that only need the newest runs
 * (latest-run pickers, trends) can leave `page` unset and read `data.items`. */
export function useRuns(
  refetchInterval: number = POLL_INTERVALS.runs,
  page?: PageParams,
  filters?: ScanListFilters,
) {
  return useQuery({
    queryKey: queryKeys.runsPage(page, filters),
    queryFn: () => fetchRuns(page, filters),
    refetchInterval,
  });
}

export function useRunDetail(runId: string, tenantId?: string | null) {
  return useQuery({
    queryKey: queryKeys.run(runId, tenantId),
    queryFn: () => fetchRun(runId),
    enabled: Boolean(runId),
  });
}

export function useRunHosts(runId: string, tenantId?: string | null) {
  return useQuery({
    queryKey: queryKeys.runHosts(runId, tenantId),
    queryFn: () => fetchHosts(runId),
    enabled: Boolean(runId),
  });
}

export function useRunPorts(runId: string, tenantId?: string | null) {
  return useQuery({
    queryKey: queryKeys.runPorts(runId, tenantId),
    queryFn: () => fetchPorts(runId),
    enabled: Boolean(runId),
  });
}

/** Operator-only. `enabled` must be false for a viewer so the manifest is never fetched. */
export function useRunScreenshots(runId: string, enabled: boolean, tenantId?: string | null) {
  return useQuery({
    queryKey: queryKeys.runScreenshots(runId, tenantId),
    queryFn: () => fetchScreenshots(runId),
    enabled: Boolean(runId) && enabled,
  });
}

export function useRunVulns(
  runId: string,
  filters?: { host?: string | null; port?: string | null; limit?: number },
  tenantId?: string | null,
) {
  const host = filters?.host ?? null;
  const port = filters?.port ?? null;
  const limit = filters?.limit ?? VULN_FETCH_LIMIT;
  return useQuery({
    queryKey: queryKeys.runVulns(runId, { host, port }, tenantId),
    queryFn: () => fetchVulns(runId, limit, host, port),
    enabled: Boolean(runId),
    staleTime: 30_000,
  });
}
