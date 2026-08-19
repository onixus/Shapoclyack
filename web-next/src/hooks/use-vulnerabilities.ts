"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  assignVulnerability,
  clearVulnerabilityException,
  fetchTrackedVulnerability,
  fetchTrackedVulnerabilities,
  fetchVulnerabilityEvents,
  fetchVulnerabilitySummary,
  setVulnerabilityException,
  transitionVulnerability,
  type PageParams,
  type TrackedVulnerability,
  type VulnerabilityAssignBody,
  type VulnerabilityExceptionBody,
  type VulnerabilityListFilters,
  type VulnerabilityTransitionBody,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

function filtersKey(filters: VulnerabilityListFilters): Record<string, unknown> {
  return {
    state: filters.state ?? "",
    open_only: Boolean(filters.open_only),
    severity: filters.severity ?? "",
    asset_id: filters.asset_id ?? "",
    assignee: filters.assignee ?? "",
    sla: filters.sla ?? "",
    stale_days: filters.stale_days ?? null,
  };
}

export function useTrackedVulnerabilities(
  filters: VulnerabilityListFilters,
  page?: PageParams,
  enabled = true,
) {
  return useQuery({
    queryKey: queryKeys.vulnerabilitiesPage(filtersKey(filters), page),
    queryFn: () => fetchTrackedVulnerabilities(filters, page),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
    enabled,
  });
}

export function useVulnerabilitySummary() {
  return useQuery({
    queryKey: queryKeys.vulnerabilitySummary,
    queryFn: fetchVulnerabilitySummary,
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useTrackedVulnerability(vulnId: string | null) {
  return useQuery({
    queryKey: queryKeys.vulnerability(vulnId ?? ""),
    queryFn: () => fetchTrackedVulnerability(vulnId!),
    enabled: Boolean(vulnId),
  });
}

export function useVulnerabilityEvents(vulnId: string | null, page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.vulnerabilityEvents(vulnId ?? "", page),
    queryFn: () => fetchVulnerabilityEvents(vulnId!, page),
    enabled: Boolean(vulnId),
  });
}

function invalidateVulnQueries(queryClient: ReturnType<typeof useQueryClient>, vulnId: string) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities }),
    queryClient.invalidateQueries({ queryKey: queryKeys.vulnerability(vulnId) }),
    queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilitySummary }),
  ]);
}

function onVulnWriteSuccess(
  queryClient: ReturnType<typeof useQueryClient>,
  updated: TrackedVulnerability,
  message: string,
) {
  queryClient.setQueryData(queryKeys.vulnerability(updated.vuln_id), updated);
  void invalidateVulnQueries(queryClient, updated.vuln_id);
  toast.success(message);
}

export function useTransitionVulnerability(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VulnerabilityTransitionBody) => transitionVulnerability(vulnId, body),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, `Moved to ${updated.state}`),
    onError: (err) => {
      toast.error("Transition failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useAssignVulnerability(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VulnerabilityAssignBody) => assignVulnerability(vulnId, body),
    onSuccess: (updated) =>
      onVulnWriteSuccess(
        queryClient,
        updated,
        updated.assignee ? `Assigned to ${updated.assignee}` : "Unassigned",
      ),
    onError: (err) => {
      toast.error("Assignment failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetVulnerabilityException(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VulnerabilityExceptionBody) => setVulnerabilityException(vulnId, body),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, "Risk accepted"),
    onError: (err) => {
      toast.error("Could not accept risk", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useClearVulnerabilityException(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => clearVulnerabilityException(vulnId),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, "Acceptance withdrawn"),
    onError: (err) => {
      toast.error("Could not withdraw acceptance", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
