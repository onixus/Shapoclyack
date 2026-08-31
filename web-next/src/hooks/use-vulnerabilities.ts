"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  assignVulnerability,
  clearVulnerabilityException,
  clearVulnerabilityTicket,
  commentOnVulnerability,
  fetchRiskHistory,
  fetchTrackedVulnerability,
  fetchTrackedVulnerabilities,
  fetchVulnerabilityActivity,
  fetchVulnerabilityEvents,
  fetchVulnerabilitySummary,
  setVulnerabilityException,
  setVulnerabilityTicket,
  syncVulnTicket,
  transitionVulnerability,
  triggerRiskSnapshot,
  triggerVulnVerification,
  type PageParams,
  type TrackedVulnerability,
  type VulnerabilityAssignBody,
  type VulnerabilityExceptionBody,
  type VulnerabilityListFilters,
  type VulnerabilityTicketBody,
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
    unassigned: Boolean(filters.unassigned),
    sla: filters.sla ?? "",
    stale_days: filters.stale_days ?? null,
    in_kev: Boolean(filters.in_kev),
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

export function useVulnerabilityActivity(page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.vulnerabilityActivity(page),
    queryFn: () => fetchVulnerabilityActivity(page),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useRiskHistory(params?: {
  since?: string;
  until?: string;
  limit?: number;
}) {
  return useQuery({
    queryKey: queryKeys.riskHistory(params),
    queryFn: () => fetchRiskHistory(params),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useTriggerRiskSnapshot() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: triggerRiskSnapshot,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["vulnerabilities", "risk-history"] });
      toast.success("Risk snapshot captured");
    },
    onError: (error: Error) => {
      toast.error(error.message || "Failed to capture risk snapshot");
    },
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

export function useCommentOnVulnerability(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (note: string) => commentOnVulnerability(vulnId, note),
    onSuccess: (updated) => {
      onVulnWriteSuccess(queryClient, updated, "Comment added");
      void queryClient.invalidateQueries({ queryKey: ["vulnerabilities", "events"] });
    },
    onError: (err) => {
      toast.error("Could not add comment", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetVulnerabilityTicket(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: VulnerabilityTicketBody) => setVulnerabilityTicket(vulnId, body),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, "Ticket linked"),
    onError: (err) => {
      toast.error("Could not link ticket", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useClearVulnerabilityTicket(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => clearVulnerabilityTicket(vulnId),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, "Ticket unlinked"),
    onError: (err) => {
      toast.error("Could not unlink ticket", {
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

export function useTriggerVulnVerification(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => triggerVulnVerification(vulnId),
    onSuccess: (updated) =>
      onVulnWriteSuccess(queryClient, updated, "Verification re-scan dispatched"),
    onError: (err) => {
      toast.error("Could not start verification", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSyncVulnTicket(vulnId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => syncVulnTicket(vulnId),
    onSuccess: (updated) => onVulnWriteSuccess(queryClient, updated, "Ticket synchronised"),
    onError: (err) => {
      toast.error("Could not sync ticket", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
