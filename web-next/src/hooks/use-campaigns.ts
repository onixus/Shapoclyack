"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import type { PageParams, VulnerabilityListFilters } from "@/lib/api";
import {
  campaignsApi,
  findingFilterParams,
  problemsApi,
  type Campaign,
  type CampaignCategory,
  type CampaignCreateBody,
  type CampaignSelection,
  type CampaignStatus,
} from "@/lib/campaigns";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";
import { useSubmissionKey } from "@/hooks/use-bulk-actions";

export function useProblems(filters: VulnerabilityListFilters, page?: PageParams, enabled = true) {
  return useQuery({
    queryKey: queryKeys.problemsPage(findingFilterParams(filters), page),
    queryFn: () => problemsApi.list(filters, page),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
    enabled,
  });
}

/**
 * Why a drill-down shows a different number than the row it came from: the
 * server compares the row's count with the current one and says how many of
 * the findings changed after the list was loaded. Asked only when the row's
 * count is known (a bare `?problem=` deep link has none).
 */
export function useProblemDrift(
  drill: { key: string; instances: number; asOf: string } | null,
  filters: VulnerabilityListFilters,
  enabled = true,
) {
  const known = Boolean(drill && drill.instances >= 0 && drill.asOf);
  return useQuery({
    queryKey: ["vulnerabilities", "problem-drift", drill?.key ?? "", drill?.instances ?? -1, drill?.asOf ?? "", findingFilterParams(filters)],
    queryFn: () =>
      problemsApi.instances(drill!.key, filters, { limit: 1 }, {
        as_of: drill!.asOf,
        expected_instances: drill!.instances,
      }),
    enabled: enabled && known,
  });
}

export function useCampaigns(page?: PageParams, status?: CampaignStatus) {
  return useQuery({
    queryKey: queryKeys.campaignsPage(page, status),
    queryFn: () => campaignsApi.list(page, status),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useCampaign(id: string | null) {
  return useQuery({
    queryKey: queryKeys.campaign(id ?? ""),
    queryFn: () => campaignsApi.get(id as string),
    enabled: Boolean(id),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useCampaignMembers(
  id: string | null,
  page?: PageParams,
  options?: { status?: "included" | "excluded"; category?: CampaignCategory | "" },
) {
  return useQuery({
    queryKey: queryKeys.campaignMembers(id ?? "", page, options),
    queryFn: () => campaignsApi.members(id as string, page, options),
    enabled: Boolean(id),
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

export function useCampaignEvents(id: string | null, page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.campaignEvents(id ?? "", page),
    queryFn: () => campaignsApi.events(id as string, page),
    enabled: Boolean(id),
  });
}

/** The exact composition a selection would freeze now. A mutation rather than a
 * query: it is asked for on purpose, with the selection the operator holds. */
export function useCampaignPreview() {
  return useMutation({
    mutationFn: (selection: CampaignSelection) => campaignsApi.preview(selection),
  });
}

/**
 * Creating a campaign is the request most worth never doubling, so the
 * `Idempotency-Key` is held against the body it names (as the bulk verbs do):
 * the same click retried carries the same key, the next different campaign gets
 * a new one.
 */
export function useCreateCampaign(onCreated?: (campaign: Campaign) => void) {
  const queryClient = useQueryClient();
  const key = useSubmissionKey();
  return useMutation({
    mutationFn: (body: CampaignCreateBody) => campaignsApi.create(body, key.forBody(body)),
    onSuccess: (campaign) => {
      key.settled();
      toast.success(
        campaign.replayed
          ? `Campaign “${campaign.name}” already existed (replayed)`
          : `Campaign “${campaign.name}” created with ${campaign.snapshot_size} findings`,
      );
      void queryClient.invalidateQueries({ queryKey: queryKeys.campaigns });
      onCreated?.(campaign);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

function useCampaignInvalidation() {
  const queryClient = useQueryClient();
  return (id: string) => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.campaign(id) });
    void queryClient.invalidateQueries({ queryKey: queryKeys.campaigns });
  };
}

export function useUpdateCampaign(id: string) {
  const refresh = useCampaignInvalidation();
  return useMutation({
    mutationFn: (body: Parameters<typeof campaignsApi.update>[1]) => campaignsApi.update(id, body),
    onSuccess: () => {
      toast.success("Campaign updated");
      refresh(id);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

export function useAddCampaignMembers(id: string) {
  const refresh = useCampaignInvalidation();
  return useMutation({
    mutationFn: (args: { selection: CampaignSelection; reason: string }) =>
      campaignsApi.addMembers(id, args.selection, args.reason),
    onSuccess: (report) => {
      const rejected = report.results.filter((r) => !["added", "readded"].includes(r.outcome)).length;
      toast.success(
        `${(report.added ?? 0) + (report.readded ?? 0)} added` +
          (rejected ? `, ${rejected} not added` : ""),
      );
      refresh(id);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

export function useExcludeCampaignMembers(id: string) {
  const refresh = useCampaignInvalidation();
  return useMutation({
    mutationFn: (args: { vulnIds: string[]; reason: string }) =>
      campaignsApi.excludeMembers(id, args.vulnIds, args.reason),
    onSuccess: (report) => {
      toast.success(`${report.excluded ?? 0} excluded`);
      refresh(id);
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

/** Verification report per finding: the toast only counts, the dialog lists. */
export function useVerifyCampaign(id: string) {
  const queryClient = useQueryClient();
  const refresh = useCampaignInvalidation();
  const key = useSubmissionKey();
  return useMutation({
    mutationFn: (vulnIds?: string[]) => campaignsApi.verify(id, vulnIds, key.forBody({ id, vulnIds })),
    onSuccess: (report) => {
      key.settled();
      const dispatched = report.summary.dispatched ?? 0;
      toast.success(`${dispatched} verification${dispatched === 1 ? "" : "s"} dispatched`);
      refresh(id);
      void queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
    },
    onError: (error: Error) => toast.error(error.message),
  });
}

export function useCampaignStatusChange(id: string) {
  const refresh = useCampaignInvalidation();
  return useMutation({
    mutationFn: (args: { action: "cancel" | "resume"; reason: string }) =>
      args.action === "cancel"
        ? campaignsApi.cancel(id, args.reason)
        : campaignsApi.resume(id, args.reason),
    onSuccess: () => refresh(id),
    onError: (error: Error) => toast.error(error.message),
  });
}
