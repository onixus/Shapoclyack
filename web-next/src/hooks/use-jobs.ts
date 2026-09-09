"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  cancelJob,
  fetchJob,
  fetchJobSummary,
  fetchJobs,
  startScan,
  type PageParams,
  type ScanListFilters,
  type StartScanBody,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

/**
 * How many jobs are moving right now, from `GET /api/jobs/summary` — one
 * grouped count. Not derived from the paged list: that list is sorted by
 * `started_at` NULLS LAST, so on any installation with more history than one
 * page the queued jobs (no start time yet) are always past the window.
 */
export function useJobCounts(
  enabled: boolean,
  filters?: ScanListFilters,
  refetchInterval: number = POLL_INTERVALS.dashboard,
) {
  const query = useQuery({
    queryKey: queryKeys.jobSummary,
    queryFn: fetchJobSummary,
    refetchInterval,
    enabled,
  });
  const surface = filters?.surface;
  const scoped = surface ? query.data?.by_surface?.[surface] : query.data;
  return {
    isLoading: query.isLoading,
    running: scoped?.running ?? 0,
    queued: scoped?.queued ?? 0,
    summary: query.data,
  };
}

export function useJobs(enabled: boolean, page?: PageParams, filters?: ScanListFilters) {
  return useQuery({
    queryKey: queryKeys.jobsPage(page, filters),
    queryFn: () => fetchJobs(page, filters),
    refetchInterval: POLL_INTERVALS.jobs,
    enabled,
  });
}

/** One job, polled while it is still moving so a drawer left open follows it. */
export function useJob(jobId: string | null, enabled = true) {
  return useQuery({
    queryKey: queryKeys.job(jobId ?? ""),
    queryFn: () => fetchJob(jobId ?? ""),
    enabled: enabled && Boolean(jobId),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "queued" || status === "claimed" || status === "running"
        ? POLL_INTERVALS.jobs
        : false;
    },
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ body, idempotencyKey }: { body: StartScanBody; idempotencyKey?: string }) =>
      startScan(body, { idempotencyKey }),
    onSuccess: async (job) => {
      toast.success("Scan job queued", {
        description: job.job_id ? `Job ${job.job_id}` : undefined,
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.jobs });
    },
    onError: (err) => {
      toast.error("Failed to start scan", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useCancelJob() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) => cancelJob(jobId),
    onSuccess: async (job) => {
      toast.success("Job cancelled", { description: `Job ${job.job_id}` });
      await queryClient.invalidateQueries({ queryKey: queryKeys.jobs });
    },
    onError: (err) => {
      toast.error("Could not cancel job", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
