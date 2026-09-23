"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  cancelJob,
  discardJobPublication,
  fetchJob,
  fetchJobPublications,
  fetchJobSummary,
  fetchJobs,
  requeueJobPublication,
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
      // `cancelling` keeps polling too: it is the state a drawer is most
      // likely to be left open on, waiting for the agent to confirm (#360).
      return status === "queued" ||
        status === "claimed" ||
        status === "running" ||
        status === "cancelling"
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
      // Two different things happened, and saying "cancelled" for both would
      // promise a stop the API has not been told happened yet (#360).
      if (job.status === "cancelling") {
        toast.success("Stopping the scan", {
          description: `Job ${job.job_id} — waiting for the agent to confirm`,
        });
      } else {
        toast.success("Job cancelled", { description: `Job ${job.job_id}` });
      }
      await queryClient.invalidateQueries({ queryKey: queryKeys.jobs });
    },
    onError: (err) => {
      toast.error("Could not cancel job", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

/**
 * What a finished job's accepted run still owes before it is visible (#425).
 * Asked only of a job that has ended — a publication row is written with the
 * terminal status — and polled while a row is still pending, so a drawer left
 * open watches a requeue land, or while a dead row is still held by a running
 * attempt, so its buttons come on when the API would accept them.
 */
export function useJobPublications(jobId: string | null, enabled = true) {
  return useQuery({
    queryKey: queryKeys.jobPublications(jobId ?? ""),
    queryFn: () => fetchJobPublications(jobId ?? ""),
    enabled: enabled && Boolean(jobId),
    refetchInterval: (query) =>
      query.state.data?.some((row) => row.status === "pending" || !row.actionable)
        ? POLL_INTERVALS.jobs
        : false,
  });
}

export function useRequeuePublication(jobId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (publicationId: string) => requeueJobPublication(jobId, publicationId),
    onSuccess: async () => {
      toast.success("Publication requeued", {
        description: "The next reconciler tick publishes it.",
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.jobs });
    },
    onError: (err) => {
      toast.error("Could not requeue the publication", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDiscardPublication(jobId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (publicationId: string) => discardJobPublication(jobId, publicationId),
    onSuccess: async () => {
      toast.success("Publication discarded", {
        description: "The run stays unpublished; its extracted tree is kept for a day.",
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.jobs });
    },
    onError: (err) => {
      toast.error("Could not discard the publication", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
