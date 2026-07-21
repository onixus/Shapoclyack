"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { fetchJobs, startScan } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useJobs(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.jobs,
    queryFn: fetchJobs,
    refetchInterval: POLL_INTERVALS.jobs,
    enabled,
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: startScan,
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
