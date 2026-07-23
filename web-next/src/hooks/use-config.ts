"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { fetchConfig, updateConfig } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useConfig() {
  return useQuery({
    queryKey: queryKeys.config,
    queryFn: fetchConfig,
  });
}

export function useUpdateConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (overrides: Record<string, unknown>) => updateConfig(overrides),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.config, data);
      toast.success("Configuration saved");
    },
    onError: (err) => {
      toast.error("Save failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
