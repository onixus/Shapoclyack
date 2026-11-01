"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useT } from "@/lib/i18n";
import { systemText } from "@/lib/system-presentation";
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
  const t = useT();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (overrides: Record<string, unknown>) => updateConfig(overrides),
    onSuccess: (data) => {
      queryClient.setQueryData(queryKeys.config, data);
      toast.success(systemText(t.locale, "Configuration saved"));
    },
    onError: (err) => {
      toast.error(systemText(t.locale, "Save failed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
