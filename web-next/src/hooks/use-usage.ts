"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchFleetUsage,
  fetchUsage,
  updateTenantQuota,
  type TenantQuotaUpdate,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useUsage(historyMonths = 12) {
  return useQuery({
    queryKey: queryKeys.usage(historyMonths),
    queryFn: () => fetchUsage(historyMonths),
  });
}

/** The fleet view is platform-admin only and 403s for anyone else, so the page
 * passes its own entitlement in rather than firing the request to find out. */
export function useFleetUsage(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.fleetUsage,
    queryFn: fetchFleetUsage,
    enabled,
  });
}

export function useUpdateTenantQuota() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tenantId, quota }: { tenantId: string; quota: TenantQuotaUpdate }) =>
      updateTenantQuota(tenantId, quota),
    onSuccess: async (quota) => {
      toast.success("Quota saved", { description: quota.tenant_id });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.fleetUsage }),
        queryClient.invalidateQueries({ queryKey: queryKeys.tenantQuota(quota.tenant_id) }),
        queryClient.invalidateQueries({ queryKey: ["usage"] }),
      ]);
    },
    onError: (err) => {
      toast.error("Failed to save quota", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
