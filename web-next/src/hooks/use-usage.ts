"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  deleteTenantQuota,
  fetchFleetUsage,
  fetchTenantQuota,
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

/** The quota row stored for one tenant — which is not the same thing as the
 * limits in force for it: a tenant with no row of its own reports
 * `quota_source: "default"` and inherited numbers. The editor prefills from
 * this, so it can tell "inherits the platform default" from "unlimited here".
 * Null tenant means no editor is open, and then nothing is fetched. */
export function useTenantQuota(tenantId: string | null) {
  return useQuery({
    queryKey: queryKeys.tenantQuota(tenantId ?? ""),
    queryFn: () => fetchTenantQuota(tenantId as string),
    enabled: tenantId !== null,
  });
}

/** Deletes the tenant's own quota row, putting it back on the platform
 * default. Both usage views quote the limits in force, so both are refetched. */
export function useDeleteTenantQuota() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tenantId: string) => deleteTenantQuota(tenantId),
    onSuccess: async (_data, tenantId) => {
      toast.success("Quota reset to the platform default", { description: tenantId });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.fleetUsage }),
        queryClient.invalidateQueries({ queryKey: queryKeys.tenantQuota(tenantId) }),
        queryClient.invalidateQueries({ queryKey: ["usage"] }),
      ]);
    },
    onError: (err) => {
      toast.error("Failed to reset quota", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
