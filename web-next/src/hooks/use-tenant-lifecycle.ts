"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  approveTenantDeletion,
  cancelTenantDeletion,
  fetchTenantDeletions,
  fetchTenantLifecycle,
  requestTenantDeletion,
  resumeTenant,
  retryTenantDeletion,
  suspendTenant,
  type TenantLifecycle,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** One tenant's status, hold and deletion (#325). Platform admins only; while a
 * purge runs the page polls, so each store's progress shows as it happens. */
export function useTenantLifecycle(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.tenantLifecycle(tenantId),
    queryFn: () => fetchTenantLifecycle(tenantId),
    enabled: enabled && Boolean(tenantId),
    refetchInterval: (query) => (query.state.data?.status === "deleting" ? 5000 : false),
  });
}

/** The last hundred deletions, tombstones included (#325). Platform admins only. */
export function useTenantDeletions(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.tenantDeletions,
    queryFn: () => fetchTenantDeletions({ limit: 100 }),
    enabled,
  });
}

/** Every lifecycle change answers with the new document; it replaces the cached
 * one, and the tenant listing is refreshed because its status column moved. */
function useLifecycleMutation<T>(
  tenantId: string,
  run: (value: T) => Promise<TenantLifecycle>,
  done: string,
  failed: string,
) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: run,
    onSuccess: async (data) => {
      queryClient.setQueryData(queryKeys.tenantLifecycle(tenantId), data);
      toast.success(done, { description: tenantId });
      await queryClient.invalidateQueries({ queryKey: queryKeys.tenants });
    },
    onError: (err: unknown) =>
      toast.error(failed, { description: err instanceof Error ? err.message : undefined }),
  });
}

export function useSuspendTenant(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    (body: { reason: string; revoke_credentials: boolean }) => suspendTenant(tenantId, body),
    "Tenant suspended",
    "Failed to suspend the tenant",
  );
}

export function useResumeTenant(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    () => resumeTenant(tenantId),
    "Tenant resumed",
    "Failed to resume the tenant",
  );
}

export function useRequestTenantDeletion(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    (body: { confirm: string; reason: string }) => requestTenantDeletion(tenantId, body),
    "Deletion requested",
    "Failed to request the deletion",
  );
}

export function useCancelTenantDeletion(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    () => cancelTenantDeletion(tenantId),
    "Deletion cancelled",
    "Failed to cancel the deletion",
  );
}

export function useApproveTenantDeletion(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    (confirm: string) => approveTenantDeletion(tenantId, confirm),
    "Purge started",
    "Failed to approve the purge",
  );
}

export function useRetryTenantDeletion(tenantId: string) {
  return useLifecycleMutation(
    tenantId,
    () => retryTenantDeletion(tenantId),
    "Purge retried",
    "Failed to retry the purge",
  );
}
