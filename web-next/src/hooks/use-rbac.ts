"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createTenantRole,
  deleteTenantRole,
  fetchPermissionCatalogue,
  fetchRoleCatalogue,
  updateTenantRole,
  type TenantRoleBody,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/**
 * The roles that can be granted in one tenant (#318).
 *
 * The console used to keep its own list of three — in `users/page.tsx`, in
 * `service-tokens-panel.tsx` and in the `Role` type both read — so the five
 * roles #318 added were grantable over the API and invisible in the UI that
 * exists to grant them. This is the one place the list comes from now,
 * including the roles the tenant defined for itself.
 *
 * Needs `tenant.member.read`, so `enabled` is the caller's answer to "may
 * this principal see the membership screen at all".
 */
export function useRoleCatalogue(tenantId: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.roleCatalogue(tenantId),
    queryFn: () => fetchRoleCatalogue(tenantId),
    enabled: enabled && Boolean(tenantId),
    // Mostly reference data — but a tenant's own roles change from this very
    // console, and the mutations below invalidate it when they do.
    staleTime: 5 * 60 * 1000,
  });
}

/** Every named authority, with the sentence the catalogue publishes for it. */
export function usePermissionCatalogue(enabled = true) {
  return useQuery({
    queryKey: queryKeys.permissionCatalogue,
    queryFn: fetchPermissionCatalogue,
    enabled,
    staleTime: 5 * 60 * 1000,
  });
}

/** Both lists a role change can move: the catalogue (the role itself, and its
 * member count) and the member list (a rename or a reassignment rewrites the
 * role every holder shows). */
async function invalidateRoleViews(
  queryClient: ReturnType<typeof useQueryClient>,
  tenantId: string,
) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: queryKeys.roleCatalogue(tenantId) }),
    queryClient.invalidateQueries({ queryKey: queryKeys.tenantMembers(tenantId) }),
  ]);
}

export function useCreateTenantRole(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: TenantRoleBody) => createTenantRole(tenantId, body),
    onSuccess: async (role) => {
      toast.success("Role created", { description: `${role.role_id} in ${tenantId}` });
      await invalidateRoleViews(queryClient, tenantId);
    },
    onError: (err) => {
      toast.error("Failed to create the role", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useUpdateTenantRole(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ roleId, body }: { roleId: string; body: Partial<TenantRoleBody> }) =>
      updateTenantRole(tenantId, roleId, body),
    onSuccess: async (role) => {
      toast.success("Role updated", { description: role.role_id });
      await invalidateRoleViews(queryClient, tenantId);
    },
    onError: (err) => {
      toast.error("Failed to update the role", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteTenantRole(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ roleId, reassignTo }: { roleId: string; reassignTo?: string }) =>
      deleteTenantRole(tenantId, roleId, reassignTo),
    onSuccess: async (result) => {
      toast.success("Role deleted", {
        description: result.reassigned_to
          ? `${result.role_id} · ${result.memberships_reassigned} member(s) now ${result.reassigned_to}`
          : result.role_id,
      });
      await invalidateRoleViews(queryClient, tenantId);
    },
    onError: (err) => {
      toast.error("Failed to delete the role", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
