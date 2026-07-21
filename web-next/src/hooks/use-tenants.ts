"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { createProvisioningKey, createTenant, fetchTenants } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useTenants(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.tenants,
    queryFn: fetchTenants,
    enabled,
  });
}

/** Creates a tenant, then immediately issues a one-time provisioning key for it. */
export function useCreateTenantWithKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (tenantName: string) => {
      const tenant = await createTenant({ name: tenantName });
      const key = await createProvisioningKey(tenant.tenant_id, "web-next");
      return { tenant, key };
    },
    onSuccess: async ({ tenant }) => {
      toast.success("Tenant created", { description: tenant.tenant_id });
      await queryClient.invalidateQueries({ queryKey: queryKeys.tenants });
    },
    onError: (err) => {
      toast.error("Failed to create tenant", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
