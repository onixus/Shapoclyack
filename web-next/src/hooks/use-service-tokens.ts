"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createServiceToken,
  fetchServiceTokens,
  revokeServiceToken,
  type Role,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useServiceTokens(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.serviceTokens(tenantId),
    queryFn: () => fetchServiceTokens(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

export function useCreateServiceToken(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: {
      name: string;
      scopes: string[];
      role: Role;
      expires_in_days?: number;
    }) => createServiceToken(tenantId, body),
    onSuccess: async () => {
      // Deliberately no toast carrying the token: the plaintext belongs in the
      // one panel that asks the admin to copy it, not in a notification that
      // lingers on screen and in a screenshot.
      await queryClient.invalidateQueries({ queryKey: queryKeys.serviceTokens(tenantId) });
    },
    onError: (err) => {
      toast.error("Failed to create service token", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useRevokeServiceToken(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (tokenId: string) => revokeServiceToken(tenantId, tokenId),
    onSuccess: async (token) => {
      toast.success("Service token revoked", { description: token.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.serviceTokens(tenantId) });
    },
    onError: (err) => {
      toast.error("Failed to revoke service token", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
