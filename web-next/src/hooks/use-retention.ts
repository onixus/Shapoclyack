"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  downloadUserDataExport,
  eraseUser,
  fetchLegalHolds,
  fetchRetentionPolicy,
  placeLegalHold,
  releaseLegalHold,
  resetRetentionPolicy,
  updateRetentionPolicy,
  type RetentionPolicyUpdate,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

function failed(title: string) {
  return (err: unknown) =>
    toast.error(title, { description: err instanceof Error ? err.message : undefined });
}

/** One tenant's windows and hold (#332). Gated by the caller on
 * `tenant.retention.read`, which the API also checks. */
export function useRetentionPolicy(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.retention(tenantId),
    queryFn: () => fetchRetentionPolicy(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

/** The register of holds across tenants. Platform admins only; the caller
 * gates on that, and the API refuses anybody else. */
export function useLegalHolds(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.legalHolds,
    queryFn: fetchLegalHolds,
    enabled,
  });
}

/** Every mutation here answers with, or changes, the same document, so each
 * one refreshes it rather than patching the cache: the server decides
 * `effective_days` (an override clamped into the current bounds), and the
 * page should show its answer. A hold also changes the register. */
function useRefresh(tenantId: string) {
  const queryClient = useQueryClient();
  return () =>
    Promise.all([
      queryClient.invalidateQueries({ queryKey: queryKeys.retention(tenantId) }),
      queryClient.invalidateQueries({ queryKey: queryKeys.legalHolds }),
    ]);
}

export function useUpdateRetentionPolicy(tenantId: string) {
  const refresh = useRefresh(tenantId);
  return useMutation({
    mutationFn: (body: RetentionPolicyUpdate) => updateRetentionPolicy(tenantId, body),
    onSuccess: async () => {
      toast.success("Retention windows saved", { description: tenantId });
      await refresh();
    },
    onError: failed("Failed to save retention windows"),
  });
}

export function useResetRetentionPolicy(tenantId: string) {
  const refresh = useRefresh(tenantId);
  return useMutation({
    mutationFn: () => resetRetentionPolicy(tenantId),
    onSuccess: async () => {
      toast.success("Retention reset to the platform defaults", { description: tenantId });
      await refresh();
    },
    onError: failed("Failed to reset retention windows"),
  });
}

export function usePlaceLegalHold(tenantId: string) {
  const refresh = useRefresh(tenantId);
  return useMutation({
    mutationFn: (reason: string) => placeLegalHold(tenantId, reason),
    onSuccess: async () => {
      toast.success("Legal hold placed", { description: tenantId });
      await refresh();
    },
    onError: failed("Failed to place the legal hold"),
  });
}

export function useReleaseLegalHold(tenantId: string) {
  const refresh = useRefresh(tenantId);
  return useMutation({
    mutationFn: () => releaseLegalHold(tenantId),
    onSuccess: async () => {
      toast.success("Legal hold released", { description: tenantId });
      await refresh();
    },
    onError: failed("Failed to release the legal hold"),
  });
}

export function useExportUserData() {
  return useMutation({
    mutationFn: (username: string) => downloadUserDataExport(username),
    onError: failed("Failed to export the account's data"),
  });
}

export function useEraseUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (username: string) => eraseUser(username),
    onSuccess: async (result) => {
      toast.success(
        result.already_erased ? "Account was already erased" : "Account erased",
        { description: result.username },
      );
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: failed("Failed to erase the account"),
  });
}
