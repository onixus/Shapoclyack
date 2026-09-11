"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchPermissionCatalogue, fetchRoleCatalogue } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/**
 * The roles that can be granted in one tenant (#318).
 *
 * The console used to keep its own list of three — in `users/page.tsx`, in
 * `service-tokens-panel.tsx` and in the `Role` type both read — so the five
 * roles #318 added were grantable over the API and invisible in the UI that
 * exists to grant them. This is the one place the list comes from now.
 *
 * Needs `tenant.member.read`, so `enabled` is the caller's answer to "may
 * this principal see the membership screen at all".
 */
export function useRoleCatalogue(tenantId: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.roleCatalogue(tenantId),
    queryFn: () => fetchRoleCatalogue(tenantId),
    enabled: enabled && Boolean(tenantId),
    // Reference data: it changes when the platform's vocabulary does, which
    // is not within a session.
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
