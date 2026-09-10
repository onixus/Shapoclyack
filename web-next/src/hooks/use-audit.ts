"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  downloadAuditExport,
  fetchAuditEvents,
  type AuditFilters,
  type PageParams,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** The administrative audit trail (#327). Admin-only on the API — a tenant
 * admin sees their tenant, a platform admin every tenant — so the caller passes
 * its own entitlement in rather than firing the request to find out it is a
 * 403. */
export function useAuditEvents(enabled: boolean, page?: PageParams, filters?: AuditFilters) {
  return useQuery({
    queryKey: queryKeys.auditEvents(page, filters as Record<string, string | undefined>),
    queryFn: () => fetchAuditEvents(page, filters),
    enabled,
  });
}

/** Export the *whole* filtered trail, not the page on screen. A mutation rather
 * than a query because it has an effect — a file lands in the operator's
 * downloads — and because nothing should cache a year of audit rows in the
 * browser. */
export function useAuditExport(filters?: AuditFilters) {
  return useMutation({
    mutationFn: (format: "csv" | "ndjson") => downloadAuditExport(format, filters),
    onError: (err) => {
      toast.error("Failed to export the audit trail", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
