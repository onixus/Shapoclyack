"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchPromotedDomains,
  fetchScanScope,
  replaceScanScope,
  type ScanScopeEffect,
  type ScanScopeEntry,
  type ScanScopeEntryInput,
  type ScanScopeKind,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** A tenant's approved scanning scope (#226). Admin-only on the API, so the
 * caller passes its own entitlement in rather than firing the request to
 * find out it is a 403. An empty list is an answer — the tenant scans
 * nothing — not a missing one, so it is rendered, not treated as "loading". */
export function useScanScope(tenantId: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.scanScope(tenantId),
    queryFn: () => fetchScanScope(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

/** Related domains the tenant's operators promoted underneath the scope
 * (org_profile M4). Read-only cross-check next to the editor. */
export function usePromotedDomains(tenantId: string, enabled = true) {
  return useQuery({
    queryKey: queryKeys.promotedDomains(tenantId),
    queryFn: () => fetchPromotedDomains(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

/** What "the same scope" means to the editor: the four fields a `PUT` carries,
 * in order, trimmed the way they are sent. The approval stamp is deliberately
 * out of it — a scope re-approved by somebody else, entry for entry, is not a
 * scope that changed under the admin editing it. */
export function scanScopeSignature(
  entries: readonly { effect: ScanScopeEffect; kind: ScanScopeKind; value: string; note?: string }[],
) {
  return JSON.stringify(
    entries.map((entry) => ({
      effect: entry.effect,
      kind: entry.kind,
      value: entry.value.trim(),
      note: (entry.note ?? "").trim(),
    })),
  );
}

/** Raised instead of sending a `PUT` that would overwrite somebody else's
 * approval. Carries the scope as it is now, so the editor can be reseeded from
 * the thing the admin has to look at. */
export class ScanScopeConflict extends Error {
  constructor(readonly current: ScanScopeEntry[]) {
    super("Scan scope changed since you opened it — review the new entries and try again");
    this.name = "ScanScopeConflict";
  }
}

/** Approves the scope, replacing whatever the tenant had. The server is the
 * authority on the entries: its 422 detail names the entry it refused, so it
 * is carried into the toast verbatim rather than replaced with a generic
 * failure the admin would have to reproduce over curl to understand.
 *
 * `baseline` is the signature of the scope the editor was seeded from, and it
 * is re-read before the write: the endpoint replaces the whole list and offers
 * no ETag, so two admins with the dialog open would otherwise silently undo
 * each other — the second `PUT` wins with a list that never contained the
 * first one's entries. A scope that moved in between is refused here rather
 * than overwritten, and the fresh one is put in the cache for the editor to
 * reseed from.
 */
export function useReplaceScanScope(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      entries,
      baseline,
    }: {
      entries: ScanScopeEntryInput[];
      baseline: string;
    }) => {
      const current = await fetchScanScope(tenantId);
      if (scanScopeSignature(current) !== baseline) {
        throw new ScanScopeConflict(current);
      }
      return replaceScanScope(tenantId, entries);
    },
    onSuccess: (entries) => {
      toast.success("Scan scope approved", {
        description:
          entries.length === 0
            ? `${tenantId} can no longer scan anything`
            : `${entries.length} ${entries.length === 1 ? "entry" : "entries"} for ${tenantId}`,
      });
      // What the server stored, not a refetch of it: the response is already
      // the authoritative list, and it may well be equal to the one the editor
      // started from — the server normalises values and collapses duplicates.
      queryClient.setQueryData(queryKeys.scanScope(tenantId), entries);
    },
    onError: (err) => {
      if (err instanceof ScanScopeConflict) {
        queryClient.setQueryData(queryKeys.scanScope(tenantId), err.current);
      }
      toast.error("Failed to approve scan scope", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
