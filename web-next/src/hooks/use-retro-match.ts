"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchAssetServices, fetchRetroMatchStatus, refreshRetroMatch } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

/** The retro matcher's dataset and the tenant's queue (docs/retro-cve-matching.md).
 *
 * Polled at the vulnerability cadence: the refresh only queues, and the queue
 * draining in the background is the thing an operator who pressed the button
 * is waiting to see. */
export function useRetroMatchStatus(enabled = true) {
  return useQuery({
    queryKey: queryKeys.retroMatchStatus,
    queryFn: fetchRetroMatchStatus,
    enabled,
    refetchInterval: POLL_INTERVALS.vulnerabilities,
  });
}

/** Put every stored listener of the tenant back on the retro queue. Operator. */
export function useRefreshRetroMatch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: refreshRetroMatch,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.retroMatchStatus }),
  });
}

/** Listeners scans fingerprinted on one asset, with the retro verdict on each. */
export function useAssetServices(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.assetServices(assetId ?? "", tenantId),
    queryFn: () => fetchAssetServices(assetId!, tenantId),
    enabled: Boolean(assetId),
  });
}
