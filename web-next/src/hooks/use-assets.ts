"use client";

import { useQuery } from "@tanstack/react-query";
import { fetchAsset, fetchAssets, type AssetStatus } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useAssets(filters: { status: AssetStatus | "" }) {
  return useQuery({
    queryKey: queryKeys.assets({ status: filters.status }),
    queryFn: () => fetchAssets({ status: filters.status }),
    refetchInterval: POLL_INTERVALS.assets,
  });
}

export function useAssetDetail(assetId: string | null) {
  return useQuery({
    queryKey: queryKeys.asset(assetId ?? ""),
    queryFn: () => fetchAsset(assetId!),
    enabled: Boolean(assetId),
  });
}
