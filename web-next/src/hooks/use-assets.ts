"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchAsset,
  fetchAssetSummary,
  fetchAssets,
  updateAsset,
  type AssetStatus,
  type PageParams,
  type UpdateAssetBody,
} from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { queryKeys } from "@/lib/query-keys";

export function useAssets(
  filters: { status: AssetStatus | ""; unowned?: boolean },
  page?: PageParams,
) {
  return useQuery({
    queryKey: queryKeys.assetsPage({ status: filters.status, unowned: filters.unowned }, page),
    queryFn: () => fetchAssets({ status: filters.status, unowned: filters.unowned }, page),
    refetchInterval: POLL_INTERVALS.assets,
  });
}

export function useAssetSummary() {
  return useQuery({
    queryKey: queryKeys.assetSummary,
    queryFn: fetchAssetSummary,
    refetchInterval: POLL_INTERVALS.assets,
  });
}

export function useAssetDetail(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.asset(assetId ?? "", tenantId),
    queryFn: () => fetchAsset(assetId!, tenantId),
    enabled: Boolean(assetId),
  });
}

export function useUpdateAsset(assetId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateAssetBody) => updateAsset(assetId, body),
    onSuccess: async (updated) => {
      queryClient.setQueryData(queryKeys.asset(assetId), updated);
      await queryClient.invalidateQueries({ queryKey: ["assets"] });
      toast.success("Asset updated");
    },
    onError: (err) => {
      toast.error("Update failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
