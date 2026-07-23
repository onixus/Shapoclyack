"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { fetchAsset, fetchAssets, updateAsset, type AssetStatus, type UpdateAssetBody } from "@/lib/api";
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
