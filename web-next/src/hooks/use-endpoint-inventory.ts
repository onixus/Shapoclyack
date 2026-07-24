"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchAssetSoftware,
  fetchEndpointDeviceChanges,
  fetchEndpointDevicesForAsset,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** Endpoint device(s) reconciled to this network-scan asset (Agent_plan.md S1-S7). */
export function useEndpointDevicesForAsset(assetId: string | null) {
  return useQuery({
    queryKey: queryKeys.endpointDevicesForAsset(assetId ?? ""),
    queryFn: () => fetchEndpointDevicesForAsset(assetId!),
    enabled: Boolean(assetId),
  });
}

export function useAssetSoftware(assetId: string | null) {
  return useQuery({
    queryKey: queryKeys.assetSoftware(assetId ?? ""),
    queryFn: () => fetchAssetSoftware(assetId!),
    enabled: Boolean(assetId),
  });
}

export function useEndpointDeviceChanges(deviceId: string | null) {
  return useQuery({
    queryKey: queryKeys.endpointDeviceChanges(deviceId ?? ""),
    queryFn: () => fetchEndpointDeviceChanges(deviceId!),
    enabled: Boolean(deviceId),
  });
}
