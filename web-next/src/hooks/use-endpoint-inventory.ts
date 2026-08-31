"use client";

import { useQuery } from "@tanstack/react-query";
import {
  fetchAssetSoftware,
  fetchDevicePatchGap,
  fetchEndpointCveMatches,
  fetchEndpointDeviceChanges,
  fetchEndpointDevices,
  fetchEndpointDevicesForAsset,
  fetchPatchGaps,
  fetchRecentSoftwareChanges,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** All Lariska endpoint devices for the tenant. */
export function useEndpointDevices(tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.endpointDevices(tenantId),
    queryFn: () => fetchEndpointDevices({ tenantId }),
  });
}

/** Endpoint device(s) reconciled to this network-scan asset (Agent_plan.md S1-S7). */
export function useEndpointDevicesForAsset(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.endpointDevicesForAsset(assetId ?? "", tenantId),
    queryFn: () => fetchEndpointDevicesForAsset(assetId!, tenantId),
    enabled: Boolean(assetId),
  });
}

export function useAssetSoftware(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.assetSoftware(assetId ?? "", tenantId),
    queryFn: () => fetchAssetSoftware(assetId!, tenantId),
    enabled: Boolean(assetId),
  });
}

export function useEndpointDeviceChanges(deviceId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.endpointDeviceChanges(deviceId ?? "", tenantId),
    queryFn: () => fetchEndpointDeviceChanges(deviceId!, tenantId),
    enabled: Boolean(deviceId),
  });
}

/** Cross-device recent software-change feed for the tenant. */
export function useRecentSoftwareChanges(tenantId = "default", limit = 50) {
  return useQuery({
    queryKey: queryKeys.recentSoftwareChanges(tenantId, limit),
    queryFn: () => fetchRecentSoftwareChanges({ tenantId, limit }),
  });
}

/** Vendor-advisory CVE matches for one endpoint (ROADMAP Track E M1). */
export function useEndpointCveMatches(deviceId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.endpointCveMatches(deviceId ?? "", tenantId),
    queryFn: () => fetchEndpointCveMatches(deviceId!, tenantId),
    enabled: Boolean(deviceId),
  });
}

/** Estate-wide patch gap (ROADMAP Track E M2). */
export function usePatchGaps(tenantId = "default", limit = 50) {
  return useQuery({
    queryKey: queryKeys.patchGaps(tenantId, limit),
    queryFn: () => fetchPatchGaps(tenantId, limit),
  });
}

/** One endpoint's outstanding upgrades. */
export function useDevicePatchGap(deviceId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.devicePatchGap(deviceId ?? "", tenantId),
    queryFn: () => fetchDevicePatchGap(deviceId!, tenantId),
    enabled: Boolean(deviceId),
  });
}
