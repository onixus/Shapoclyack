"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchAssetAdvisories,
  fetchAssetSoftware,
  fetchDeviceAdvisories,
  fetchDevicePatchGap,
  fetchEndpointDeviceChanges,
  fetchEndpointDevices,
  fetchEndpointDevicesForAsset,
  fetchPatchGaps,
  fetchRecentSoftwareChanges,
  triggerDeviceAdvisoryMatch,
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

/** CVE/OSV security advisories for a specific endpoint device. */
export function useDeviceAdvisories(deviceId: string | null) {
  return useQuery({
    queryKey: ["endpoint", "device", deviceId, "advisories"],
    queryFn: () => fetchDeviceAdvisories(deviceId!),
    enabled: Boolean(deviceId),
  });
}

/** CVE/OSV security advisories for an asset's software inventory. */
export function useAssetAdvisories(assetId: string | null) {
  return useQuery({
    queryKey: ["assets", assetId, "advisories"],
    queryFn: () => fetchAssetAdvisories(assetId!),
    enabled: Boolean(assetId),
  });
}

/** Tenant-wide patch gap summary. */
export function usePatchGaps() {
  return useQuery({
    queryKey: ["endpoint", "patch-gaps"],
    queryFn: fetchPatchGaps,
  });
}

/** Device-specific patch gap metrics and remediation advice. */
export function useDevicePatchGap(deviceId: string | null) {
  return useQuery({
    queryKey: ["endpoint", "device", deviceId, "patch-gap"],
    queryFn: () => fetchDevicePatchGap(deviceId!),
    enabled: Boolean(deviceId),
  });
}

/** Trigger advisory re-match for an endpoint device. */
export function useTriggerDeviceMatch(deviceId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => triggerDeviceAdvisoryMatch(deviceId),
    onSuccess: (advisories) => {
      void queryClient.invalidateQueries({ queryKey: ["endpoint", "device", deviceId] });
      void queryClient.invalidateQueries({ queryKey: ["endpoint", "patch-gaps"] });
      void queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
      toast.success(`Matched ${advisories.length} security advisories`);
    },
    onError: (err) => {
      toast.error("Advisory match failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

