import { afterEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import type { EndpointDeviceInfo, EndpointSoftwareChangeInfo, EndpointSoftwareItemInfo } from "@/lib/api";

vi.mock("@/lib/api", () => ({
  fetchEndpointDevices: vi.fn(),
  fetchEndpointDevicesForAsset: vi.fn(),
  fetchAssetSoftware: vi.fn(),
  fetchEndpointDeviceChanges: vi.fn(),
}));

import {
  fetchEndpointDevices,
  fetchEndpointDevicesForAsset,
  fetchAssetSoftware,
  fetchEndpointDeviceChanges,
} from "@/lib/api";
import {
  useEndpointDevices,
  useEndpointDevicesForAsset,
  useAssetSoftware,
  useEndpointDeviceChanges,
} from "@/hooks/use-endpoint-inventory";

const DEVICE: EndpointDeviceInfo = {
  device_id: "dev_1",
  tenant_id: "default",
  agent_id: "agent_1",
  asset_id: "asset_1",
  hostname: "host-1",
  os_family: "linux",
  os_name: "Ubuntu",
  os_version: "24.04",
  os_arch: "x86_64",
  agent_version: "0.2.7",
  labels: {},
  reconciliation_status: "linked",
  status: "active",
  first_seen: "2026-07-01T00:00:00Z",
  last_seen: "2026-07-30T00:00:00Z",
  last_inventory_at: "2026-07-30T00:00:00Z",
  latest_snapshot_id: "snap_1",
};

const SOFTWARE_ITEM: EndpointSoftwareItemInfo = {
  name: "openssh",
  version: "9.6p1",
  publisher: "OpenBSD",
  architecture: "amd64",
  source: "dpkg",
  install_location: null,
};

const SOFTWARE_CHANGE: EndpointSoftwareChangeInfo = {
  device_id: "dev_1",
  snapshot_id: "snap_1",
  event_type: "installed",
  display_name: "openssh",
  old_version: null,
  new_version: "9.6p1",
  observed_at: "2026-07-30T00:00:00Z",
};

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

afterEach(() => {
  vi.clearAllMocks();
});

describe("useEndpointDevices", () => {
  it("returns the fetched devices on the happy path", async () => {
    vi.mocked(fetchEndpointDevices).mockResolvedValueOnce([DEVICE]);

    const { result } = renderHook(() => useEndpointDevices("default"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([DEVICE]);
    expect(fetchEndpointDevices).toHaveBeenCalledWith({ tenantId: "default" });
  });

  it("surfaces the error when the fetch fails", async () => {
    vi.mocked(fetchEndpointDevices).mockRejectedValueOnce(new Error("network down"));

    const { result } = renderHook(() => useEndpointDevices("default"), { wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toBe("network down");
  });
});

describe("useEndpointDevicesForAsset", () => {
  it("does not fetch when assetId is null", () => {
    const { result } = renderHook(() => useEndpointDevicesForAsset(null), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(fetchEndpointDevicesForAsset).not.toHaveBeenCalled();
  });

  it("fetches devices reconciled to the given asset", async () => {
    vi.mocked(fetchEndpointDevicesForAsset).mockResolvedValueOnce([DEVICE]);

    const { result } = renderHook(() => useEndpointDevicesForAsset("asset_1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([DEVICE]);
    expect(fetchEndpointDevicesForAsset).toHaveBeenCalledWith("asset_1");
  });
});

describe("useAssetSoftware", () => {
  it("does not fetch when assetId is null", () => {
    const { result } = renderHook(() => useAssetSoftware(null), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(fetchAssetSoftware).not.toHaveBeenCalled();
  });

  it("returns the fetched software list on the happy path", async () => {
    vi.mocked(fetchAssetSoftware).mockResolvedValueOnce([SOFTWARE_ITEM]);

    const { result } = renderHook(() => useAssetSoftware("asset_1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([SOFTWARE_ITEM]);
  });

  it("surfaces the error when the fetch fails", async () => {
    vi.mocked(fetchAssetSoftware).mockRejectedValueOnce(new Error("forbidden"));

    const { result } = renderHook(() => useAssetSoftware("asset_1"), { wrapper });

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect((result.current.error as Error).message).toBe("forbidden");
  });
});

describe("useEndpointDeviceChanges", () => {
  it("does not fetch when deviceId is null", () => {
    const { result } = renderHook(() => useEndpointDeviceChanges(null), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(fetchEndpointDeviceChanges).not.toHaveBeenCalled();
  });

  it("returns the fetched change feed on the happy path", async () => {
    vi.mocked(fetchEndpointDeviceChanges).mockResolvedValueOnce([SOFTWARE_CHANGE]);

    const { result } = renderHook(() => useEndpointDeviceChanges("dev_1"), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data).toEqual([SOFTWARE_CHANGE]);
  });
});
