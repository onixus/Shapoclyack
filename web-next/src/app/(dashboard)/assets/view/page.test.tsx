import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { it, expect, vi } from "vitest";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";
import AssetDetailPage from "./page";
const update = vi.hoisted(() => vi.fn());
vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("assetId=asset-proof"),
}));
vi.mock("@/hooks/use-assets", () => ({
  useAssetDetail: () => ({
    data: {
      asset_id: "asset-proof",
      status: "active",
      environment: "production",
      data_classification: "confidential",
      exposure_level: "internet",
      asset_criticality: 2,
      tags: {},
      identifiers: [{ identifier_type: "fqdn", identifier_value: "example.test" }],
      risk: { open_total: 0 },
    },
  }),
  useUpdateAsset: () => ({ mutate: update }),
  useAssetContextEvents: () => ({ data: { items: [] } }),
}));
vi.mock("@/hooks/use-runs", () => ({
  useRuns: () => ({ data: { items: [] } }),
  useRunVulns: () => ({ data: [] }),
  useRunHosts: () => ({ data: [] }),
  useRunPorts: () => ({ data: [] }),
}));
vi.mock("@/hooks/use-vulnerabilities", () => ({
  useTrackedVulnerabilities: () => ({ data: { items: [], total: 0 } }),
}));
vi.mock("@/hooks/use-endpoint-inventory", () => ({
  useEndpointDevicesForAsset: () => ({ data: [] }),
  useAssetSoftware: () => ({ data: [] }),
  useEndpointDeviceChanges: () => ({ data: [] }),
}));
vi.mock("@/hooks/use-retro-match", () => ({ useAssetServices: () => ({ data: [] }) }));
it("shows Russian asset controls and retains exact context values when saving", async () => {
  useAppearanceStore.setState({ locale: "ru" });
  useAuthStore.setState({ canOperate: true });
  render(<AssetDetailPage />);
  expect(screen.getByRole("heading", { name: "example.test" })).toBeVisible();
  expect(screen.getAllByText("рабочая среда").length).toBeGreaterThan(0);
  expect(screen.getByText("Доменное имя")).toBeVisible();
  expect(screen.getByText("Вывести из эксплуатации")).toBeVisible();
  const raw = screen
    .getAllByText("Технические данные")
    .map((e) => e.closest("details")!)
    .find((e) => e.textContent?.includes('"asset_id"'))!;
  expect(raw).not.toHaveAttribute("open");
  expect(raw).toHaveTextContent("production");
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: /Сохранить/ }));
  expect(update.mock.calls[0][0]).toMatchObject({
    environment: "production",
    data_classification: "confidential",
    exposure_level: "internet",
    asset_criticality: 2,
  });
  await user.click(screen.getByRole("tab", { name: /ПО/ }));
  expect(screen.getByText(/Агент Lariska пока не связан/)).toBeVisible();
});
