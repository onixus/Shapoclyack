import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";
import EndpointsPage from "./page";
import type { EndpointDeviceInfo } from "@/lib/api";
const state = vi.hoisted(() => ({
  devices: [] as EndpointDeviceInfo[],
  error: null as Error | null,
}));
vi.mock("@/hooks/use-endpoint-inventory", () => ({
  useEndpointDevices: () => ({ data: state.devices, error: state.error }),
  useRecentSoftwareChanges: () => ({ data: [] }),
  usePatchGaps: () => ({ data: null }),
}));
vi.mock("@/hooks/use-system", () => ({
  useSystemStatus: () => ({ data: { endpoint_inventory: { stale_hours: 48 } } }),
}));
const device: EndpointDeviceInfo = {
  device_id: "endpoint-proof",
  tenant_id: "default",
  agent_id: "agent-proof",
  asset_id: "asset-proof",
  hostname: "laptop.test",
  os_name: "Fedora",
  os_family: "linux",
  os_version: "43",
  os_arch: "x86_64",
  agent_version: "0.5.0",
  labels: {},
  reconciliation_status: "linked",
  status: "stale",
  first_seen: null,
  last_seen: null,
  last_inventory_at: "2026-10-28T00:00:00Z",
  latest_snapshot_id: "snapshot-proof",
  sources: [],
};
beforeEach(() => {
  useAppearanceStore.setState({ locale: "ru" });
  useAuthStore.setState({ activeTenant: "default" });
  state.devices = [];
  state.error = null;
});
it("shows Russian empty states and hides original request errors in technical details", () => {
  const { rerender } = render(<EndpointsPage />);
  expect(screen.getByText(/Устройств Lariska пока нет/)).toBeVisible();
  state.error = new Error("Endpoint HTTP 503");
  rerender(<EndpointsPage />);
  expect(screen.getByRole("alert")).toHaveTextContent("Не удалось загрузить данные устройств.");
  expect(screen.getByText("Endpoint HTTP 503", { exact: false })).not.toBeVisible();
  expect(screen.getByText("Данные устройств недоступны.")).toBeVisible();
});
it("opens a read-only Russian device card, preserves asset URL and closes on tenant switch", async () => {
  state.devices = [device];
  const user = userEvent.setup();
  render(<EndpointsPage />);
  expect(screen.getByText("Данные устарели")).toBeVisible();
  expect(screen.getAllByRole("link", { name: "Открыть актив" })[0]).toHaveAttribute(
    "href",
    "/assets/view?assetId=asset-proof",
  );
  await user.click(screen.getByRole("button", { name: "Открыть карточку устройства" }));
  const dialog = screen.getByRole("dialog");
  expect(within(dialog).getByRole("heading", { name: "Карточка устройства" })).toBeVisible();
  expect(within(dialog).getByText("Связано с сетевым активом")).toBeVisible();
  useAuthStore.setState({ activeTenant: "other" });
  expect(await screen.findByRole("heading", { name: "Конечные точки" })).toBeVisible();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
});
it("retains server-provided stale filtering without inventing an age threshold", async () => {
  state.devices = [
    device,
    { ...device, device_id: "new-device", hostname: "fresh.test", status: "active" },
  ];
  const user = userEvent.setup();
  render(<EndpointsPage />);
  await user.click(screen.getByRole("button", { name: "Только устаревшие" }));
  expect(screen.getByText("laptop.test")).toBeVisible();
  expect(screen.queryByText("fresh.test")).not.toBeInTheDocument();
});
