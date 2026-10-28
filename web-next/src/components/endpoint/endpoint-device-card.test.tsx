import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it } from "vitest";
import { useAppearanceStore } from "@/lib/appearance";
import type { EndpointDeviceInfo } from "@/lib/api";
import { EndpointDeviceCard } from "./endpoint-device-card";
const device: EndpointDeviceInfo = {
  device_id: "device-proof",
  tenant_id: "default",
  agent_id: "agent-proof",
  asset_id: null,
  hostname: "workstation.test",
  os_family: "linux",
  os_name: "Fedora",
  os_version: "43",
  os_arch: "x86_64",
  agent_version: "0.5.0",
  labels: {},
  reconciliation_status: "unlinked",
  status: "stale",
  first_seen: null,
  last_seen: null,
  last_inventory_at: "2026-10-28T00:00:00Z",
  latest_snapshot_id: "snapshot-proof",
  sources: [
    {
      source: "pip",
      status: "failed",
      diagnostic_code: "permission_denied",
      collected_at: "2026-10-28T00:00:00Z",
      last_complete_at: null,
      collector_version: "0.5.0",
    },
  ],
};
beforeEach(() => useAppearanceStore.setState({ locale: "ru" }));
it("separates inventory freshness from linkage and keeps original identifiers/codes collapsed", async () => {
  render(<EndpointDeviceCard device={device} />);
  expect(screen.getByText("Не связано с сетевым активом")).toBeVisible();
  expect(screen.getByText("Данные устарели")).toBeVisible();
  expect(screen.getByText("64-разрядная x86")).toBeVisible();
  expect(screen.getByText("Пакеты Python")).toBeVisible();
  expect(screen.getByRole("list")).toHaveTextContent("ошибка сбора");
  expect(screen.getByText("Нет доступа к данным источника")).toBeVisible();
  const original = screen
    .getAllByText("Технические данные")
    .map((x) => x.closest("details")!)
    .find((x) => x.textContent?.includes('"device_id"'))!;
  expect(original.open).toBe(false);
  expect(original).toHaveTextContent('"status": "stale"');
  expect(original).toHaveTextContent('"reconciliation_status": "unlinked"');
  await userEvent.click(within(original).getByText("Технические данные"));
  expect(original.open).toBe(true);
  expect(original).toHaveTextContent("snapshot-proof");
});
it("never infers a known state for unfamiliar provider codes", () => {
  render(
    <EndpointDeviceCard
      device={{
        ...device,
        status: "new_state" as "active",
        reconciliation_status: "new_link" as "linked",
        os_family: "new_os",
        os_arch: "new_arch",
        sources: [],
      }}
    />,
  );
  expect(screen.getByText("Состояние привязки не определено")).toBeVisible();
  expect(screen.getByText("Актуальность данных не определена")).toBeVisible();
  expect(screen.getByText("Другая архитектура")).toBeVisible();
  expect(screen.getByText("Семейство ОС не определено")).toBeVisible();
  expect(screen.getByText(/"new_state"/)).not.toBeVisible();
});

it("does not treat a heartbeat without inventory as a fresh inventory", () => {
  render(
    <EndpointDeviceCard
      device={{ ...device, status: "active", last_inventory_at: null, sources: [] }}
    />,
  );
  expect(screen.getByText("Инвентарь ещё не получен")).toBeVisible();
  expect(screen.getByText("Инвентарь ещё не получен").closest("[data-tone]")).toHaveAttribute(
    "data-tone",
    "muted",
  );
  expect(screen.queryByText("Данные актуальны")).not.toBeInTheDocument();
});
