import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import UsagePage from "@/app/(dashboard)/usage/page";
import * as apiModule from "@/lib/api";
import type { FleetUsage, Me, TenantQuota, TenantUsage, UsageResource } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

/** The history chart renders through recharts' ResponsiveContainer, which
 * jsdom leaves without a ResizeObserver. */
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

function resource(overrides: Partial<UsageResource> = {}): UsageResource {
  return { used: 10, limit: 100, remaining: 90, used_ratio: 0.1, over_limit: false, ...overrides };
}

const UNLIMITED = resource({ limit: null, remaining: null, used_ratio: null });

function usage(overrides: Partial<TenantUsage> = {}): TenantUsage {
  return {
    tenant_id: "default",
    period_start: "2026-09-01T00:00:00",
    period_end: "2026-10-01T00:00:00",
    quota_source: "tenant",
    enforced: true,
    note: "Contract ACME-2026",
    updated_at: "2026-09-03T10:00:00",
    updated_by: "admin",
    assets: { used: 812, limit: 2000, remaining: 1188, used_ratio: 0.406, over_limit: false },
    scans: { used: 12, limit: 40, remaining: 28, used_ratio: 0.3, over_limit: false },
    scan_history: [
      { month: "2026-08", scans: 9 },
      { month: "2026-09", scans: 12 },
    ],
    ...overrides,
  };
}

function fleet(overrides: Partial<FleetUsage> = {}): FleetUsage {
  return {
    period_start: "2026-09-01T00:00:00",
    period_end: "2026-10-01T00:00:00",
    tenants: [
      {
        tenant_id: "calm",
        name: "Calm Corp",
        status: "active",
        quota_source: "default",
        assets: resource({ used: 5, remaining: 95, used_ratio: 0.05 }),
        scans: UNLIMITED,
      },
      {
        tenant_id: "acme",
        name: "ACME",
        status: "active",
        quota_source: "tenant",
        assets: resource({ used: 120, limit: 100, remaining: 0, used_ratio: 1.2, over_limit: true }),
        scans: resource({ used: 9, limit: 10, remaining: 1, used_ratio: 0.9 }),
      },
    ],
    ...overrides,
  };
}

/** What `GET /tenants/{id}/quota` returns: the row stored for the tenant, which
 * is not what the fleet table shows — that carries the limits in force. */
function storedQuota(overrides: Partial<TenantQuota> = {}): TenantQuota {
  return {
    tenant_id: "acme",
    max_assets: 100,
    max_scans_per_month: 10,
    quota_source: "tenant",
    note: null,
    updated_at: "2026-09-01T10:00:00",
    updated_by: "admin",
    ...overrides,
  };
}

async function openEditor(tenantName: string) {
  const rows = screen.getAllByRole("row").slice(1);
  const row = rows.find((r) => within(r).queryByText(tenantName)) as HTMLElement;
  await userEvent.click(within(row).getByRole("button", { name: "Edit quota" }));
  return row;
}

function signIn(user: Partial<Me> = {}) {
  useAuthStore.setState({
    user: {
      username: "u",
      role: "viewer",
      tenants: ["default"],
      default_tenant: "default",
      is_platform_admin: false,
      ...user,
    },
    activeTenant: null,
    hydrated: true,
    loading: false,
  });
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <UsagePage />
    </QueryClientProvider>,
  );
  return queryClient;
}

describe("UsagePage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, activeTenant: null });
  });

  it("shows consumption against the ceiling, the period and where the quota came from", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    signIn();
    renderPage();

    expect(await screen.findByText("812")).toBeInTheDocument();
    expect(screen.getAllByText(/812 of 2,000/).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/12 of 40/).length).toBeGreaterThan(0);
    expect(screen.getAllByText("2026-09-01 → 2026-10-01").length).toBeGreaterThan(0);
    expect(screen.getByText("Contract ACME-2026")).toBeInTheDocument();
    expect(screen.getAllByText("Set for this tenant").length).toBeGreaterThan(0);
    expect(screen.getByText(/40.6%/)).toBeInTheDocument();
    expect(screen.getByText(/1,188 remaining/)).toBeInTheDocument();
  });

  it("calls an unlimited resource unlimited instead of drawing a bar at either end", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(
      usage({ assets: { ...UNLIMITED, used: 812 }, note: null, updated_at: null }),
    );
    signIn();
    renderPage();

    expect((await screen.findAllByText(/812 of Unlimited/)).length).toBeGreaterThan(0);
    expect(screen.getByText(/no ceiling/i)).toBeInTheDocument();
    // Only the scan quota has a ceiling, so only it gets a bar — an unlimited
    // resource must not read as either empty or full.
    expect(screen.getAllByRole("progressbar")).toHaveLength(1);
    expect(screen.queryByText("100%")).not.toBeInTheDocument();
    expect(screen.queryByText(/0 remaining/)).not.toBeInTheDocument();
  });

  it("hides the cross-tenant table from a viewer and never asks for it", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    const fleetSpy = vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    signIn();
    renderPage();

    await screen.findByText("812");
    expect(screen.queryByText("Tenants against their quotas")).not.toBeInTheDocument();
    expect(screen.queryByText("ACME")).not.toBeInTheDocument();
    expect(fleetSpy).not.toHaveBeenCalled();
  });

  it("flags an over-limit tenant first for a platform admin", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    signIn({ role: "admin", is_platform_admin: true });
    renderPage();

    expect(await screen.findByText("ACME")).toBeInTheDocument();
    expect(screen.getByText("Tenants against their quotas")).toBeInTheDocument();
    const rows = screen.getAllByRole("row").slice(1);
    expect(within(rows[0]).getByText("ACME")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Over limit")).toBeInTheDocument();
    expect(within(rows[0]).getByText("Near limit")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Calm Corp")).toBeInTheDocument();
    expect(within(rows[1]).getByText(/10 of Unlimited/)).toBeInTheDocument();
  });

  it("sends an emptied ceiling as unlimited rather than as zero", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    vi.spyOn(apiModule, "fetchTenantQuota").mockResolvedValue(storedQuota());
    const put = vi.spyOn(apiModule, "updateTenantQuota").mockResolvedValue(
      storedQuota({ max_assets: null, updated_at: "2026-09-03T11:00:00" }),
    );
    signIn({ role: "admin", is_platform_admin: true });
    renderPage();

    await screen.findByText("ACME");
    await openEditor("ACME");

    const box = await screen.findByLabelText("Max assets — acme");
    expect(box).toHaveValue("100");
    await userEvent.clear(box);
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("acme", {
        max_assets: null,
        max_scans_per_month: 10,
      }),
    );
  });

  it("prefills the stored note and sends it back, instead of wiping it on the next edit", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    vi.spyOn(apiModule, "fetchTenantQuota").mockResolvedValue(
      storedQuota({ note: "Contract ACME-2026" }),
    );
    const put = vi.spyOn(apiModule, "updateTenantQuota").mockResolvedValue(storedQuota());
    signIn({ role: "admin", is_platform_admin: true });
    renderPage();

    await screen.findByText("ACME");
    await openEditor("ACME");

    expect(await screen.findByLabelText("Note — acme")).toHaveValue("Contract ACME-2026");
    const assets = screen.getByLabelText("Max assets — acme");
    await userEvent.clear(assets);
    await userEvent.type(assets, "250");
    await userEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("acme", {
        max_assets: 250,
        max_scans_per_month: 10,
        note: "Contract ACME-2026",
      }),
    );
  });

  it("opens an inherited tenant with empty boxes rather than pinning the platform default", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    const get = vi.spyOn(apiModule, "fetchTenantQuota").mockResolvedValue(
      storedQuota({
        tenant_id: "calm",
        quota_source: "default",
        updated_at: null,
        updated_by: null,
      }),
    );
    signIn({ role: "admin", is_platform_admin: true });
    renderPage();

    await screen.findByText("Calm Corp");
    await openEditor("Calm Corp");

    expect(get).toHaveBeenCalledWith("calm");
    // The fleet row says 100 assets, but that ceiling is the platform's, not
    // this tenant's — saving it would pin it here forever.
    expect(await screen.findByLabelText("Max assets — calm")).toHaveValue("");
    expect(screen.getByLabelText("Max scans per month — calm")).toHaveValue("");
    expect(screen.getByText(/no quota of its own/i)).toBeInTheDocument();
    // Nothing to reset: the tenant has no row to drop.
    expect(
      screen.queryByRole("button", { name: "Reset to platform default" }),
    ).not.toBeInTheDocument();
  });

  it("resets a tenant-specific quota back to the platform default, once confirmed", async () => {
    vi.spyOn(apiModule, "fetchUsage").mockResolvedValue(usage());
    vi.spyOn(apiModule, "fetchFleetUsage").mockResolvedValue(fleet());
    vi.spyOn(apiModule, "fetchTenantQuota").mockResolvedValue(storedQuota());
    const remove = vi.spyOn(apiModule, "deleteTenantQuota").mockResolvedValue(undefined);
    signIn({ role: "admin", is_platform_admin: true });
    renderPage();

    await screen.findByText("ACME");
    await openEditor("ACME");

    await userEvent.click(
      await screen.findByRole("button", { name: "Reset to platform default" }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/Reset acme to the platform default\?/)).toBeInTheDocument();
    await userEvent.click(
      within(dialog).getByRole("button", { name: "Reset to platform default" }),
    );

    await waitFor(() => expect(remove).toHaveBeenCalledWith("acme"));
  });
});
