import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Sidebar } from "@/components/layout/Sidebar";
import * as apiModule from "@/lib/api";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

let pathname = "/scans/external";
vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
}));

function installLocalStorage() {
  const store = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, String(value)),
      removeItem: (key: string) => void store.delete(key),
      clear: () => store.clear(),
    },
  });
}

function signIn(user: Partial<Me>) {
  useAuthStore.setState({
    user: {
      username: "u",
      role: "viewer",
      tenants: [],
      default_tenant: "default",
      is_platform_admin: false,
      ...user,
    },
    canOperate: user.role === "operator" || user.role === "admin",
    activeTenant: null,
    hydrated: true,
    loading: false,
  });
}

function renderSidebar() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={queryClient}>
      <Sidebar />
    </QueryClientProvider>,
  );
}

describe("Sidebar", () => {
  beforeEach(() => {
    installLocalStorage();
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue({
      app_version: "0.45",
      tools: [],
      enrichment: [],
      scan_config: { profiles: [], stages: {} },
      runtime: {
        allow_scan_start: true,
        job_execution_mode: "agent",
        nats_enabled: false,
        clickhouse_enabled: false,
        postgres_enabled: true,
        ch_ingest_enabled: false,
        asset_stale_days: 30,
        endpoint_inventory_enabled: true,
        endpoint_stale_hours: 24,
      },
      inventory: { tenants: 1, agents_total: 2, agents_online: 1 },
      endpoint_inventory: {
        enabled: true,
        devices_total: 0,
        devices_stale: 0,
        stale_hours: 24,
        retention_enabled: false,
        snapshot_retention_days: 30,
        change_retention_days: 30,
        retention_interval_seconds: 3600,
        retention_last_run_at: null,
      },
    });
    pathname = "/scans/external";
  });

  it("groups the menu and marks only the current page", () => {
    signIn({ role: "operator" });
    renderSidebar();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByText("External surface")).toBeInTheDocument();
    expect(within(nav).getByText("Internal surface")).toBeInTheDocument();
    const current = within(nav).getAllByRole("link", { current: "page" });
    expect(current).toHaveLength(1);
    expect(current[0]).toHaveAttribute("href", "/scans/external");
    // "/scans" is a prefix of the current path but must not light up too.
    expect(within(nav).getByRole("link", { name: "Jobs" })).not.toHaveAttribute("aria-current");
  });

  it("hides operator pages and the quick-launch pair from a viewer", () => {
    signIn({ role: "viewer" });
    renderSidebar();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).queryByText("External scans")).not.toBeInTheDocument();
    expect(within(nav).queryByText("Sensors")).not.toBeInTheDocument();
    expect(within(nav).getByText("Vulnerabilities")).toBeInTheDocument();
    expect(screen.queryByTestId("quick-launch")).not.toBeInTheDocument();
  });

  it("keeps the audit trail reachable for a tenant admin signed in as a global viewer", () => {
    // "admin" on GET /api/audit means admin *in the tenant*, which the JWT does
    // not carry. A minRole on this entry hid the page from exactly the account
    // it exists for; the API is the boundary, and the page renders its 403.
    signIn({ role: "viewer", tenants: ["acme"] });
    renderSidebar();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByRole("link", { name: "Audit trail" })).toHaveAttribute(
      "href",
      "/audit",
    );
    // The neighbouring page really is global-admin-only, so it stays hidden.
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });

  it("offers an operator one click to each surface's launcher", () => {
    signIn({ role: "operator" });
    renderSidebar();
    const quick = screen.getByTestId("quick-launch");
    expect(within(quick).getByRole("link", { name: /External scan/ })).toHaveAttribute(
      "href",
      "/scans/external?launch=1",
    );
    expect(within(quick).getByRole("link", { name: /Internal scan/ })).toHaveAttribute(
      "href",
      "/scans/internal?launch=1",
    );
  });

  it("collapses a group, remembers it, and keeps the current page visible", async () => {
    signIn({ role: "admin" });
    renderSidebar();
    const user = userEvent.setup();
    const nav = screen.getByRole("navigation", { name: "Primary" });
    expect(within(nav).getByText("Exposure")).toBeInTheDocument();
    await user.click(within(nav).getByRole("button", { name: "External surface" }));
    expect(within(nav).queryByText("Exposure")).not.toBeInTheDocument();
    // The active entry survives the collapse.
    expect(within(nav).getByRole("link", { name: "External scans" })).toBeInTheDocument();
    expect(JSON.parse(window.localStorage.getItem("shapoclyack.nav.collapsed") ?? "[]")).toEqual([
      "external",
    ]);
  });

  it("shows the API version and execution mode instead of a decorative pulse", async () => {
    signIn({ role: "viewer" });
    renderSidebar();
    expect(await screen.findByText("v0.45")).toBeInTheDocument();
    expect(screen.getByText("Sensor execution")).toBeInTheDocument();
  });

  it("moves focus into the mobile drawer, closes on Escape and returns focus to the toggle", async () => {
    signIn({ role: "viewer" });
    renderSidebar();
    const user = userEvent.setup();
    const toggle = screen.getByRole("button", { name: "Open navigation" });
    await user.click(toggle);
    const drawer = document.getElementById("primary-sidebar") as HTMLElement;
    expect(drawer.contains(document.activeElement)).toBe(true);
    await user.keyboard("{Escape}");
    expect(screen.getByRole("button", { name: "Open navigation" })).toHaveFocus();
    expect(screen.getByRole("button", { name: "Open navigation" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });

  it("sends focus to the main region, not the toggle, after a nav link closes the drawer", async () => {
    signIn({ role: "viewer" });
    const main = document.createElement("main");
    main.id = "main-content";
    main.tabIndex = -1;
    document.body.appendChild(main);
    renderSidebar();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    await user.click(screen.getByRole("link", { name: "Vulnerabilities" }));
    expect(screen.getByRole("button", { name: "Open navigation" })).not.toHaveFocus();
    expect(main).toHaveFocus();
    main.remove();
  });

  it("keeps the slide-out animation by transitioning visibility with the transform", () => {
    signIn({ role: "viewer" });
    renderSidebar();
    const drawer = document.getElementById("primary-sidebar") as HTMLElement;
    expect(drawer.className).toContain("transition-[transform,visibility]");
  });

  it("does not steal focus on first render", () => {
    signIn({ role: "viewer" });
    renderSidebar();
    expect(document.body).toHaveFocus();
  });
});
