import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanLauncher, scopeFill } from "@/components/scans/scan-launcher";
import * as apiModule from "@/lib/api";
import type { JobInfo, ScopeTargets } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

function job(overrides: Partial<JobInfo> = {}): JobInfo {
  return {
    job_id: "abc123def456",
    status: "queued",
    run_id: null,
    mode: "balanced",
    started_at: null,
    finished_at: null,
    exit_code: null,
    error: null,
    requested_by: "op",
    ...overrides,
  };
}

function renderLauncher(surface: "external" | "internal" | null) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ScanLauncher surface={surface} />
    </QueryClientProvider>,
  );
}

const SCOPE: ScopeTargets = {
  approved: true,
  targets: [
    { kind: "cidr", value: "10.0.0.0/8", surface: "internal" },
    { kind: "cidr", value: "203.0.113.0/24", surface: "external" },
    { kind: "domain", value: "example.com", surface: "external" },
  ],
  skipped: [
    { kind: "cidr", value: "::/0", reason: "wildcard" },
    { kind: "domain", value: "internal.example.com", reason: "denied" },
  ],
};

describe("scopeFill", () => {
  it("puts everything on the unpinned launcher", () => {
    expect(scopeFill(SCOPE, "all", "all")).toEqual({
      domains: ["example.com"],
      ranges: ["10.0.0.0/8", "203.0.113.0/24"],
      otherSurface: 0,
      skipped: SCOPE.skipped,
    });
  });

  it("keeps names out of everything on the internal page, but not out of its domains button", () => {
    expect(scopeFill(SCOPE, "all", "internal")).toMatchObject({
      domains: undefined,
      ranges: ["10.0.0.0/8"],
      otherSurface: 1,
      skipped: [SCOPE.skipped[0]],
    });
    expect(scopeFill(SCOPE, "domains", "internal")).toMatchObject({
      domains: ["example.com"],
      ranges: undefined,
      otherSurface: 0,
      skipped: [SCOPE.skipped[1]],
    });
  });
});

describe("ScanLauncher", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ activeTenant: null });
    mockSystemStatus("local");
    vi.spyOn(apiModule, "fetchWordlists").mockResolvedValue([]);
  });

  function mockSystemStatus(jobExecutionMode: "local" | "agent") {
    return vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue({
      app_version: "0.45",
      tools: [],
      enrichment: [],
      scan_config: { profiles: [], stages: {}, service_backend: "pulse" },
      runtime: {
        allow_scan_start: true,
        job_execution_mode: jobExecutionMode,
        nats_enabled: false,
        clickhouse_enabled: false,
        postgres_enabled: true,
        ch_ingest_enabled: false,
        asset_stale_days: 30,
        endpoint_inventory_enabled: true,
        endpoint_stale_hours: 24,
      },
      inventory: { tenants: 1, agents_total: 0, agents_online: 0 },
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
  }

  function group(name: string, agentCount: number) {
    return {
      group_id: `agp_${name}`,
      tenant_id: "default",
      name,
      description: "",
      created_at: null,
      created_by: null,
      agent_count: agentCount,
    };
  }

  it("sends the page's surface and an idempotency key with the request", async () => {
    const start = vi.spyOn(apiModule, "startScan").mockResolvedValue(job());
    renderLauncher("external");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/Domains \/ FQDNs/), "api.example.com");
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await user.click(await screen.findByRole("button", { name: /Confirm & launch/ }));
    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    const [body, options] = start.mock.calls[0];
    expect(body.surface).toBe("external");
    expect(body.domains).toBe("api.example.com");
    expect(body.intent).toBe("inventory");
    expect(options?.idempotencyKey).toMatch(/^console:/);
  });

  it("lets the server derive the surface on the unpinned launcher", async () => {
    const start = vi.spyOn(apiModule, "startScan").mockResolvedValue(job());
    renderLauncher(null);
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/IP ranges/), "10.0.0.0/24");
    expect(screen.getByText("Targets suggest: Internal")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await user.click(await screen.findByRole("button", { name: /Confirm & launch/ }));
    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    expect(start.mock.calls[0][0].surface).toBeUndefined();
  });

  it("warns when private ranges are typed into the external launcher", async () => {
    renderLauncher("external");
    const user = userEvent.setup();
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText(/IP ranges/), "192.168.0.0/16");
    expect(screen.getByRole("status")).toHaveTextContent(/Internal/);
  });

  it("keeps internet-only options off the internal launcher", () => {
    renderLauncher("internal");
    expect(screen.queryByLabelText(/wordlist/i)).not.toBeInTheDocument();
    // Private ranges lead the form; the domains field explains internal names.
    expect(screen.getByPlaceholderText(/10\.0\.0\.0\/24/)).toBeInTheDocument();
  });

  it("sends the chosen agent group in agent mode (#361)", async () => {
    mockSystemStatus("agent");
    vi.spyOn(apiModule, "fetchAgentGroups").mockResolvedValue([
      group("pci-segment", 2),
      group("office", 1),
    ]);
    const start = vi.spyOn(apiModule, "startScan").mockResolvedValue(job());
    renderLauncher("external");
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/Domains \/ FQDNs/), "api.example.com");
    await user.click(await screen.findByRole("combobox", { name: /Sensor group/ }));
    await user.click(await screen.findByRole("option", { name: "pci-segment" }));
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await user.click(await screen.findByRole("button", { name: /Confirm & launch/ }));

    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    expect(start.mock.calls[0][0].agent_group).toBe("pci-segment");
  });

  it("warns before launching into a group with nothing in it", async () => {
    mockSystemStatus("agent");
    vi.spyOn(apiModule, "fetchAgentGroups").mockResolvedValue([group("pci-segment", 0)]);
    renderLauncher("external");
    const user = userEvent.setup();

    await user.click(await screen.findByRole("combobox", { name: /Sensor group/ }));
    await user.click(await screen.findByRole("option", { name: "pci-segment" }));
    expect(await screen.findByText(/no sensor online/)).toBeInTheDocument();
  });

  it("fills the external launcher with everything in scope and launches it", async () => {
    const fetched = vi.spyOn(apiModule, "fetchScopeTargets").mockResolvedValue(SCOPE);
    const start = vi.spyOn(apiModule, "startScan").mockResolvedValue(job());
    renderLauncher("external");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /Everything in scope/ }));

    await waitFor(() =>
      expect(screen.getByLabelText(/Domains \/ FQDNs/)).toHaveValue("example.com"),
    );
    expect(screen.getByLabelText(/IP ranges/)).toHaveValue("203.0.113.0/24");
    const note = screen.getByTestId("scope-fill-note");
    expect(note).toHaveTextContent("1 domains · 1 ranges");
    expect(note).toHaveTextContent("1 more ranges belong on Internal scans");
    expect(note).toHaveTextContent("::/0 (matches anything), internal.example.com (denied)");

    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await user.click(await screen.findByRole("button", { name: /Confirm & launch/ }));
    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    expect(start.mock.calls[0][0]).toMatchObject({
      domains: "example.com",
      ranges: "203.0.113.0/24",
      surface: "external",
    });

    // Read again at every click: the scope may have moved in between.
    await user.click(screen.getByRole("button", { name: /Everything in scope/ }));
    await waitFor(() => expect(fetched).toHaveBeenCalledTimes(2));
  });

  it("fills only the domains field from its own button", async () => {
    vi.spyOn(apiModule, "fetchScopeTargets").mockResolvedValue(SCOPE);
    renderLauncher("external");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/IP ranges/), "198.51.100.7");

    await user.click(screen.getByRole("button", { name: /Fill domains from/ }));

    await waitFor(() =>
      expect(screen.getByLabelText(/Domains \/ FQDNs/)).toHaveValue("example.com"),
    );
    expect(screen.getByLabelText(/IP ranges/)).toHaveValue("198.51.100.7");
  });

  it("fills the internal launcher with its private ranges only", async () => {
    vi.spyOn(apiModule, "fetchScopeTargets").mockResolvedValue(SCOPE);
    renderLauncher("internal");
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /Everything in scope/ }));

    await waitFor(() => expect(screen.getByLabelText(/IP ranges/)).toHaveValue("10.0.0.0/8"));
    expect(screen.getByLabelText(/Domains \/ FQDNs/)).toHaveValue("");
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("leaves typed targets alone when the scope has nothing to give", async () => {
    vi.spyOn(apiModule, "fetchScopeTargets").mockResolvedValue({
      approved: false,
      targets: [],
      skipped: [],
    });
    renderLauncher("external");
    const user = userEvent.setup();
    await user.type(screen.getByLabelText(/Domains \/ FQDNs/), "api.example.com");

    await user.click(screen.getByRole("button", { name: /Everything in scope/ }));

    expect(await screen.findByTestId("scope-fill-note")).toHaveTextContent(
      "no approved scan scope",
    );
    expect(screen.getByLabelText(/Domains \/ FQDNs/)).toHaveValue("api.example.com");
  });

  it("says why the scope could not be read", async () => {
    vi.spyOn(apiModule, "fetchScopeTargets").mockRejectedValue(new Error("Forbidden"));
    renderLauncher(null);
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: /Fill ranges from/ }));

    expect(await screen.findByTestId("scope-fill-note")).toHaveTextContent(
      "Could not read the scope: Forbidden",
    );
  });

  it("does not offer an agent group when scans run locally", async () => {
    const groups = vi.spyOn(apiModule, "fetchAgentGroups").mockResolvedValue([
      group("pci-segment", 2),
    ]);
    const start = vi.spyOn(apiModule, "startScan").mockResolvedValue(job());
    renderLauncher("external");
    const user = userEvent.setup();

    await user.type(screen.getByLabelText(/Domains \/ FQDNs/), "api.example.com");
    await user.click(screen.getByRole("button", { name: /Start scan/ }));
    await user.click(await screen.findByRole("button", { name: /Confirm & launch/ }));

    await waitFor(() => expect(start).toHaveBeenCalledTimes(1));
    expect(start.mock.calls[0][0].agent_group).toBeUndefined();
    expect(groups).not.toHaveBeenCalled();
  });
});
