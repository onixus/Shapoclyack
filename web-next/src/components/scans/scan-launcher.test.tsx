import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanLauncher } from "@/components/scans/scan-launcher";
import * as apiModule from "@/lib/api";
import type { JobInfo } from "@/lib/api";
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

describe("ScanLauncher", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ activeTenant: null });
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue({
      app_version: "0.45",
      tools: [],
      enrichment: [],
      scan_config: { profiles: [], nse_profiles: [], stages: {}, service_backend: "pulse" },
      runtime: {
        allow_scan_start: true,
        job_execution_mode: "local",
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
    vi.spyOn(apiModule, "fetchWordlists").mockResolvedValue([]);
  });

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
});
