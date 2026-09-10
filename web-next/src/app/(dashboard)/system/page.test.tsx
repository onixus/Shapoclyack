import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SystemPage from "@/app/(dashboard)/system/page";
import * as apiModule from "@/lib/api";
import type { EnrichmentDb, Me, SystemStatus } from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";

const NOW = "2026-09-08T10:00:00Z";

function db(overrides: Partial<EnrichmentDb> & { name: string }): EnrichmentDb {
  return {
    present: true,
    path: `/app/scanner/data/${overrides.name}.json`,
    size_bytes: 1024,
    modified_at: NOW,
    age_days: 0,
    stale: false,
    ...overrides,
  };
}

function status(enrichment: EnrichmentDb[]): SystemStatus {
  return {
    app_version: "0.44-0907",
    tools: [],
    enrichment,
    scan_config: { profiles: [], nse_profiles: [], stages: {} },
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
      change_retention_days: 90,
      retention_interval_seconds: 3600,
      retention_last_run_at: null,
    },
  };
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <SystemPage />
    </QueryClientProvider>,
  );
}

/** The badge cell of the enrichment row for `name`. */
function badgeOf(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  expect(row).not.toBeNull();
  return within(row as HTMLElement).getByTestId("enrichment-freshness");
}

describe("SystemPage enrichment freshness", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAppearanceStore.setState({ locale: "en" });
  });

  it("does not render a dataset the build called unusable as fresh", async () => {
    // A fresh offline install: the seed is present, its mtime is the build's,
    // and it holds eight advisories. present + not stale is everything the
    // badge used to look at, so it came out green while the API was saying
    // usable: false — which is the one field that separates a corpus from a
    // placeholder here.
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(
      status([
        db({ name: "advisories_debian", usable: false }),
        db({ name: "advisories_ubuntu", usable: true }),
      ]),
    );
    renderPage();

    expect(await screen.findByText("advisories_debian")).toBeInTheDocument();
    expect(badgeOf("advisories_debian")).toHaveTextContent("stub");
    expect(badgeOf("advisories_ubuntu")).toHaveTextContent("fresh");
  });

  it("treats a missing verdict as no verdict, not as a bad one", async () => {
    // null is "no manifest was found" — an image built before the manifest
    // existed, or a volume without one. Badging that as a stub would report
    // every such install as broken on the strength of nothing.
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(
      status([db({ name: "epss", usable: null }), db({ name: "kev" })]),
    );
    renderPage();

    expect(await screen.findByText("epss")).toBeInTheDocument();
    expect(badgeOf("epss")).toHaveTextContent("fresh");
    expect(badgeOf("kev")).toHaveTextContent("fresh");
  });

  it("keeps missing and stale ahead of the floor verdict", async () => {
    // An absent file has no entries to fail a floor with, and a dataset that is
    // both old and short is worth reporting as old: the operator's next action
    // differs, and "stub" would send them to the wrong one.
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(
      status([
        db({ name: "geoip", present: false, usable: false, size_bytes: null, modified_at: null, age_days: null }),
        db({ name: "cvss4", usable: false, stale: true, age_days: 90 }),
      ]),
    );
    renderPage();

    expect(await screen.findByText("geoip")).toBeInTheDocument();
    expect(badgeOf("geoip")).toHaveTextContent("missing");
    expect(badgeOf("cvss4")).toHaveTextContent("stale");
  });

  it("translates the badge, including the new one", async () => {
    useAppearanceStore.setState({ locale: "ru" });
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(
      status([db({ name: "advisories_debian", usable: false }), db({ name: "kev" })]),
    );
    renderPage();

    expect(await screen.findByText("advisories_debian")).toBeInTheDocument();
    expect(badgeOf("advisories_debian")).toHaveTextContent("заглушка");
    expect(badgeOf("kev")).toHaveTextContent("актуально");
  });
});


function principal(overrides: Partial<Me>): Me {
  return {
    username: "someone",
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    ...overrides,
  };
}

describe("SystemPage configuration panel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAppearanceStore.setState({ locale: "en" });
    vi.spyOn(apiModule, "fetchSystemStatus").mockResolvedValue(status([db({ name: "kev" })]));
    vi.spyOn(apiModule, "fetchConfig").mockResolvedValue({
      editable_paths: ["nuclei.enabled"],
      defaults: { "nuclei.enabled": false },
      effective: { "nuclei.enabled": false },
      overrides: {},
    });
  });

  it("hides the tuner from a principal without config.read", async () => {
    // GET /api/config is 403 for a viewer since #318, so rendering the panel
    // would put an error message where a read-only view used to be.
    useAuthStore.setState({ user: principal({ permissions: [] }) });
    renderPage();

    expect(await screen.findByText("kev")).toBeInTheDocument();
    expect(screen.queryByText("Scanner Configuration Tuner")).not.toBeInTheDocument();
  });

  it("shows it to a principal that holds config.read", async () => {
    useAuthStore.setState({
      user: principal({ role: "operator", permissions: ["config.read"] }),
    });
    renderPage();

    expect(await screen.findByText("Scanner Configuration Tuner")).toBeInTheDocument();
  });

  it("falls back to the role on an API that sends no permissions", async () => {
    // An installation upgraded in two steps: the console is new, the API is
    // not. Gating on a field that is simply absent would empty the page.
    useAuthStore.setState({ user: principal({ role: "admin" }) });
    renderPage();

    expect(await screen.findByText("Scanner Configuration Tuner")).toBeInTheDocument();
  });
});
