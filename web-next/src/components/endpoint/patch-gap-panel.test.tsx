import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { DevicePatchGapCard, PatchGapPanel } from "@/components/endpoint/patch-gap-panel";
import * as apiModule from "@/lib/api";
import type { DevicePatchGap, PatchGapItem, TenantPatchGap } from "@/lib/api";

function item(overrides: Partial<PatchGapItem> = {}): PatchGapItem {
  return {
    installed_package: "curl",
    source_package: "curl",
    installed_version: "7.68.0-1ubuntu2.1",
    target_version: "7.68.0-1ubuntu2.20",
    cve_ids: ["CVE-2023-38545", "CVE-2023-38546"],
    cve_count: 2,
    worst_severity: "critical",
    by_severity: { critical: 1, medium: 1 },
    distro: "ubuntu",
    distro_release: "focal",
    upgrade_command: "sudo apt-get update && sudo apt-get install --only-upgrade curl",
    ...overrides,
  };
}

function deviceGap(overrides: Partial<DevicePatchGap> = {}): DevicePatchGap {
  return {
    device_id: "dev_1",
    hostname: "workstation-01.example.test",
    packages_to_upgrade: 1,
    cves_closed_by_upgrade: 2,
    unfixed_findings: 0,
    worst_severity: "critical",
    combined_upgrade_command:
      "sudo apt-get update && sudo apt-get install --only-upgrade curl",
    gaps: [item()],
    ...overrides,
  };
}

function wrapper(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("DevicePatchGapCard", () => {
  it("shows the command an operator is meant to run", () => {
    wrapper(<DevicePatchGapCard gap={deviceGap()} />);
    expect(
      screen.getAllByText(/apt-get install --only-upgrade curl/).length,
    ).toBeGreaterThan(0);
  });

  it("shows the upgrade as a version step", () => {
    wrapper(<DevicePatchGapCard gap={deviceGap()} />);
    expect(screen.getByText("7.68.0-1ubuntu2.20")).toBeInTheDocument();
  });

  it("says so rather than naming a target when the fixes could not be ordered", () => {
    // Naming one would promise a fix that may not close every CVE listed.
    wrapper(
      <DevicePatchGapCard
        gap={deviceGap({
          gaps: [item({ target_version: null, upgrade_command: null })],
          combined_upgrade_command: null,
        })}
      />,
    );
    expect(screen.getByText(/target unresolved/i)).toBeInTheDocument();
    expect(screen.queryByText(/apt-get install/)).not.toBeInTheDocument();
  });

  it("reports findings with no published fix separately from the upgrade", () => {
    wrapper(<DevicePatchGapCard gap={deviceGap({ unfixed_findings: 3 })} />);
    expect(screen.getByText(/no published fix/i)).toBeInTheDocument();
  });

  it("renders nothing at all when there is nothing outstanding", () => {
    const { container } = wrapper(
      <DevicePatchGapCard
        gap={deviceGap({ packages_to_upgrade: 0, unfixed_findings: 0, gaps: [] })}
      />,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("PatchGapPanel", () => {
  beforeEach(() => vi.restoreAllMocks());

  function tenantGap(overrides: Partial<TenantPatchGap> = {}): TenantPatchGap {
    return {
      tenant_id: "default",
      devices_with_gaps: 1,
      packages_to_upgrade: 4,
      cves_closed_by_upgrade: 9,
      unfixed_findings: 0,
      devices: [
        {
          device_id: "dev_1",
          hostname: "workstation-01.example.test",
          packages_to_upgrade: 4,
          cves_closed_by_upgrade: 9,
          unfixed_findings: 0,
          worst_severity: "critical",
        },
      ],
      truncated: false,
      ...overrides,
    };
  }

  it("summarises the estate and lists the worst hosts", async () => {
    vi.spyOn(apiModule, "fetchPatchGaps").mockResolvedValue(tenantGap());
    wrapper(<PatchGapPanel />);
    expect(await screen.findByText("workstation-01.example.test")).toBeInTheDocument();
    expect(screen.getByText("4")).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
  });

  it("stays out of the way when the estate is clean", async () => {
    vi.spyOn(apiModule, "fetchPatchGaps").mockResolvedValue(
      tenantGap({
        devices_with_gaps: 0,
        packages_to_upgrade: 0,
        cves_closed_by_upgrade: 0,
        devices: [],
      }),
    );
    const { container } = wrapper(<PatchGapPanel />);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(container).toBeEmptyDOMElement();
  });

  it("says the list is capped so the totals are not misread", async () => {
    vi.spyOn(apiModule, "fetchPatchGaps").mockResolvedValue(tenantGap({ truncated: true }));
    wrapper(<PatchGapPanel />);
    expect(await screen.findByText(/totals cover the whole tenant/i)).toBeInTheDocument();
  });
});
