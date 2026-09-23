import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AssetServicesPanel } from "@/components/asset/asset-services-panel";
import * as apiModule from "@/lib/api";
import type { AssetServiceInfo } from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";

/** Shape of `asset_services.to_dict` (api/services/asset_services.py). */
function service(overrides: Partial<AssetServiceInfo> = {}): AssetServiceInfo {
  return {
    id: 1,
    asset_id: "ast_1",
    host: "10.0.0.5",
    port: 22,
    protocol: "tcp",
    service: "ssh",
    product: "OpenSSH",
    version: "7.4",
    banner: "SSH-2.0-OpenSSH_7.4",
    cpe: ["cpe:/a:openbsd:openssh:7.4"],
    source: "scan",
    first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-20T00:00:00Z",
    last_run_id: "run-1",
    fingerprint_changed_at: "2026-09-01T00:00:00Z",
    matched_dataset_version: "2026-09-20:3f2a9c1b0d4e5f60+adv:9c1d2e3f",
    matched_at: "2026-09-21T00:00:00Z",
    match_status: "matched",
    match_counts: { vulnerable: 4, fixed: 0, not_affected: 0, possible: 0 },
    possible_cves: [],
    ...overrides,
  };
}

// An Apache build on Debian the advisory seed does not cover: NVD says the
// upstream version is affected, but a backport may have fixed it.
const APACHE = service({
  id: 2,
  port: 80,
  service: "http",
  product: "Apache httpd",
  version: "2.4.25",
  banner: "Apache/2.4.25 (Debian)",
  cpe: ["cpe:/a:apache:http_server:2.4.25"],
  match_counts: { vulnerable: 0, fixed: 0, not_affected: 0, possible: 5 },
  possible_cves: [
    { cve: "CVE-2021-44790", severity: "critical", cvss: 9.8, reason: "unsupported_distro" },
    { cve: "CVE-2019-0211", severity: "high", cvss: 7.8, reason: "unsupported_distro" },
  ],
});

// A listener the matcher could not ask about: the scan named no version.
const NO_VERSION = service({
  id: 3,
  port: 8443,
  service: "https",
  product: "",
  version: "",
  banner: "",
  cpe: [],
  match_status: "no_version",
  match_counts: {},
  possible_cves: [],
});

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AssetServicesPanel assetId="ast_1" tenantId="default" />
    </QueryClientProvider>,
  );
}

function rowOf(port: string): HTMLElement {
  const row = screen.getByText(port).closest("tr");
  expect(row).not.toBeNull();
  return row as HTMLElement;
}

describe("AssetServicesPanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAppearanceStore.setState({ locale: "en" });
  });

  it("lists each listener with its fingerprint and retro counts", async () => {
    const fetchSpy = vi
      .spyOn(apiModule, "fetchAssetServices")
      .mockResolvedValue([service(), APACHE]);
    renderPanel();

    expect(await screen.findByText("22/tcp")).toBeInTheDocument();
    expect(fetchSpy).toHaveBeenCalledWith("ast_1", "default");
    const ssh = rowOf("22/tcp");
    expect(within(ssh).getByText("OpenSSH 7.4")).toBeInTheDocument();
    expect(within(ssh).getByText("cpe:/a:openbsd:openssh:7.4")).toBeInTheDocument();
    expect(within(ssh).getByText("assessed")).toBeInTheDocument();
    expect(within(ssh).getByText("4")).toBeInTheDocument();
  });

  it("keeps possible CVEs collapsed and apart from tracked ones", async () => {
    vi.spyOn(apiModule, "fetchAssetServices").mockResolvedValue([APACHE]);
    renderPanel();

    await screen.findByText("80/tcp");
    const apache = rowOf("80/tcp");
    expect(within(apache).getByText("5")).toBeInTheDocument();
    const summary = within(apache).getByText(/Possible, not tracked/);
    fireEvent.click(summary);
    expect(within(apache).getByText("CVE-2021-44790")).toBeInTheDocument();
    expect(within(apache).getByText("CVE-2019-0211")).toBeInTheDocument();
  });

  it("says why a listener was not assessed instead of showing it as clean", async () => {
    vi.spyOn(apiModule, "fetchAssetServices").mockResolvedValue([NO_VERSION]);
    renderPanel();

    await screen.findByText("8443/tcp");
    const row = rowOf("8443/tcp");
    expect(within(row).getByText("no version")).toBeInTheDocument();
    expect(within(row).getByText(/not the same as clean/)).toBeInTheDocument();
    // No counts on a row nobody could assess: a zero there would read as clean.
    expect(within(row).queryByText(/Vulnerable/)).not.toBeInTheDocument();
  });

  it("marks a listener no sweep has reached yet", async () => {
    vi.spyOn(apiModule, "fetchAssetServices").mockResolvedValue([
      service({ match_status: null, matched_at: null, matched_dataset_version: null, match_counts: {} }),
    ]);
    renderPanel();

    expect(await screen.findByText("not yet matched")).toBeInTheDocument();
    expect(screen.getByText(/Not matched against the current dataset yet/)).toBeInTheDocument();
  });

  it("says nothing is stored yet rather than implying the asset is clean", async () => {
    vi.spyOn(apiModule, "fetchAssetServices").mockResolvedValue([]);
    renderPanel();
    expect(
      await screen.findByText(/No fingerprinted listeners are stored for this asset yet/),
    ).toBeInTheDocument();
  });

  it("renders the Russian labels for an unassessable listener", async () => {
    useAppearanceStore.setState({ locale: "ru" });
    vi.spyOn(apiModule, "fetchAssetServices").mockResolvedValue([
      service({ match_status: "unknown_product", match_counts: {} }),
    ]);
    renderPanel();

    expect(await screen.findByText("неизвестный продукт")).toBeInTheDocument();
    expect(screen.getByText("Порт")).toBeInTheDocument();
  });
});
