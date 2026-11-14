import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import LicensePage from "@/app/(dashboard)/license/page";
import * as apiModule from "@/lib/api";
import type { LicenseStatus, Me } from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";

function license(overrides: Partial<LicenseStatus> = {}): LicenseStatus {
  return {
    installed: true,
    active: true,
    enforcement_enabled: true,
    product_active: true,
    new_scans_allowed: true,
    features: { lariska: true, brand_watch: false },
    license_id: "lic-acme-2026",
    customer_name: "ACME Corp",
    valid_from: "2026-01-01T00:00:00Z",
    expires_at: "2027-01-01T00:00:00Z",
    issued_at: "2025-12-15T12:00:00Z",
    note: "Annual renewal",
    reason: null,
    ...overrides,
  };
}

function signIn(user: Partial<Me> = {}) {
  useAuthStore.setState({
    user: {
      username: "u",
      role: "viewer",
      tenants: ["default"],
      default_tenant: "default",
      is_platform_admin: false,
      permissions: [],
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
      <LicensePage />
    </QueryClientProvider>,
  );
  return queryClient;
}

describe("LicensePage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAppearanceStore.setState({ locale: "en" });
    signIn();
  });

  it("shows customer, term and feature entitlements read-only for a viewer", async () => {
    vi.spyOn(apiModule, "getLicense").mockResolvedValue(license());
    renderPage();

    expect(await screen.findByText("ACME Corp")).toBeInTheDocument();
    expect(screen.getByText("Lariska (endpoint inventory)")).toBeInTheDocument();
    expect(screen.getByText("Brand Watch")).toBeInTheDocument();
    expect(screen.getByText("lic-acme-2026")).toBeInTheDocument();
    expect(screen.getByText(/Uploading needs platform.license.manage/)).toBeInTheDocument();
    expect(screen.queryByText("Activate license")).not.toBeInTheDocument();
  });

  it("banners when the product term is closed", async () => {
    vi.spyOn(apiModule, "getLicense").mockResolvedValue(
      license({
        product_active: false,
        new_scans_allowed: false,
        reason: "license expired",
        features: { lariska: false, brand_watch: false },
      }),
    );
    renderPage();

    expect(await screen.findByRole("status")).toHaveTextContent("license expired");
    expect(screen.getByText("Inactive")).toBeInTheDocument();
    expect(screen.getByText("Blocked")).toBeInTheDocument();
  });

  it("lets a platform admin upload a license file", async () => {
    vi.spyOn(apiModule, "getLicense").mockResolvedValue(license({ installed: false, customer_name: null }));
    const upload = vi.spyOn(apiModule, "uploadLicense").mockResolvedValue(license());
    signIn({
      role: "admin",
      is_platform_admin: true,
      permissions: ["platform.license.manage"],
    });
    renderPage();

    expect(await screen.findByText("Drop a license file here, or click to choose")).toBeInTheDocument();

    const input = document.getElementById("license-file") as HTMLInputElement;
    const file = new File(['{"license_id":"x"}'], "acme.lic", { type: "application/json" });
    await userEvent.upload(input, file);

    await userEvent.click(screen.getByRole("button", { name: "Activate license" }));
    await waitFor(() => expect(upload).toHaveBeenCalledWith(file));
  });
});
