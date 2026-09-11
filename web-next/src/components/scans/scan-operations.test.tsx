import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanOperations } from "@/components/scans/scan-operations";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams(),
}));

function member(role: string, permissions: string[]): Me {
  return {
    username: "on-call",
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: role,
    permissions,
    scoped_tenant: "default",
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ScanOperations surface={null} />
    </QueryClientProvider>,
  );
}

const DENIED = /role privileges required/i;

describe("ScanOperations access", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, canOperate: false });
  });

  it("keeps the page shut for a viewer", () => {
    useAuthStore.setState({ user: member("viewer", []), canOperate: false });
    renderPage();
    expect(screen.getByText(DENIED)).toBeInTheDocument();
  });

  it("opens for a scan-operator, whose global role is viewer", () => {
    // The API gates `GET /api/jobs` on the operator rank *in the tenant*, which
    // a `scan-operator` has (#318); the console gated it on the global role and
    // so hid the whole page — and with it the Cancel button docs/ui.md promises
    // — from the role the permission exists for.
    useAuthStore.setState({
      user: member("scan-operator", ["scan.cancel"]),
      canOperate: false,
    });
    renderPage();
    expect(screen.queryByText(DENIED)).not.toBeInTheDocument();
  });
});
