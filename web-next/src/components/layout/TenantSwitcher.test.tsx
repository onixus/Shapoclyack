import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it } from "vitest";
import { TenantSwitcher } from "@/components/layout/TenantSwitcher";
import { getActiveTenant } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import type { Me } from "@/lib/api";

/** jsdom in this setup exposes no Storage implementation, so stand one up. */
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
    activeTenant: null,
    hydrated: true,
    loading: false,
  });
}

function renderSwitcher() {
  const queryClient = new QueryClient();
  render(
    <QueryClientProvider client={queryClient}>
      <TenantSwitcher />
    </QueryClientProvider>,
  );
  return queryClient;
}

describe("TenantSwitcher", () => {
  beforeEach(() => {
    installLocalStorage();
    useAuthStore.setState({ user: null, activeTenant: null });
  });

  it("shows a plain chip when the user has a single tenant to act in", () => {
    signIn({ tenants: ["ten_a"], default_tenant: "ten_a" });
    renderSwitcher();
    expect(screen.getByText("ten_a")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("offers the fleet-wide view plus every tenant to a platform admin", async () => {
    signIn({ role: "admin", is_platform_admin: true, tenants: ["ten_a", "ten_b"] });
    renderSwitcher();

    // Unscoped by default — the pre-P0 fleet-wide view.
    expect(screen.getByText("All tenants")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button"));
    for (const label of ["All tenants", "ten_a", "ten_b"]) {
      expect(screen.getAllByText(label).length).toBeGreaterThan(0);
    }
  });

  it("persists the picked tenant and drops the cache fetched in the old scope", async () => {
    signIn({ role: "admin", is_platform_admin: true, tenants: ["ten_a", "ten_b"] });
    const queryClient = renderSwitcher();
    queryClient.setQueryData(["assets"], [{ asset_id: "from-previous-tenant" }]);

    await userEvent.click(screen.getByRole("button"));
    await userEvent.click(screen.getByText("ten_b"));

    expect(useAuthStore.getState().activeTenant).toBe("ten_b");
    expect(getActiveTenant()).toBe("ten_b");
    expect(queryClient.getQueryData(["assets"])).toBeUndefined();
  });

  it("falls back to sane defaults when the API predates tenant context", () => {
    // /auth/me on an older API answers with username+role only.
    useAuthStore.setState({
      user: { username: "viewer", role: "viewer" } as Me,
      activeTenant: null,
    });
    renderSwitcher();
    expect(screen.getByText("default")).toBeInTheDocument();
  });
});
