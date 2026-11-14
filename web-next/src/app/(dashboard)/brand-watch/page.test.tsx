import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import BrandWatchPage from "@/app/(dashboard)/brand-watch/page";
import type { Me } from "@/lib/api";
import { api } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;

function member(permissions: string[]): Me {
  return {
    username: "acme",
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: "operator",
    permissions,
    scoped_tenant: "default",
  };
}

function profile(overrides: Record<string, unknown> = {}) {
  return {
    id: "bwp_1",
    name: "Acme",
    approved: false,
    our_brand: false,
    official_domains: ["acme.test"],
    brand_strings: ["acme"],
    ...overrides,
  };
}

function renderPage() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <BrandWatchPage />
    </QueryClientProvider>,
  );
}

function signIn(permissions: string[]) {
  useAuthStore.setState({
    user: member(permissions),
    canOperate: true,
    hydrated: true,
    loading: false,
    activeTenant: "default",
  });
}

describe("BrandWatchPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    signIn(["brand_watch.read"]);
    vi.spyOn(api, "get").mockImplementation(async (url: string) => {
      if (url === "/brand-watch/profiles") return { data: [profile()] };
      if (url === "/brand-watch/diff") return { data: [] };
      return { data: [] };
    });
  });

  it("hides the create form and the approve control from a reader", async () => {
    renderPage();
    expect(await screen.findByText("Acme")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save profile" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getByText("Not approved")).toBeInTheDocument();
  });

  it("saves a profile as not ours and does not imply a scan starts", async () => {
    signIn(["brand_watch.read", "brand_watch.write"]);
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: profile({ id: "bwp_2", name: "New" }) });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByRole("button", { name: "Save profile" })).toBeDisabled();
    expect(screen.getByText(/does not start a scan/i)).toBeInTheDocument();
    post.mockImplementation(async (url: string) => {
      if (url === "/brand-watch/preview") {
        return { data: { names: [{ name: "login-new.test", rule: "combosquat" }] } };
      }
      return { data: profile({ id: "bwp_2", name: "New" }) };
    });
    await user.type(screen.getByLabelText("Name"), "New");
    await user.type(screen.getByLabelText("Official domains"), "new.test");
    await user.click(screen.getByRole("button", { name: "Build lookalike list" }));
    expect(await screen.findByLabelText("Names to watch")).toHaveValue("login-new.test");
    await user.clear(screen.getByLabelText("Official domains"));
    expect(screen.getByLabelText("Names to watch")).toHaveValue("");
    await user.type(screen.getByLabelText("Official domains"), "new.test");
    await user.click(screen.getByRole("button", { name: "Build lookalike list" }));
    expect(await screen.findByLabelText("Names to watch")).toHaveValue("login-new.test");
    await user.type(screen.getByLabelText("Names to watch"), "\nextra-new.test");
    await user.click(screen.getByRole("button", { name: "Save profile" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/brand-watch/profiles", {
        name: "New",
        official_domains: ["new.test"],
        watched_names: ["login-new.test", "extra-new.test"],
        our_brand: false,
      }),
    );
  });

  it("approves only after the operator confirms the domains are theirs", async () => {
    signIn(["brand_watch.read", "brand_watch.write"]);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: profile({ approved: true, our_brand: true }),
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Approve" }));
    expect(screen.getByText(/this tenant's own domains/i)).toBeInTheDocument();
    expect(post).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "These are our domains" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/brand-watch/profiles/bwp_1/approve", { our_brand: true }),
    );
  });

  it("opens one profile's candidates and says names wait for the daily rebuild", async () => {
    const get = vi.spyOn(api, "get").mockImplementation(async (url: string) => {
      if (url === "/brand-watch/profiles") return { data: [profile()] };
      if (url === "/brand-watch/profiles/bwp_1/candidates") return { data: [] };
      return { data: [] };
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Acme" }));
    expect(await screen.findByText(/after the daily rebuild, not after a scan/i)).toBeInTheDocument();
    expect(get).toHaveBeenCalledWith("/brand-watch/profiles/bwp_1/candidates");
  });

  it("sets a candidate disposition without waiting for a diff row", async () => {
    signIn(["brand_watch.read", "brand_watch.disposition"]);
    vi.spyOn(api, "get").mockImplementation(async (url: string) => {
      if (url === "/brand-watch/profiles") return { data: [profile({ approved: true })] };
      if (url === "/brand-watch/profiles/bwp_1/candidates") {
        return {
          data: [
            {
              id: "bwc_1",
              name_unicode: "examp1e.com",
              name_punycode: "examp1e.com",
              state: "registered",
              disposition: "open",
            },
          ],
        };
      }
      return { data: [] };
    });
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: { id: "bwc_1", disposition: "confirmed" } });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Acme" }));
    expect(await screen.findByText("examp1e.com")).toBeInTheDocument();
    expect(screen.getByText("registered")).toBeInTheDocument();
    const picker = screen.getByRole("combobox", { name: "Disposition" });
    await user.click(picker);
    await user.click(await screen.findByRole("option", { name: "Confirmed" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/brand-watch/candidates/bwc_1/disposition", {
        disposition: "confirmed",
      }),
    );
    expect(within(picker).getByText("Open")).toBeInTheDocument();
  });
});
