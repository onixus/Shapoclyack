import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SessionExpiryBanner } from "@/components/session-expiry-banner";
import { setAccessToken } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import type { Me } from "@/lib/api";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }));

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

/** A token shaped like the API's, carrying only the claim the banner reads. */
function tokenExpiringIn(ms: number): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const exp = Math.floor((Date.now() + ms) / 1000);
  return `${encode({ alg: "HS256" })}.${encode({ sub: "operator", exp })}.signature`;
}

function signIn() {
  useAuthStore.setState({
    user: {
      username: "operator",
      role: "operator",
      tenants: [],
      default_tenant: "default",
      is_platform_admin: false,
    } as Me,
    hydrated: true,
    loading: false,
  });
}

describe("SessionExpiryBanner", () => {
  beforeEach(() => {
    installLocalStorage();
    replace.mockClear();
    useAuthStore.setState({ user: null });
  });

  it("says nothing while the session has hours left", () => {
    signIn();
    setAccessToken(tokenExpiringIn(60 * 60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("warns in the last five minutes", () => {
    signIn();
    setAccessToken(tokenExpiringIn(2 * 60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.getByRole("status")).toHaveTextContent("ends in 2 min");
  });

  it("stays once the session has actually expired", async () => {
    // The defect this guards: at zero the banner disappeared, so the console
    // looked normal until the next request answered 401 and redirected — with
    // whatever was in an open form.
    signIn();
    setAccessToken(tokenExpiringIn(-60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.getByRole("status")).toHaveTextContent("Your session has ended");

    const logout = vi.fn(async () => "already-ended" as const);
    useAuthStore.setState({ logout });
    await userEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    expect(logout).toHaveBeenCalledOnce();
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("shows nothing to a console nobody is signed in to", () => {
    setAccessToken(tokenExpiringIn(-60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
