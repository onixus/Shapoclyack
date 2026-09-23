import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SessionExpiryBanner } from "@/components/session-expiry-banner";
import { refreshAccessToken, setAccessToken } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { noteActivity } from "@/lib/session";
import type { Me } from "@/lib/api";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace }) }));

// The network half of silent refresh is covered in api.test.ts; here only
// *whether* the banner asks for one matters.
vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  refreshAccessToken: vi.fn(async () => null),
}));

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

/** A token shaped like the API's, carrying the claims the banner reads.
 *
 * `issuedAgoMs` decides whether the user counts as active: activity is noted
 * at "now" at most, so a token issued in the future was issued after the last
 * thing the user did — an idle console. */
function tokenExpiringIn(ms: number, issuedAgoMs = -60 * 60 * 1000): string {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value))
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const exp = Math.floor((Date.now() + ms) / 1000);
  const iat = Math.floor((Date.now() - issuedAgoMs) / 1000);
  return `${encode({ alg: "HS256" })}.${encode({ sub: "operator", exp, iat })}.signature`;
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

const refresh = vi.mocked(refreshAccessToken);

describe("SessionExpiryBanner", () => {
  beforeEach(() => {
    installLocalStorage();
    replace.mockClear();
    refresh.mockClear();
    refresh.mockImplementation(async () => null);
    useAuthStore.setState({ user: null });
  });

  it("says nothing while the session has hours left", () => {
    signIn();
    setAccessToken(tokenExpiringIn(60 * 60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(refresh).not.toHaveBeenCalled();
  });

  it("renews silently, with no banner, for a user who is at the console", async () => {
    signIn();
    setAccessToken(tokenExpiringIn(2 * 60 * 1000, 13 * 60 * 1000));
    noteActivity(Date.now());
    render(<SessionExpiryBanner />);
    await waitFor(() => expect(refresh).toHaveBeenCalledOnce());
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("warns an idle console in the last five minutes instead of renewing it", async () => {
    signIn();
    setAccessToken(tokenExpiringIn(2 * 60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.getByRole("status")).toHaveTextContent("ends in 2 min");
    expect(refresh).not.toHaveBeenCalled();

    // The button is the user coming back: it renews, and the banner goes.
    refresh.mockImplementation(async () => {
      setAccessToken(tokenExpiringIn(15 * 60 * 1000, 0));
      return "renewed";
    });
    await userEvent.click(screen.getByRole("button", { name: "Stay signed in" }));
    await waitFor(() => expect(screen.queryByRole("status")).not.toBeInTheDocument());
    expect(replace).not.toHaveBeenCalled();
  });

  it("stays once the session has actually expired", async () => {
    // The defect this guards: at zero the banner disappeared, so the console
    // looked normal until the next request answered 401 and redirected — with
    // whatever was in an open form.
    signIn();
    setAccessToken(tokenExpiringIn(-60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.getByRole("status")).toHaveTextContent("Your session has ended");

    // The refresh is tried first and refused, so this really is the end.
    const logout = vi.fn(async () => "already-ended" as const);
    useAuthStore.setState({ logout });
    await userEvent.click(screen.getByRole("button", { name: "Sign in again" }));
    expect(refresh).toHaveBeenCalledOnce();
    expect(logout).toHaveBeenCalledOnce();
    expect(replace).toHaveBeenCalledWith("/login");
  });

  it("shows nothing to a console nobody is signed in to", () => {
    setAccessToken(tokenExpiringIn(-60 * 1000));
    render(<SessionExpiryBanner />);
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});
