import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MfaPendingBanner } from "@/components/mfa/mfa-pending-banner";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

let pathname = "/";
const push = vi.fn();
vi.mock("next/navigation", () => ({
  usePathname: () => pathname,
  useRouter: () => ({ push }),
}));

function signIn(user: Partial<Me>) {
  useAuthStore.setState({
    user: {
      username: "admin",
      role: "admin",
      tenants: [],
      default_tenant: "default",
      is_platform_admin: true,
      ...user,
    },
    hydrated: true,
    loading: false,
  });
}

beforeEach(() => {
  pathname = "/";
  push.mockClear();
});

describe("MfaPendingBanner", () => {
  it("explains the confinement and offers the one route that works", () => {
    signIn({ mfa_pending: true });
    render(<MfaPendingBanner />);
    expect(screen.getByRole("alert")).toHaveTextContent(/requires a second factor for your role/i);
    screen.getByRole("button", { name: /set it up/i }).click();
    expect(push).toHaveBeenCalledWith("/security");
  });

  it("says nothing to a session that owes nothing", () => {
    signIn({ mfa_pending: false });
    render(<MfaPendingBanner />);
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("gets out of the way on the page it points at", () => {
    pathname = "/security";
    signIn({ mfa_pending: true });
    render(<MfaPendingBanner />);
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
