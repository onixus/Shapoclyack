import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SsoSignInButton } from "@/components/sso-sign-in-button";
import { api } from "@/lib/api";

describe("SsoSignInButton", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when the API reports SSO is off", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: { enabled: false, login_url: "/api/auth/oidc/login" },
    });
    const { container } = render(<SsoSignInButton />);
    await waitFor(() => expect(api.get).toHaveBeenCalledWith("/auth/sso"));
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the status call fails, so password login still works", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("older API"));
    const { container } = render(<SsoSignInButton />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("offers the button and navigates to the provider when SSO is enabled", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: { enabled: true, login_url: "/api/auth/oidc/login" },
    });
    // jsdom refuses a real navigation; replace the accessor to observe it.
    const assigned: string[] = [];
    Object.defineProperty(window, "location", {
      configurable: true,
      value: {
        pathname: "/login",
        hash: "",
        set href(value: string) {
          assigned.push(value);
        },
        get href() {
          return assigned[assigned.length - 1] ?? "/login";
        },
      },
    });

    render(<SsoSignInButton />);
    const button = await screen.findByRole("button", { name: "Sign in with SSO" });
    await userEvent.click(button);
    expect(assigned).toEqual(["/api/auth/oidc/login"]);
  });

  it("offers SAML as a redirect and LDAP as a form provider", async () => {
    const onLdap = vi.fn();
    render(
      <SsoSignInButton
        onLdap={onLdap}
        status={{
          enabled: true,
          login_url: "/api/auth/oidc/login",
          local_login: "enabled",
          providers: [
            { provider: "saml", login_url: "/api/auth/saml/login" },
            { provider: "ldap", login_url: "/api/auth/ldap/login" },
          ],
        }}
      />,
    );

    expect(screen.getByRole("button", { name: "Sign in with SAML" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Sign in with LDAP / Active Directory" }));
    expect(onLdap).toHaveBeenCalledOnce();
  });
});
