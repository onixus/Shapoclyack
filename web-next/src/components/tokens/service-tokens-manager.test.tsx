import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ServiceTokensManager } from "@/components/tokens/service-tokens-manager";
import * as api from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    fetchServiceTokens: vi.fn(),
    fetchAvailableScopes: vi.fn(),
    createServiceToken: vi.fn(),
    revokeServiceToken: vi.fn(),
  };
});

describe("ServiceTokensManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAppearanceStore.setState({ theme: "dark", locale: "en", hydrated: true });
    vi.mocked(api.fetchAvailableScopes).mockResolvedValue(["scans:read", "scans:write", "assets:read"]);
    vi.mocked(api.fetchServiceTokens).mockResolvedValue([
      {
        id: "tok_12345",
        name: "Test CI Token",
        key_prefix: "abcd1234",
        tenant_id: "default",
        role: "operator",
        scopes: ["scans:read", "scans:write"],
        created_at: "2026-08-30T12:00:00Z",
        created_by: "admin",
        expires_at: null,
        last_used_at: null,
        revoked_at: null,
        is_active: true,
      },
    ]);
  });

  it("renders service tokens table with listed tokens", async () => {
    render(<ServiceTokensManager />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("Test CI Token")).toBeInTheDocument();
    });

    expect(screen.getByText("shk_abcd1234_••••")).toBeInTheDocument();
    expect(screen.getByText("operator")).toBeInTheDocument();
    expect(screen.getByText("Active")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeInTheDocument();
  });

  it("opens modal and creates a new token", async () => {
    const user = userEvent.setup();
    vi.mocked(api.createServiceToken).mockResolvedValue({
      id: "tok_67890",
      name: "New Webhook Token",
      key_prefix: "ef012345",
      tenant_id: "default",
      role: "viewer",
      scopes: ["scans:read"],
      created_at: "2026-08-31T10:00:00Z",
      created_by: "operator",
      expires_at: null,
      last_used_at: null,
      revoked_at: null,
      is_active: true,
      token: "shk_ef012345_supersecretstringvaluehere12345",
    });

    render(<ServiceTokensManager />);

    await waitFor(() => {
      expect(screen.getByText("Test CI Token")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "Generate Token" }));
    expect(screen.getByPlaceholderText("e.g. GitHub Actions CI Token")).toBeInTheDocument();

    await user.type(screen.getByPlaceholderText("e.g. GitHub Actions CI Token"), "New Webhook Token");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => {
      expect(screen.getByText("Token Generated Successfully")).toBeInTheDocument();
      expect(screen.getByText("shk_ef012345_supersecretstringvaluehere12345")).toBeInTheDocument();
    });
  });
});
