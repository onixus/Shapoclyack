import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import RetentionPage from "@/app/(dashboard)/retention/page";
import * as apiModule from "@/lib/api";
import type { LegalHold, Me, RetentionCategory, RetentionPolicy } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function category(overrides: Partial<RetentionCategory>): RetentionCategory {
  return {
    category: "runs",
    description: "Scan run artifacts",
    default_days: 30,
    override_days: null,
    effective_days: 30,
    min_days: 1,
    max_days: 365,
    source: "default",
    ...overrides,
  };
}

/** What `GET /tenants/{id}/retention` answers: every category, inherited or not. */
function policy(overrides: Partial<RetentionPolicy> = {}): RetentionPolicy {
  return {
    tenant_id: "acme",
    categories: [
      category({ category: "runs" }),
      category({
        category: "audit_events",
        description: "Administrative audit trail",
        default_days: 365,
        effective_days: 365,
        min_days: 365,
        max_days: 3650,
      }),
      category({
        category: "screenshots",
        description: "Screenshot images",
        default_days: 14,
        override_days: 7,
        effective_days: 7,
        max_days: 90,
        source: "tenant",
      }),
    ],
    note: "",
    updated_at: null,
    updated_by: "",
    legal_hold: null,
    ...overrides,
  };
}

const HOLD: LegalHold = {
  tenant_id: "acme",
  reason: "Preservation order, matter 2026-17",
  set_by: "root",
  set_at: "2026-09-20T10:00:00Z",
};

const TENANT_ADMIN = ["tenant.retention.read", "tenant.retention.manage"];

function signIn(user: Partial<Me> = {}) {
  useAuthStore.setState({
    user: {
      username: "ada",
      role: "viewer",
      tenants: ["acme"],
      default_tenant: "acme",
      is_platform_admin: false,
      permissions: [],
      ...user,
    },
    activeTenant: "acme",
    hydrated: true,
    loading: false,
  });
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={queryClient}>
      <RetentionPage />
    </QueryClientProvider>,
  );
}

describe("RetentionPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, activeTenant: null });
  });

  it("lets a tenant admin set a window and sends the whole document", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy());
    const put = vi.spyOn(apiModule, "updateRetentionPolicy").mockResolvedValue(policy());
    signIn({ tenant_role: "admin", permissions: TENANT_ADMIN });
    renderPage();

    const runs = await screen.findByLabelText("Days for Scan runs");
    expect(screen.getByText("Not on legal hold.")).toBeInTheDocument();
    // The hold is the platform's, and so is the personal-data panel.
    expect(screen.queryByRole("button", { name: "Place legal hold" })).not.toBeInTheDocument();
    expect(screen.queryByText("Personal data requests")).not.toBeInTheDocument();

    await userEvent.type(runs, "90");
    await userEvent.type(screen.getByLabelText("Note"), "DPA annex 2");
    await userEvent.click(screen.getByRole("button", { name: "Save windows" }));

    // Whole-document: the untouched override is sent as it stands and the
    // inherited category as null, so nothing the admin did not touch moves.
    expect(put).toHaveBeenCalledWith("acme", {
      overrides: { runs: 90, audit_events: null, screenshots: 7 },
      note: "DPA annex 2",
    });
  });

  it("shows the audit floor before the API refuses it", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy());
    const put = vi.spyOn(apiModule, "updateRetentionPolicy");
    signIn({ tenant_role: "admin", permissions: TENANT_ADMIN });
    renderPage();

    const audit = await screen.findByLabelText("Days for Audit trail");
    await userEvent.type(audit, "30");

    expect(screen.getByRole("alert")).toHaveTextContent("Between 365 and 3650 days");
    expect(screen.getByRole("button", { name: "Save windows" })).toBeDisabled();
    expect(put).not.toHaveBeenCalled();
  });

  it("shows an auditor the windows and nothing to edit", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy());
    signIn({ tenant_role: "auditor", permissions: ["tenant.retention.read"] });
    renderPage();

    const row = (await screen.findByText("Screenshots")).closest("tr") as HTMLElement;
    expect(within(row).getAllByText("7 days")).toHaveLength(2);
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save windows" })).not.toBeInTheDocument();
  });

  it("does not ask for a policy the caller may not read", async () => {
    const fetchSpy = vi.spyOn(apiModule, "fetchRetentionPolicy");
    signIn({ tenant_role: "viewer", permissions: [] });
    renderPage();

    expect(await screen.findByText(/tenant\.retention\.read/)).toBeInTheDocument();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("tells a tenant that it is held and since when, not why", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(
      policy({ legal_hold: { ...HOLD, reason: null, set_by: null } }),
    );
    signIn({ tenant_role: "admin", permissions: TENANT_ADMIN });
    renderPage();

    const banner = await screen.findByText(/On legal hold since/);
    expect(banner).toBeInTheDocument();
    expect(screen.queryByText(/matter 2026-17/)).not.toBeInTheDocument();
    expect(screen.getByText(/for platform administrators/)).toBeInTheDocument();
  });

  it("lets a platform admin release a hold, after saying what happens next", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy({ legal_hold: HOLD }));
    const release = vi.spyOn(apiModule, "releaseLegalHold").mockResolvedValue(undefined);
    signIn({ role: "admin", is_platform_admin: true, permissions: TENANT_ADMIN, username: "root" });
    renderPage();

    expect(await screen.findByText(/matter 2026-17 — placed by root/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Release hold" }));
    expect(await screen.findByText(/delete everything the hold kept/)).toBeInTheDocument();
    expect(release).not.toHaveBeenCalled();
    const dialog = screen.getByRole("alertdialog");
    await userEvent.click(within(dialog).getByRole("button", { name: "Release hold" }));
    expect(release).toHaveBeenCalledWith("acme");
  });

  it("places a hold only with a reason", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy());
    const place = vi.spyOn(apiModule, "placeLegalHold").mockResolvedValue(HOLD);
    signIn({ role: "admin", is_platform_admin: true, permissions: TENANT_ADMIN, username: "root" });
    renderPage();

    const button = await screen.findByRole("button", { name: "Place legal hold" });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason for the hold"), "matter 2026-17");
    await userEvent.click(button);
    expect(place).toHaveBeenCalledWith("acme", "matter 2026-17");
  });

  it("exports and erases an account, the erasure only once the name is typed", async () => {
    vi.spyOn(apiModule, "fetchRetentionPolicy").mockResolvedValue(policy());
    const exportSpy = vi.spyOn(apiModule, "downloadUserDataExport").mockResolvedValue(undefined);
    const erase = vi.spyOn(apiModule, "eraseUser").mockResolvedValue({
      username: "dana",
      erased_at: "2026-09-24T10:00:00Z",
      already_erased: false,
      removed: { email: true },
    });
    signIn({ role: "admin", is_platform_admin: true, permissions: TENANT_ADMIN, username: "root" });
    renderPage();

    const box = await screen.findByLabelText("Username");
    // Not one's own account: the API refuses it, so the button does too.
    await userEvent.type(box, "root");
    expect(screen.getByRole("button", { name: "Erase account" })).toBeDisabled();
    await userEvent.clear(box);
    await userEvent.type(box, "dana");

    await userEvent.click(screen.getByRole("button", { name: "Export data (JSON)" }));
    expect(exportSpy).toHaveBeenCalledWith("dana");

    await userEvent.click(screen.getByRole("button", { name: "Erase account" }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Erase account" });
    expect(confirm).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText("Type dana to confirm"), "dana");
    await userEvent.click(confirm);
    expect(erase).toHaveBeenCalledWith("dana");
    expect(await screen.findByText("dana was erased.")).toBeInTheDocument();
  });
});
