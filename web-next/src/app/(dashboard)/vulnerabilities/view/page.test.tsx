import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import VulnerabilityDetailPage from "@/app/(dashboard)/vulnerabilities/view/page";
import * as apiModule from "@/lib/api";
import type { Me, TrackedVulnerability } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

const searchParams = new URLSearchParams({ vulnId: "vln_1", tenantId: "default" });

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParams,
}));

function vuln(overrides: Partial<TrackedVulnerability> = {}): TrackedVulnerability {
  return {
    vuln_id: "vln_1",
    tenant_id: "default",
    asset_id: "ast_1",
    finding_key: "k1",
    source: "scan",
    device_id: null,
    cve: "CVE-2024-0001",
    cwe: [],
    script_id: null,
    title: "",
    port: "443",
    severity: "critical",
    risk_level: "very_high",
    contextual_score: 9.1,
    cvss: 9.8,
    in_kev: false,
    exploit_maturity: null,
    network_exposure: "external",
    network_exposure_source: null,
    state: "PLANNED",
    state_changed_at: null,
    state_changed_by: null,
    assignee: null,
    owner_team: null,
    due_at: "2026-10-01T00:00:00Z",
    sla_days: 15,
    sla_source: "default",
    sla_state: "on_track",
    exception_until: null,
    exception_reason: null,
    exception_by: null,
    exception_state: "none",
    exception_requested_by: null,
    exception_requested_at: null,
    exception_requested_until: null,
    exception_decided_by: null,
    exception_decided_at: null,
    exception_decision_note: null,
    exception_requested_reason: null,
    exception_approved_at: null,
    exception_approved_requested_by: null,
    exception_expired_at: null,
    first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-01T00:00:00Z",
    sla_started_at: "2026-09-01T00:00:00Z",
    first_seen_run_id: null,
    last_seen_run_id: null,
    observation_count: 1,
    reopen_count: 0,
    closed_at: null,
    ticket_system: null,
    ticket_key: null,
    ticket_url: null,
    ...overrides,
  };
}

/** A signed-in principal. `role` is the *global* one — a `risk-approver` is a
 * plain viewer there, which is exactly what the panel used to gate on. */
function signIn(overrides: Partial<Me>) {
  const user: Me = {
    username: "alice",
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    ...overrides,
  };
  useAuthStore.setState({
    user,
    loading: false,
    hydrated: true,
    canOperate: canOperateIn(user),
    activeTenant: "default",
  });
}

function renderPage(finding: TrackedVulnerability) {
  vi.spyOn(apiModule, "fetchTrackedVulnerability").mockResolvedValue(finding);
  vi.spyOn(apiModule, "fetchVulnerabilityEvents").mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 50,
    has_more: false,
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VulnerabilityDetailPage />
    </QueryClientProvider>,
  );
}

const PENDING = vuln({
  exception_state: "exception_requested",
  exception_requested_by: "alice",
  exception_requested_at: "2026-09-10T00:00:00Z",
  exception_requested_until: "2026-12-01T00:00:00Z",
  exception_requested_reason: "vendor patch lands in Q4",
});

describe("Accepted risk panel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, canOperate: false, hydrated: true, loading: false });
  });

  it("gives Approve to the risk-approver, who is a viewer globally", async () => {
    // The whole point of #348: this account holds the permission inside the
    // tenant and nothing above `viewer` outside it. Gated on the global role,
    // the only person who can answer the request never saw the buttons.
    signIn({
      username: "risk-boss",
      role: "viewer",
      tenant_role: "risk-approver",
      permissions: ["vulnerability.exception.approve"],
      scoped_tenant: "default",
    });
    renderPage(PENDING);

    expect(await screen.findByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reject" })).toBeInTheDocument();
    // Answering is not asking: the approver cannot file requests.
    expect(screen.queryByRole("button", { name: /Request acceptance/ })).not.toBeInTheDocument();
  });

  it("does not offer the requester a decision the API refuses", async () => {
    signIn({
      username: "alice",
      role: "admin",
      tenant_role: "admin",
      permissions: ["vulnerability.exception.request"],
      scoped_tenant: "default",
    });
    renderPage(PENDING);

    expect(await screen.findByRole("button", { name: /Request acceptance/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
    expect(screen.getByText(/needs a second pair of eyes/)).toBeInTheDocument();
  });

  it("says an acceptance has lapsed instead of showing a past date as in force", async () => {
    signIn({
      username: "alice",
      role: "admin",
      tenant_role: "admin",
      permissions: [],
      scoped_tenant: "default",
    });
    renderPage(
      vuln({
        exception_state: "exception_expired",
        exception_until: "2026-09-01T00:00:00Z",
        exception_reason: "vendor patch in Q4",
        exception_by: "risk-boss",
        exception_approved_requested_by: "alice",
        exception_expired_at: "2026-09-01T00:15:00Z",
        sla_state: "breached",
      }),
    );

    expect(await screen.findByText(/The acceptance lapsed on/)).toBeInTheDocument();
    expect(screen.queryByText(/In force until/)).not.toBeInTheDocument();
  });

  it("keeps the approved window on screen while an extension waits", async () => {
    signIn({
      username: "alice",
      role: "admin",
      tenant_role: "admin",
      permissions: [],
      scoped_tenant: "default",
    });
    renderPage(
      vuln({
        // In force, and more time is being asked for — the two texts are
        // different, and the one on the row is the one that was signed.
        exception_state: "exception_requested",
        exception_until: "2027-01-01T00:00:00Z",
        exception_reason: "vendor patch in Q4",
        exception_by: "risk-boss",
        exception_requested_by: "alice",
        exception_requested_until: "2027-06-01T00:00:00Z",
        exception_requested_reason: "EXTENSION not yet approved",
        sla_state: "accepted",
      }),
    );

    expect(await screen.findByText(/In force until/)).toBeInTheDocument();
    expect(screen.getByText("vendor patch in Q4")).toBeInTheDocument();
    // Twice: on the row, and prefilled into the form that would resubmit it.
    expect(screen.getAllByText("EXTENSION not yet approved").length).toBeGreaterThan(0);
  });

  it("hides the panel from an account that can neither ask nor answer", async () => {
    signIn({ username: "bob", role: "operator", tenant_role: "operator", permissions: [] });
    renderPage(PENDING);

    expect(await screen.findByText("Finding")).toBeInTheDocument();
    expect(screen.queryByText("Accepted risk")).not.toBeInTheDocument();
  });

  const EXTENDING = vuln({
    // Signed by somebody else and in force; the requester wants more time.
    exception_state: "exception_requested",
    exception_until: "2027-01-01T00:00:00Z",
    exception_reason: "vendor patch in Q4",
    exception_by: "risk-boss",
    exception_requested_by: "alice",
    exception_requested_until: "2027-06-01T00:00:00Z",
    exception_requested_reason: "EXTENSION not yet approved",
    sla_state: "accepted",
  });

  it("offers the requester their own request back, never the signed acceptance", async () => {
    // The defect. With an extension pending, the only button on this card was
    // "Withdraw", wired to `DELETE /{id}/exception` — so an admin correcting a
    // date destroyed the acceptance a second person had signed, and could not
    // put it back.
    const withdrawRequest = vi
      .spyOn(apiModule, "withdrawVulnerabilityExceptionRequest")
      .mockResolvedValue(EXTENDING);
    const clear = vi.spyOn(apiModule, "clearVulnerabilityException");
    signIn({
      username: "alice",
      role: "viewer",
      tenant_role: "admin",
      permissions: [],
      scoped_tenant: "default",
    });
    renderPage(EXTENDING);

    await userEvent.click(await screen.findByRole("button", { name: "Withdraw request" }));
    await waitFor(() => expect(withdrawRequest).toHaveBeenCalledWith("vln_1"));
    // The acceptance is not this person's to revoke, and no button offers to.
    expect(clear).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: /Revoke acceptance/ })).toBeNull();
  });

  it("asks before revoking, and names what is being destroyed", async () => {
    const clear = vi
      .spyOn(apiModule, "clearVulnerabilityException")
      .mockResolvedValue(EXTENDING);
    signIn({
      username: "risk-boss",
      role: "viewer",
      tenant_role: "risk-approver",
      permissions: ["vulnerability.exception.approve"],
      scoped_tenant: "default",
    });
    renderPage(EXTENDING);

    await userEvent.click(await screen.findByRole("button", { name: "Revoke acceptance" }));
    // The confirmation says whose signature and until when, because after the
    // click the finding is breached and this account is the only way back.
    const warning = screen.getByText(/back under its original deadline/);
    expect(warning).toHaveTextContent("risk-boss");
    expect(clear).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Revoke acceptance" }));
    await waitFor(() => expect(clear).toHaveBeenCalledWith("vln_1"));
  });
});
