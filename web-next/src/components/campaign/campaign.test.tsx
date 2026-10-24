import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CampaignDetail } from "@/components/campaign/campaign-detail";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import * as lib from "@/lib/campaigns";
import type { Campaign, CampaignMember } from "@/lib/campaigns";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
  useRouter: () => ({ replace: vi.fn(), push: vi.fn() }),
  usePathname: () => "/campaigns",
}));

function campaign(overrides: Partial<Campaign> = {}): Campaign {
  return {
    campaign_id: "cmp_1",
    name: "Upgrade openssl",
    description: "Upgrade to 3.0.14 and restart",
    owner: "grace",
    due_at: "2026-11-30T20:59:59Z",
    status: "active",
    status_changed_at: null,
    completed_at: null,
    reopen_count: 1,
    past_due: false,
    composition_hash: "h",
    snapshot_size: 11,
    created_by: "ada",
    created_at: "2026-10-20T00:00:00Z",
    updated_at: "2026-10-20T00:00:00Z",
    progress: {
      total: 11,
      excluded: 1,
      categories: {
        open: 3,
        fixing: 2,
        awaiting_verification: 1,
        verified: 2,
        accepted_risk: 1,
        false_positive: 0,
        closed_unverified: 1,
        unavailable: 1,
      },
      unresolved: 8,
      recurred: 1,
      assets: 5,
      tickets: { linked_findings: 2, distinct_tickets: 1 },
    },
    ...overrides,
  };
}

function member(overrides: Partial<CampaignMember> = {}): CampaignMember {
  return {
    vuln_id: "vln_1",
    status: "included",
    category: "unavailable",
    problem_key: "cve:CVE-2024-0001",
    asset_id: "ast_7",
    cve: "CVE-2024-0001",
    title: "openssl",
    severity: "high",
    state: "FIXING",
    assignee: null,
    due_at: null,
    sla_state: "on_track",
    machine_verified: false,
    closure_reason: null,
    reopen_count: 1,
    recurred: true,
    ticket_system: "jira",
    ticket_key: "SEC-7",
    ticket_url: "https://jira.example.com/browse/SEC-7",
    added_by: "ada",
    added_at: "2026-10-20T00:00:00Z",
    add_reason: null,
    excluded_by: null,
    excluded_at: null,
    exclude_reason: null,
    last_verify: { requested_at: "2026-10-21T00:00:00Z", outcome: "failed", detail: "scanning disabled" },
    verification: { kind: "verification_inconclusive", at: "2026-10-22T00:00:00Z", note: null, gaps: ["nuclei template not run"] },
    ...overrides,
  };
}

function setup(data: Campaign = campaign(), operator = true) {
  useAuthStore.setState({
    user: { username: "op", role: operator ? "operator" : "viewer", default_tenant: "default", tenants: [] } as unknown as Me,
    activeTenant: "default",
    canOperate: operator,
  });
  vi.spyOn(lib.campaignsApi, "get").mockResolvedValue(data);
  const members = vi.spyOn(lib.campaignsApi, "members").mockResolvedValue({
    items: [member()], total: 1, offset: 0, limit: 25, has_more: false,
  });
  vi.spyOn(lib.campaignsApi, "events").mockResolvedValue({
    items: [
      { id: 2, occurred_at: "2026-10-22T00:00:00Z", kind: "members_excluded", actor: "ada", reason: "decommissioned", detail: {} },
      { id: 1, occurred_at: "2026-10-20T00:00:00Z", kind: "created", actor: "ada", reason: null, detail: {} },
    ],
    total: 2, offset: 0, limit: 50, has_more: false,
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(
    <QueryClientProvider client={client}>
      <CampaignDetail id="cmp_1" />
    </QueryClientProvider>,
  );
  return { members, ...view };
}

describe("campaign detail (#579)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows every category on its own and never a single 'fixed' figure", async () => {
    setup();
    expect(await screen.findByText("Upgrade openssl")).toBeInTheDocument();
    const expected: Record<string, string> = {
      open: "3",
      fixing: "2",
      awaiting_verification: "1",
      verified: "2",
      accepted_risk: "1",
      false_positive: "0",
      closed_unverified: "1",
      unavailable: "1",
    };
    for (const [category, count] of Object.entries(expected)) {
      expect(screen.getByTestId(`cat-${category}`)).toHaveTextContent(count);
    }
    expect(screen.getByText(/8 still need work/)).toBeInTheDocument();
    expect(screen.getByText(/1 came back after joining/)).toBeInTheDocument();
    expect(screen.getByText(/Returned to work 1 time\(s\) after completion/)).toBeInTheDocument();
    expect(screen.queryByText(/^(fixed|done|all fixed|resolved)$/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\d\s*%/)).not.toBeInTheDocument();
    expect(screen.getByTestId("campaign-action")).toHaveTextContent("Upgrade to 3.0.14 and restart");
  });

  it("filters the members by the clicked category and shows what the last check found", async () => {
    const { members } = setup();
    const user = userEvent.setup();
    expect(await screen.findByText("SEC-7")).toBeInTheDocument();
    // Partial coverage and the refused dispatch are stated, not hidden.
    expect(screen.getByText(/nuclei template not run/)).toBeInTheDocument();
    expect(screen.getByText(/scanning disabled/)).toBeInTheDocument();
    expect(screen.getAllByText(/came back/).length).toBeGreaterThan(1);

    await user.click(screen.getByRole("button", { name: /Unavailable \/ not verified/ }));
    await waitFor(() =>
      expect(members).toHaveBeenLastCalledWith(
        "cmp_1",
        expect.anything(),
        expect.objectContaining({ category: "unavailable", status: "included" }),
      ),
    );
  });

  it("lists the verification outcome per finding, not one summary", async () => {
    setup();
    vi.spyOn(lib.campaignsApi, "verify").mockResolvedValue({
      results: [
        { id: "vln_1", outcome: "dispatched", job_id: "job1" },
        { id: "vln_2", outcome: "failed", detail: "Scan dispatch is disabled on this server" },
        { id: "vln_3", outcome: "conflict", detail: "cannot move from OPEN to VERIFYING" },
        { id: "vln_4", outcome: "unsupported", detail: "a endpoint_software finding is not verified by a network re-scan" },
      ],
      summary: { dispatched: 1, failed: 1, conflict: 1, unsupported: 1 },
      campaign: campaign(),
    });
    const user = userEvent.setup();
    await screen.findByText("Upgrade openssl");
    await user.click(screen.getByRole("button", { name: "Request verification" }));

    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByTestId("verify-summary")).toHaveTextContent(
      "dispatched: 1 · failed: 1 · conflict: 1 · unsupported: 1",
    );
    expect(within(dialog).getByText(/Scan dispatch is disabled/)).toBeInTheDocument();
    expect(within(dialog).getByText(/cannot move from OPEN to VERIFYING/)).toBeInTheDocument();
    expect(within(dialog).getByText(/not verified by a network re-scan/)).toBeInTheDocument();
  });

  it("excludes only with a reason, and sends it", async () => {
    setup();
    const exclude = vi.spyOn(lib.campaignsApi, "excludeMembers").mockResolvedValue({
      results: [{ id: "vln_1", outcome: "excluded" }], excluded: 1, campaign: campaign(),
    });
    const user = userEvent.setup();
    await screen.findByText("SEC-7");
    await new Promise((resolve) => setTimeout(resolve, 100));
    await user.click(screen.getByRole("checkbox", { name: "Select vln_1" }));
    await user.click(await screen.findByRole("button", { name: "Exclude selected…" }));

    const dialog = await screen.findByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Exclude selected…" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Reason/), "no")
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Reason/), "t ours");
    await user.click(submit);

    await waitFor(() => expect(exclude).toHaveBeenCalledWith("cmp_1", ["vln_1"], "not ours"));
  });

  it("offers no write action to a viewer or on a cancelled campaign", async () => {
    const { unmount } = setup(campaign(), false);
    await screen.findByText("Upgrade openssl");
    expect(screen.queryByRole("button", { name: "Request verification" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel campaign…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("checkbox", { name: "Select vln_1" })).not.toBeInTheDocument();
    unmount();

    vi.restoreAllMocks();
    setup(campaign({ status: "cancelled" }), true);
    await screen.findByText("Upgrade openssl");
    expect(screen.queryByRole("button", { name: "Request verification" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Resume" })).toBeInTheDocument();
  });
});
