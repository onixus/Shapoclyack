import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import VulnerabilitiesPage from "@/app/(dashboard)/vulnerabilities/page";
import * as apiModule from "@/lib/api";
import type { Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import * as campaigns from "@/lib/campaigns";
import type { ProblemPage, ProblemRow } from "@/lib/campaigns";

let searchParams = new URLSearchParams();
const replace = vi.fn();
const push = vi.fn();

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParams,
  useRouter: () => ({ replace, push }),
  usePathname: () => "/vulnerabilities",
}));

function problem(overrides: Partial<ProblemRow> = {}): ProblemRow {
  return {
    problem_key: "cve:CVE-2024-0001",
    kind: "cve",
    cve: "CVE-2024-0001",
    title: "openssl",
    instances: 4,
    assets: 3,
    severity: "critical",
    contextual_score: 9.1,
    cvss: null,
    epss: null,
    kev_instances: 1,
    in_kev: true,
    first_seen_at: "2026-10-01T00:00:00Z",
    last_seen_at: "2026-10-20T00:00:00Z",
    states: { OPEN: 4 },
    machine_verified: 0,
    owners: { unassigned_instances: 2, assignees: [{ name: "ada", instances: 2 }], teams: [] },
    sla: { breached: 1, due_soon: 0, earliest_due_at: null },
    exposure: {
      external: 2,
      internal: 1,
      unknown: 1,
      sources: { "operator-set": 2, finding: 1, none: 1 },
      basis: { declared: 2, measured: 1, unknown: 1 },
    },
    ...overrides,
  };
}

function problemPage(rows: ProblemRow[], overrides: Partial<ProblemPage> = {}): ProblemPage {
  return {
    items: rows,
    total: rows.length,
    offset: 0,
    limit: 25,
    has_more: false,
    aggregates: {
      problems: rows.length,
      instances: 999,
      assets: 321,
      breached_instances: 17,
      kev_instances: 5,
      unassigned_instances: 40,
      machine_verified_instances: 0,
    },
    as_of: "2026-10-24T10:00:00Z",
    semantics: {},
    ...overrides,
  };
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <VulnerabilitiesPage />
    </QueryClientProvider>,
  );
}

describe("Vulnerability Center: Problems / Instances (#579)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    replace.mockReset();
    push.mockReset();
    searchParams = new URLSearchParams({ severity: "high" });
    useAuthStore.setState({
      user: { username: "u", default_tenant: "default", tenants: [] } as unknown as Me,
      activeTenant: "default",
    });
    vi.spyOn(apiModule, "fetchVulnerabilitySummary").mockResolvedValue({
      total: 0, open_total: 0, untriaged: 0, unassigned: 0, estate_risk: "low",
      by_state: {}, by_severity_open: {}, by_risk_level_open: {},
      by_sla: {}, breached: 0, worst_breached_severity: null, generated_at: null,
    });
    vi.spyOn(apiModule, "fetchRetroMatchStatus").mockRejectedValue(new Error("off"));
    vi.spyOn(apiModule, "fetchTrackedVulnerabilities").mockResolvedValue({
      items: [], total: 0, offset: 0, limit: 25, has_more: false,
    });
  });

  it("keeps the filters when switching between the two views, in both directions", async () => {
    const list = vi.spyOn(campaigns.problemsApi, "list").mockResolvedValue(problemPage([problem()]));
    const user = userEvent.setup();
    renderPage();

    await waitFor(() =>
      expect(apiModule.fetchTrackedVulnerabilities).toHaveBeenCalledWith(
        expect.objectContaining({ severity: "high" }),
        expect.anything(),
      ),
    );
    await user.click(screen.getByRole("tab", { name: "Problems" }));

    expect(await screen.findByText("CVE-2024-0001")).toBeInTheDocument();
    expect(list).toHaveBeenCalledWith(
      expect.objectContaining({ severity: "high", open_only: true }),
      expect.anything(),
    );
    // The same filter shows in the toolbar of the other table.
    expect(screen.getByRole("tab", { name: "Problems" })).toHaveAttribute("aria-selected", "true");
    expect(replace).toHaveBeenLastCalledWith("/vulnerabilities?severity=high&view=problems", { scroll: false });

    await user.click(screen.getByRole("tab", { name: "Instances" }));
    await waitFor(() => {
      const calls = vi.mocked(apiModule.fetchTrackedVulnerabilities).mock.calls;
      expect(calls[calls.length - 1][0]).toMatchObject({ severity: "high" });
    });
  });

  it("shows server aggregates for the whole selection, instances and assets apart, and unknown as unknown", async () => {
    vi.spyOn(campaigns.problemsApi, "list").mockResolvedValue(problemPage([problem()]));
    searchParams = new URLSearchParams({ view: "problems" });
    renderPage();

    // 999 / 321 are not derivable from the one row on the page.
    const totals = await screen.findByTestId("problem-aggregates");
    expect(totals.textContent).toContain("999 instances on 321 assets");
    expect(totals.textContent).toContain("17 past SLA");
    const row = screen.getByText("CVE-2024-0001").closest("tr")!;
    expect(within(row).getByText("4")).toBeInTheDocument();
    expect(within(row).getByText(/\/ 3/)).toBeInTheDocument();
    // CVSS and EPSS are absent: they read "unknown", never 0.
    expect(within(row).getAllByText("unknown").length).toBeGreaterThanOrEqual(2);
    expect(within(row).getByText(/declared 2/)).toBeInTheDocument();
    expect(within(row).getByText(/1 past SLA/)).toBeInTheDocument();
  });

  it("drills down with the problem key on the same filters and explains a changed count", async () => {
    vi.spyOn(campaigns.problemsApi, "list").mockResolvedValue(problemPage([problem()]));
    const instances = vi.spyOn(campaigns.problemsApi, "instances").mockResolvedValue({
      items: [], total: 5, offset: 0, limit: 1, has_more: true,
      drift: {
        expected_instances: 4, actual_instances: 5, differs: true,
        changed_since_as_of: 2, explanation: "2 of these findings changed after the list was loaded",
      },
    });
    searchParams = new URLSearchParams({ view: "problems", severity: "high" });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Show instances" }));

    await waitFor(() => {
      const calls = vi.mocked(apiModule.fetchTrackedVulnerabilities).mock.calls;
      expect(calls[calls.length - 1][0]).toMatchObject({
        severity: "high",
        problem_key: "cve:CVE-2024-0001",
      });
    });
    expect(replace).toHaveBeenLastCalledWith(
      "/vulnerabilities?severity=high&problem=cve%3ACVE-2024-0001",
      { scroll: false },
    );
    expect(instances).toHaveBeenCalledWith(
      "cve:CVE-2024-0001",
      expect.objectContaining({ severity: "high" }),
      { limit: 1 },
      { as_of: "2026-10-24T10:00:00Z", expected_instances: 4 },
    );
    expect(
      await screen.findByText("The list showed 4 instances; there are 5 now (2 changed since)."),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Show all instances" }));
    await waitFor(() => {
      const calls = vi.mocked(apiModule.fetchTrackedVulnerabilities).mock.calls;
      expect(calls[calls.length - 1][0]?.problem_key).toBeUndefined();
    });
  });

  it("creates a campaign from selected problems after previewing the composition", async () => {
    vi.spyOn(campaigns.problemsApi, "list").mockResolvedValue(problemPage([problem()]));
    const preview = vi.spyOn(campaigns.campaignsApi, "preview").mockResolvedValue({
      total: 4, assets: 3,
      problems: [{ problem_key: "cve:CVE-2024-0001", title: "openssl", instances: 4, assets: 3 }],
      composition_hash: "h1", already_in_other_campaigns: 1, skipped: [], items: [], truncated: false,
      as_of: "2026-10-24T10:00:00Z",
    });
    const create = vi.spyOn(campaigns.campaignsApi, "create").mockResolvedValue({
      campaign_id: "cmp_1", name: "Upgrade openssl", snapshot_size: 4,
    } as campaigns.Campaign);
    useAuthStore.setState({
      user: { username: "op", role: "operator", tenant_role: "operator", default_tenant: "default", tenants: [] } as unknown as Me,
      activeTenant: "default",
      canOperate: true,
    });
    searchParams = new URLSearchParams({ view: "problems", severity: "high" });
    const user = userEvent.setup();
    renderPage();

    await screen.findByRole("checkbox", { name: "Select cve:CVE-2024-0001" });
    // Let the page's other queries land: the table re-renders when they do.
    await new Promise((resolve) => setTimeout(resolve, 100));
    await user.click(screen.getByRole("checkbox", { name: "Select cve:CVE-2024-0001" }));
    await user.click(await screen.findByRole("button", { name: "Create campaign…" }));

    expect(preview).toHaveBeenCalledWith({
      problem_keys: ["cve:CVE-2024-0001"],
      filters: { severity: "high" },
    });
    expect(await screen.findByTestId("campaign-preview-totals")).toHaveTextContent(
      "4 findings on 3 assets in 1 problems",
    );
    expect(screen.getByText("1 already belong to other campaigns.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Name"), "Upgrade openssl");
    await user.click(screen.getByRole("button", { name: "Create campaign" }));

    await waitFor(() => expect(create).toHaveBeenCalled());
    const [body, key] = create.mock.calls[0];
    expect(body).toMatchObject({
      name: "Upgrade openssl",
      composition_hash: "h1",
      selection: { problem_keys: ["cve:CVE-2024-0001"], filters: { severity: "high" } },
    });
    expect(key).toMatch(/^console:bulk:/);
    await waitFor(() => expect(push).toHaveBeenCalledWith("/campaigns?id=cmp_1"));
  });
});
