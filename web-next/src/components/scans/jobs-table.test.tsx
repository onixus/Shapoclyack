import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { isCancellable, isStopping, JobsTable } from "@/components/scans/jobs-table";
import type { PaginationState } from "@/hooks/use-pagination";
import * as apiModule from "@/lib/api";
import type { JobInfo, Me } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
}));

function job(overrides: Partial<JobInfo> = {}): JobInfo {
  return {
    job_id: "abc123def456",
    status: "succeeded",
    run_id: "20260909T101010Z",
    mode: "balanced",
    started_at: "2026-09-09T10:10:10Z",
    finished_at: "2026-09-09T10:20:10Z",
    exit_code: 0,
    error: null,
    requested_by: "op",
    execution: "local",
    surface: "external",
    target_counts: { domains: 3 },
    scan_options: { intent: "vuln", intent_summary: "probe + nuclei critical/high" },
    ...overrides,
  };
}

const pagination: PaginationState = {
  params: { offset: 0, limit: 15 },
  offset: 0,
  limit: 15,
  setOffset: vi.fn(),
  search: "",
  setSearch: vi.fn(),
  sort: "started_at",
  order: "desc",
  setSort: vi.fn(),
  reset: vi.fn(),
};

function renderTable(items: JobInfo[], props: Partial<Parameters<typeof JobsTable>[0]> = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <JobsTable
        page={{ items, total: items.length, offset: 0, limit: 15, has_more: false }}
        isLoading={false}
        error={null}
        pagination={pagination}
        showSurface
        canOperate
        {...props}
      />
    </QueryClientProvider>,
  );
}

/** A principal whose authority is a tenant membership, not the global role. */
function member(role: string, permissions: string[]): Me {
  return {
    username: "on-call",
    role: "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: role,
    permissions,
    scoped_tenant: "default",
  };
}

describe("JobsTable", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null, canOperate: false });
  });

  it("offers cancel on a running scan too, but not once it is stopping", () => {
    // #360: a running scan is stoppable through the agent's heartbeat. A job
    // already `cancelling` is not — the stop has been asked for, and a second
    // button would suggest the first click did not land.
    expect(isCancellable({ status: "queued" })).toBe(true);
    expect(isCancellable({ status: "claimed" })).toBe(true);
    expect(isCancellable({ status: "running" })).toBe(true);
    expect(isCancellable({ status: "cancelling" })).toBe(false);
    expect(isCancellable({ status: "succeeded" })).toBe(false);
    expect(isStopping({ status: "cancelling" })).toBe(true);
    renderTable([
      job(),
      job({ job_id: "000000000001", status: "queued", run_id: null }),
      job({ job_id: "000000000002", status: "running" }),
      job({ job_id: "000000000003", status: "cancelling" }),
    ]);
    expect(screen.getAllByRole("button", { name: "Cancel job" })).toHaveLength(2);
    expect(
      screen.getByLabelText("Stopping: waiting for the agent to confirm"),
    ).toBeInTheDocument();
  });

  it("warns that a running scan is only asked to stop", async () => {
    // The queued wording ("never handed out") would promise a stop that has
    // not happened yet on a scan an agent is in the middle of.
    renderTable([job({ status: "running" })]);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Cancel job" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("on its next heartbeat");
    expect(dialog).toHaveTextContent("is kept");
  });

  it("hides cancel from a viewer even on a queued job", () => {
    useAuthStore.setState({ user: member("viewer", []), canOperate: false });
    renderTable([job({ status: "queued" })], { canOperate: false });
    expect(screen.queryByRole("button", { name: "Cancel job" })).not.toBeInTheDocument();
  });

  it("shows cancel to a scan-operator, who is a viewer in the global role", () => {
    // docs/ui.md promises the button on `scan.cancel`. Requiring the operator
    // rank on top of it hid the button from the one role #318 added for
    // exactly this — a `scan-operator` whose global role is viewer — while the
    // API accepted their stop, and would hide it from an on-call granted the
    // permission on its own.
    useAuthStore.setState({
      user: member("scan-operator", ["scan.cancel"]),
      canOperate: false,
    });
    renderTable([job({ status: "running" })], { canOperate: false });
    expect(screen.getByRole("button", { name: "Cancel job" })).toBeInTheDocument();
  });

  it("keeps the button for an operator on an API that sends no permissions", () => {
    // Pre-#318 installations answer /auth/me without a permission list; the
    // rank is then all there is, and the action must not vanish on upgrade.
    const legacy = member("operator", []);
    delete legacy.permissions;
    useAuthStore.setState({ user: legacy, canOperate: true });
    renderTable([job({ status: "running" })], { canOperate: true });
    expect(screen.getByRole("button", { name: "Cancel job" })).toBeInTheDocument();
  });

  it("asks before cancelling and then calls the API", async () => {
    const cancel = vi.spyOn(apiModule, "cancelJob").mockResolvedValue(job({ status: "cancelled" }));
    renderTable([job({ status: "queued", run_id: null })]);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Cancel job" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(dialog).toHaveTextContent("Cancel job abc123def456?");
    await user.click(within(dialog).getByRole("button", { name: "Cancel job" }));
    await waitFor(() => expect(cancel).toHaveBeenCalledTimes(1));
    expect(cancel.mock.calls[0][0]).toBe("abc123def456");
  });

  it("shows surface, intent and target counts on the row", () => {
    renderTable([job()]);
    expect(screen.getByText("External")).toBeInTheDocument();
    expect(screen.getByText("vuln")).toBeInTheDocument();
    expect(screen.getByText("domains 3")).toBeInTheDocument();
  });

  it("opens the full record from the job id", async () => {
    vi.spyOn(apiModule, "fetchJob").mockResolvedValue(job({ attempts: 2 }));
    renderTable([job()]);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "abc123def456" }));
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("probe + nuclei critical/high");
    expect(drawer).toHaveTextContent("Findings of this run");
    await waitFor(() => expect(drawer).toHaveTextContent(/Attempts\D*2/));
  });
});
