import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { isCancellable, isStopping, JobsTable, priorityRange } from "@/components/scans/jobs-table";
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
      screen.getByLabelText("Stopping: waiting for the sensor to confirm"),
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

  it("offers a priority range that matches what the API accepts (#365)", () => {
    const operator = { canOperate: true, canRaise: false, username: "op" };
    const raiser = { canOperate: true, canRaise: true, username: "boss" };
    const mine = { status: "queued", requested_by: "op" } as const;
    expect(priorityRange({ ...mine, priority: 0 }, operator)).toEqual({ min: -100, max: 0 });
    expect(priorityRange(mine, operator)).toEqual({ min: -100, max: 0 });
    // Down from where it stands: raising a demoted one back undoes whoever
    // demoted it, and the job does not say who that was.
    expect(priorityRange({ ...mine, priority: -30 }, operator)).toEqual({ min: -100, max: -30 });
    // Someone with the permission raised it: undoing that is theirs too.
    expect(priorityRange({ ...mine, priority: 5 }, operator)).toBeNull();
    // Pushing somebody else's scan back is jumping the queue.
    expect(
      priorityRange({ status: "queued", priority: 0, requested_by: "someone" }, operator),
    ).toBeNull();
    expect(priorityRange({ ...mine, priority: 0 }, { ...operator, username: null })).toBeNull();
    expect(priorityRange({ ...mine, priority: 5 }, raiser)).toEqual({ min: -100, max: 100 });
    // Out of the queue, its place in it is history.
    expect(priorityRange({ status: "claimed", priority: 0, requested_by: "op" }, raiser)).toBeNull();
    expect(
      priorityRange({ ...mine, priority: 0 }, { canOperate: false, canRaise: true, username: "op" }),
    ).toBeNull();
  });

  it("lets a tenant admin raise a queued job, gated by the permission and not the global role", async () => {
    // A global viewer who holds scan.priority.raise in this tenant.
    useAuthStore.setState({
      user: member("admin", ["scan.cancel", "scan.priority.raise"]),
      canOperate: true,
    });
    const put = vi
      .spyOn(apiModule, "setJobPriority")
      .mockResolvedValue(job({ status: "queued", priority: 40 }));
    renderTable([job({ status: "queued", priority: 5, run_id: null })]);
    expect(screen.getByText("+5")).toBeInTheDocument();
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Change priority" }));
    const dialog = await screen.findByRole("dialog");
    const field = within(dialog).getByLabelText("Priority (-100 to 100)");
    await user.clear(field);
    await user.type(field, "40");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith("abc123def456", 40));
  });

  it("keeps an operator without the permission at or below 0", async () => {
    useAuthStore.setState({ user: member("operator", ["scan.cancel"]), canOperate: true });
    const put = vi
      .spyOn(apiModule, "setJobPriority")
      .mockResolvedValue(job({ job_id: "000000000010", status: "queued", priority: -4 }));
    renderTable([
      job({ job_id: "000000000010", status: "queued", priority: 0, requested_by: "on-call" }),
      job({ job_id: "000000000011", status: "queued", priority: 7, requested_by: "on-call" }),
      job({ job_id: "000000000012", status: "queued", priority: 0, requested_by: "op" }),
    ]);
    // The raised one is not theirs to move, nor is somebody else's.
    expect(screen.getAllByRole("button", { name: "Change priority" })).toHaveLength(1);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "Change priority" }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("scan.priority.raise");
    const field = within(dialog).getByLabelText("Priority (-100 to 0)");
    await user.clear(field);
    await user.type(field, "3");
    expect(within(dialog).getByRole("button", { name: "Save" })).toBeDisabled();
    await user.clear(field);
    await user.type(field, "-4");
    await user.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith("000000000010", -4));
  });

  it("does not let a global admin role stand in for the tenant permission", () => {
    // `role: "admin"` on the account says nothing about this tenant; the
    // permission list does, and here it lacks scan.priority.raise.
    useAuthStore.setState({
      user: { ...member("operator", ["scan.cancel"]), role: "admin" },
      canOperate: true,
    });
    renderTable([job({ status: "queued", priority: 7 })]);
    expect(screen.queryByRole("button", { name: "Change priority" })).toBeNull();
  });

  it("offers no priority change to a viewer", () => {
    useAuthStore.setState({ user: member("viewer", []), canOperate: false });
    renderTable([job({ status: "queued" })], { canOperate: false });
    expect(screen.queryByRole("button", { name: "Change priority" })).toBeNull();
  });

  it("shows surface, intent and target counts on the row", () => {
    renderTable([job()]);
    expect(screen.getByText("External")).toBeInTheDocument();
    expect(screen.getByText("vuln")).toBeInTheDocument();
    expect(screen.getByText("domains 3")).toBeInTheDocument();
  });

  it("marks a queued job whose agent group has nobody in it", async () => {
    // docs/operations.md tells an operator to look here when a scan sits in
    // the queue; before this the flag existed only in the API's type.
    renderTable([
      job({
        status: "queued",
        agent_group: "pci-segment",
        agent_group_unavailable: true,
        finished_at: null,
        exit_code: null,
      }),
    ]);
    expect(screen.getByLabelText("no sensor online in this group")).toBeInTheDocument();
  });

  it("does not mark a job whose group has an agent online", () => {
    renderTable([job({ status: "queued", agent_group: "pci-segment" })]);
    expect(screen.queryByLabelText("no sensor online in this group")).toBeNull();
  });

  it("names the agent group in the drawer", async () => {
    vi.spyOn(apiModule, "fetchJob").mockResolvedValue(
      job({ status: "queued", agent_group: "pci-segment", agent_group_unavailable: true }),
    );
    renderTable([job()]);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "abc123def456" }));
    const drawer = await screen.findByRole("dialog");
    await waitFor(() => expect(drawer).toHaveTextContent("pci-segment"));
    expect(drawer).toHaveTextContent("no sensor online in this group");
  });

  it("marks a queued job that no sensor of its tenant can take", async () => {
    // Addressed to no group, so the group badge above never spoke for it: an
    // upgrade applied before the executor was enrolled read as a busy queue.
    renderTable([job({ status: "queued", sensor_unavailable: true, finished_at: null, exit_code: null })]);
    expect(screen.getByLabelText("no sensor online for this tenant")).toBeInTheDocument();
  });

  it("says why in the drawer", async () => {
    vi.spyOn(apiModule, "fetchJob").mockResolvedValue(
      job({ status: "queued", sensor_unavailable: true }),
    );
    renderTable([job()]);
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: "abc123def456" }));
    const drawer = await screen.findByRole("dialog");
    await waitFor(() => expect(drawer).toHaveTextContent("no sensor online for this tenant"));
    expect(drawer).toHaveTextContent("provisioning key has expired");
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
