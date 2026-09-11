import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { isCancellable, JobsTable } from "@/components/scans/jobs-table";
import type { PaginationState } from "@/hooks/use-pagination";
import * as apiModule from "@/lib/api";
import type { JobInfo } from "@/lib/api";

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

describe("JobsTable", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("only offers cancel on a job that has not started", () => {
    expect(isCancellable({ status: "queued" })).toBe(true);
    expect(isCancellable({ status: "claimed" })).toBe(true);
    expect(isCancellable({ status: "running" })).toBe(false);
    expect(isCancellable({ status: "succeeded" })).toBe(false);
    renderTable([job(), job({ job_id: "000000000001", status: "queued", run_id: null })]);
    expect(screen.getAllByRole("button", { name: "Cancel job" })).toHaveLength(1);
  });

  it("hides cancel from a viewer even on a queued job", () => {
    renderTable([job({ status: "queued" })], { canOperate: false });
    expect(screen.queryByRole("button", { name: "Cancel job" })).not.toBeInTheDocument();
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
    expect(screen.getByLabelText("no agent online in this group")).toBeInTheDocument();
  });

  it("does not mark a job whose group has an agent online", () => {
    renderTable([job({ status: "queued", agent_group: "pci-segment" })]);
    expect(screen.queryByLabelText("no agent online in this group")).toBeNull();
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
    expect(drawer).toHaveTextContent("no agent online in this group");
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
