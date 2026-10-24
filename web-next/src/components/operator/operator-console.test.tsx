import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OperatorConsole } from "@/components/operator/operator-console";
import { useAppearanceStore } from "@/lib/appearance";
import {
  operatorApi,
  operatorKey,
  type OperatorProposal,
  type OperatorSession,
  type OperatorTask,
} from "@/lib/operator-api";

const sessionRow: OperatorSession = {
  session_id: "s1",
  tenant_id: "tenant-a",
  username: "alice",
  created_at: "2026-10-25T10:00:00Z",
  tasks: [],
};
const queued: OperatorTask = {
  task_id: "task1",
  kind: "analyze_run",
  run_id: "run1",
  status: "queued",
  cancel_requested: false,
  error: null,
  result: null,
};
const plan: OperatorProposal = {
  proposal_id: "plan1",
  session_id: "s1",
  tenant_id: "tenant-a",
  action: "start_scan",
  arguments: { ranges: "192.0.2.1", ports: "80,443", mode: "safe" },
  arguments_sha256: "a".repeat(64),
  expires_at: "2099-01-01T00:00:00Z",
  status: "preview",
  impact: { targets: ["192.0.2.1"], quota: "checked" },
  execution: null,
};

function savedSession(tenant = "tenant-a", actor = "alice", id = "s1") {
  sessionStorage.setItem(`operator-session:${JSON.stringify([tenant, actor])}`, id);
}
function renderConsole(tenant = "tenant-a", canOperate = true) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <OperatorConsole key={tenant} tenant={tenant} actor="alice" canOperate={canOperate} />
    </QueryClientProvider>,
  );
  return {
    client,
    ...view,
    switchTenant: (next: string) =>
      view.rerender(
        <QueryClientProvider client={client}>
          <OperatorConsole key={next} tenant={next} actor="alice" canOperate={canOperate} />
        </QueryClientProvider>,
      ),
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  useAppearanceStore.setState({ locale: "en" });
  vi.spyOn(operatorApi, "status").mockResolvedValue({
    provider: "local",
    model: "Qwen-test",
    external_inference: false,
    runtime_status: "not_checked",
    quality_status: "quality_unverified",
    task_submission_enabled: true,
  });
  vi.spyOn(operatorApi, "compare").mockResolvedValue({
    status: "unsupported",
    quality_status: "quality_unverified",
    summary: "Comparison unavailable",
    reason: "Baseline mismatch",
    counts: {},
    citations: [],
    diff_source: null,
  });
  vi.spyOn(operatorApi, "sessions").mockResolvedValue({ items: [sessionRow], total: 1 });
  vi.spyOn(operatorApi, "session").mockResolvedValue(sessionRow);
  vi.spyOn(operatorApi, "submit").mockResolvedValue(queued);
  vi.spyOn(operatorApi, "cancel").mockResolvedValue({ ...queued, cancel_requested: true });
  vi.spyOn(operatorApi, "prepare").mockResolvedValue(plan);
  vi.spyOn(operatorApi, "proposal").mockResolvedValue(plan);
  vi.spyOn(operatorApi, "confirm").mockResolvedValue({
    ...plan,
    status: "succeeded",
    execution: { execution_id: "e1", status: "succeeded", result: { job_id: "j1" } },
  });
  vi.spyOn(operatorApi, "remediation").mockResolvedValue({
    device_id: "d1",
    snapshot_id: "snap",
    state: "unknown",
    quality_status: "deterministic",
    reason: "Missing inventory",
    items: [],
    truncated: false,
  });
  vi.spyOn(operatorApi, "evidence").mockResolvedValue({ context: { port: 443 } });
});
afterEach(() => {
  vi.useRealTimers();
});

describe("operator console", () => {
  it("exposes session selection and creation in keyboard order", async () => {
    renderConsole();
    await screen.findByText("local / Qwen-test");
    await userEvent.tab();
    expect(screen.getByLabelText("Personal sessions")).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole("button", { name: "New session" })).toHaveFocus();
  });
  it("shows unsupported comparisons without turning missing observations into fixes", async () => {
    renderConsole();
    await screen.findByText("Find a vendor-backed fix");
    await userEvent.type(screen.getByLabelText("Previous run ID"), "before");
    await userEvent.type(screen.getByLabelText("Current run ID"), "after");
    await userEvent.click(screen.getByRole("button", { name: "Compare published runs" }));
    expect(await screen.findByText("Baseline mismatch")).toBeInTheDocument();
    expect(screen.getByText(/missing observation is not proof/)).toBeInTheDocument();
    expect(operatorApi.compare).toHaveBeenCalledWith(
      "tenant-a",
      "before",
      "after",
      "en",
      expect.any(AbortSignal),
    );
  });
  it("leaves other workflows alone when the optional operator returns 404", async () => {
    vi.mocked(operatorApi.status).mockRejectedValue({ response: { status: 404 } });
    renderConsole();
    expect(
      await screen.findByText("Operator is disabled or unavailable on this installation."),
    ).toBeInTheDocument();
    expect(operatorApi.sessions).not.toHaveBeenCalled();
    expect(operatorApi.submit).not.toHaveBeenCalled();
  });

  it("shows configured provider separately from unchecked readiness and quality", async () => {
    renderConsole();
    expect(await screen.findByText("local / Qwen-test")).toBeInTheDocument();
    expect(screen.getByText("not_checked")).toBeInTheDocument();
    expect(screen.getByText("quality_unverified")).toBeInTheDocument();
    expect(screen.getByText(/offline operation has not been verified/)).toBeInTheDocument();
  });

  it("restores an active server task after reconnect without submitting it", async () => {
    savedSession();
    vi.mocked(operatorApi.session).mockResolvedValue({ ...sessionRow, tasks: [queued] });
    const view = renderConsole();
    expect(await screen.findByText("queued")).toBeInTheDocument();
    expect(screen.getByText(/reconnecting does not submit it again/)).toBeInTheDocument();
    expect(operatorApi.submit).not.toHaveBeenCalled();
    view.unmount();
    renderConsole();
    await screen.findByText("queued");
    expect(operatorApi.submit).not.toHaveBeenCalled();
  });

  it("queues the selected operation once with explicit tenant, language and idempotency key", async () => {
    savedSession();
    renderConsole();
    await screen.findByText("No tasks in this session.");
    await userEvent.type(screen.getByLabelText("Run ID"), "run1");
    await userEvent.click(screen.getByRole("button", { name: "Queue analysis" }));
    await waitFor(() => expect(operatorApi.submit).toHaveBeenCalledTimes(1));
    expect(operatorApi.submit).toHaveBeenCalledWith(
      "tenant-a",
      "s1",
      { tool: "analyze_run", run_id: "run1", language: "en" },
      expect.any(String),
    );
  });

  it("reuses the request key after an uncertain queue response", async () => {
    savedSession();
    vi.mocked(operatorApi.submit).mockRejectedValue(new Error("network"));
    renderConsole();
    await screen.findByText("No tasks in this session.");
    await userEvent.type(screen.getByLabelText("Run ID"), "run1");
    await userEvent.click(screen.getByRole("button", { name: "Queue analysis" }));
    await screen.findByRole("alert");
    await userEvent.click(screen.getByRole("button", { name: "Queue analysis" }));
    await waitFor(() => expect(operatorApi.submit).toHaveBeenCalledTimes(2));
    expect(vi.mocked(operatorApi.submit).mock.calls[0][3]).toBe(
      vi.mocked(operatorApi.submit).mock.calls[1][3],
    );
  });

  it("renders malicious source text as text and fetches citations only after a click", async () => {
    savedSession();
    const citation = {
      source_id: "source1",
      source_hash: "b".repeat(64),
      snapshot_id: "snap",
      status: "partial",
    };
    const injection =
      '<img src="https://evil.test/beacon" onerror="alert(1)"> [link](javascript:alert(1))';
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...sessionRow,
      tasks: [
        {
          ...queued,
          status: "succeeded",
          result: {
            quality_status: "quality_unverified",
            analysis: { status: "incomplete", summary: injection, citations: [citation] },
          },
        },
      ],
    });
    const view = renderConsole();
    expect(await screen.findByText(injection)).toBeInTheDocument();
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.querySelector("a[href]")).toBeNull();
    expect(operatorApi.evidence).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /Open authorized source: source1/ }));
    await waitFor(() =>
      expect(operatorApi.evidence).toHaveBeenCalledWith(
        "tenant-a",
        citation,
        expect.any(AbortSignal),
      ),
    );
  });

  it("clears tenant data and aborts old reads when the context changes", async () => {
    savedSession();
    let oldSignal: AbortSignal | undefined;
    vi.mocked(operatorApi.session).mockImplementation(async (_tenant, _session, signal) => {
      oldSignal = signal;
      return {
        ...sessionRow,
        tasks: [
          {
            ...queued,
            status: "succeeded",
            result: { analysis: { status: "incomplete", summary: "tenant-a secret" } },
          },
        ],
      };
    });
    const view = renderConsole();
    await screen.findByText("tenant-a secret");
    expect(
      view.client.getQueryCache().findAll({ queryKey: operatorKey("tenant-a", "alice") }).length,
    ).toBeGreaterThan(0);
    act(() => view.switchTenant("tenant-b"));
    await screen.findByText("tenant-b", { exact: false });
    expect(screen.queryByText("tenant-a secret")).not.toBeInTheDocument();
    expect(
      view.client.getQueryCache().findAll({ queryKey: operatorKey("tenant-a", "alice") }),
    ).toHaveLength(0);
    // Already completed reads may have a non-aborted signal; their cache was removed.
    expect(oldSignal).toBeInstanceOf(AbortSignal);
    expect(operatorApi.submit).not.toHaveBeenCalled();
  });

  it("reports cancellation as a request until the server confirms the terminal state", async () => {
    savedSession();
    vi.mocked(operatorApi.session).mockResolvedValue({ ...sessionRow, tasks: [queued] });
    renderConsole();
    await screen.findByText("queued");
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...sessionRow,
      tasks: [{ ...queued, status: "running", cancel_requested: true }],
    });
    await userEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
    expect(
      await screen.findByText("Cancellation requested; waiting for worker confirmation."),
    ).toBeInTheDocument();
    expect(screen.getByText("running")).toBeInTheDocument();
  });

  it("requires review and confirms the stored plan hash exactly once", async () => {
    savedSession();
    renderConsole();
    await screen.findByText("No tasks in this session.");
    await userEvent.type(screen.getByLabelText("IP ranges (one per line)"), "192.0.2.1");
    await userEvent.click(screen.getByRole("button", { name: "Preview action" }));
    const confirm = await screen.findByRole("button", { name: "Confirm this plan" });
    expect(confirm).toBeDisabled();
    expect(screen.getByText(/Plan digest:/)).toHaveTextContent(plan.arguments_sha256);
    const exactPlan = within(screen.getByRole("region", { name: "Review the exact plan" }));
    expect(exactPlan.getAllByText("192.0.2.1", { exact: true }).length).toBeGreaterThan(0);
    expect(exactPlan.getByText("safe", { exact: true })).toBeInTheDocument();
    expect(exactPlan.getByText("TCP ports", { exact: true })).toBeInTheDocument();
    expect(screen.getByText(/Expires:/)).toHaveTextContent(plan.expires_at);
    await userEvent.click(screen.getByRole("checkbox"));
    await userEvent.dblClick(confirm);
    await waitFor(() => expect(operatorApi.confirm).toHaveBeenCalledTimes(1));
    expect(operatorApi.confirm).toHaveBeenCalledWith("tenant-a", "plan1", plan.arguments_sha256);
    expect(operatorApi.prepare).toHaveBeenCalledWith("tenant-a", "s1", "start_scan", {
      ranges: "192.0.2.1",
      ports: "80,443",
      mode: "balanced",
    });
  });

  it("restores a preview without confirming and refuses expired or foreign plans", async () => {
    savedSession();
    sessionStorage.setItem(
      `operator-proposal:${JSON.stringify(["tenant-a", "alice", "s1"])}`,
      "plan1",
    );
    vi.mocked(operatorApi.proposal).mockResolvedValue({
      ...plan,
      expires_at: "2020-01-01T00:00:00Z",
    });
    renderConsole();
    expect(await screen.findByText(/This plan expired/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Confirm this plan" })).not.toBeInTheDocument();
    expect(operatorApi.confirm).not.toHaveBeenCalled();
  });

  it("requires a new acknowledgement when a refreshed plan digest changes", async () => {
    savedSession();
    sessionStorage.setItem(
      `operator-proposal:${JSON.stringify(["tenant-a", "alice", "s1"])}`,
      "plan1",
    );
    renderConsole();
    const confirm = await screen.findByRole("button", { name: "Confirm this plan" });
    await userEvent.click(screen.getByRole("checkbox"));
    expect(confirm).toBeEnabled();
    vi.mocked(operatorApi.proposal).mockResolvedValue({
      ...plan,
      arguments: { ...plan.arguments, ports: "22" },
      arguments_sha256: "c".repeat(64),
    });
    await userEvent.click(
      within(screen.getByRole("region", { name: "Review the exact plan" })).getByRole("button", {
        name: "Refresh server state",
      }),
    );
    await waitFor(() => expect(confirm).toBeDisabled());
    expect(operatorApi.confirm).not.toHaveBeenCalled();
  });

  it("keeps missing remediation evidence unknown and never invents a command", async () => {
    renderConsole();
    await screen.findByText("Find a vendor-backed fix");
    await userEvent.type(screen.getByLabelText("Endpoint device ID"), "d1");
    await userEvent.click(screen.getByRole("button", { name: "Find fixes" }));
    expect(await screen.findByText(/No confirmed fix cards are available/)).toBeInTheDocument();
    expect(screen.getByText(/Missing inventory/)).toBeInTheDocument();
    expect(screen.queryByText("Suggested command for review only")).not.toBeInTheDocument();
    expect(operatorApi.remediation).toHaveBeenCalledWith(
      "tenant-a",
      "d1",
      "en",
      expect.any(AbortSignal),
    );
  });

  it("allows a reader to view history without offering effects", async () => {
    savedSession();
    renderConsole("tenant-a", false);
    await screen.findByText("No tasks in this session.");
    expect(screen.queryByText("Prepare an action")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "New session" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Queue analysis" })).toBeDisabled();
  });
});
