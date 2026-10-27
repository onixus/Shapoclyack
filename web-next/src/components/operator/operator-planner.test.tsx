import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OperatorConsole } from "@/components/operator/operator-console";
import { useAppearanceStore } from "@/lib/appearance";
import { operatorApi, operatorKey, type OperatorPlan, type OperatorTask } from "@/lib/operator-api";

const session = {
  session_id: "s1",
  tenant_id: "tenant-a",
  username: "alice",
  created_at: "2026-10-25T10:00:00Z",
  tasks: [] as OperatorTask[],
};
const queued: OperatorTask = {
  task_id: "planner-task",
  kind: "plan_request",
  run_id: "planner-context",
  status: "queued",
  cancel_requested: false,
  error: null,
  result: null,
};
const preview = {
  proposal_id: "old-preview",
  session_id: "s1",
  tenant_id: "tenant-a",
  action: "start_scan" as const,
  arguments: { ranges: "192.0.2.1", ports: "22", mode: "fast" },
  arguments_sha256: "a".repeat(64),
  expires_at: "2099-01-01T00:00:00Z",
  status: "preview",
  impact: { network_access: true },
  execution: null,
};

function decision(
  tool: OperatorPlan["tool"],
  args: Record<string, unknown>,
  override: Partial<OperatorPlan> = {},
): OperatorTask {
  return {
    ...queued,
    status: "succeeded",
    result: {
      quality_status: "quality_unverified",
      plan: {
        tool,
        arguments: args,
        effect_executed: false,
        requires_confirmation: ["prepare_scan", "cancel_scan", "verify_finding"].includes(tool),
        status: tool === "abstain" ? "unsupported" : "proposal",
        quality_status: "quality_unverified",
        language: "en",
        ...override,
      },
    },
  };
}

function view(canOperate = true) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  });
  const wrapper = (tenant: string) => (
    <QueryClientProvider client={client}>
      <OperatorConsole key={tenant} tenant={tenant} actor="alice" canOperate={canOperate} />
    </QueryClientProvider>
  );
  const rendered = render(wrapper("tenant-a"));
  return {
    client,
    ...rendered,
    switchTenant: (tenant: string) => rendered.rerender(wrapper(tenant)),
  };
}

beforeEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  useAppearanceStore.setState({ locale: "en" });
  sessionStorage.setItem('operator-session:["tenant-a","alice"]', "s1");
  vi.spyOn(operatorApi, "status").mockResolvedValue({
    provider: "local",
    model: "fixture",
    external_inference: false,
    runtime_status: "not_checked",
    quality_status: "quality_unverified",
    task_submission_enabled: true,
  });
  vi.spyOn(operatorApi, "sessions").mockImplementation(async (tenant) =>
    tenant === "tenant-a" ? { items: [session], total: 1 } : { items: [], total: 0 },
  );
  vi.spyOn(operatorApi, "session").mockResolvedValue(session);
  vi.spyOn(operatorApi, "plan").mockResolvedValue(queued);
  vi.spyOn(operatorApi, "submit").mockResolvedValue({
    ...queued,
    kind: "summarize_run",
    run_id: "bound-run",
  });
  vi.spyOn(operatorApi, "prepare").mockResolvedValue(preview);
  vi.spyOn(operatorApi, "proposal").mockResolvedValue(preview);
  vi.spyOn(operatorApi, "confirm").mockResolvedValue(preview);
  vi.spyOn(operatorApi, "compare").mockResolvedValue({
    status: "incomplete",
    quality_status: "quality_unverified",
    summary: "Comparison fixture",
    reason: "coverage unknown",
    counts: {},
    citations: [],
  });
  vi.spyOn(operatorApi, "remediation").mockResolvedValue({
    device_id: "bound-device",
    snapshot_id: "snap",
    state: "unknown",
    quality_status: "deterministic",
    reason: "No matches",
    items: [],
    truncated: false,
  });
});

describe("natural request planner", () => {
  it("submits a durable request with explicit tenant, bound typed context and stable idempotency", async () => {
    view();
    const panel = within(await screen.findByRole("region", { name: "Ask the operator" }));
    await userEvent.type(
      panel.getByLabelText("Your request"),
      "Prepare a safe scan of the selected targets",
    );
    await userEvent.click(panel.getByText("Selected context (optional)"));
    await userEvent.type(panel.getByLabelText("Selected run ID"), "bound-run");
    await userEvent.type(panel.getByLabelText("Selected previous run ID"), "previous-run");
    await userEvent.type(panel.getByLabelText("Selected endpoint device ID"), "bound-device");
    await userEvent.click(panel.getByRole("checkbox", { name: "Include explicit scan targets" }));
    await userEvent.type(panel.getByLabelText("IP ranges (one per line)"), "192.0.2.99");
    await userEvent.dblClick(panel.getByRole("button", { name: "Propose the next step" }));
    await waitFor(() => expect(operatorApi.plan).toHaveBeenCalled());
    const calls = vi.mocked(operatorApi.plan).mock.calls;
    expect(new Set(calls.map((call) => call[3])).size).toBe(1);
    expect(calls[0]).toEqual([
      "tenant-a",
      "s1",
      {
        request: "Prepare a safe scan of the selected targets",
        language: "en",
        context: {
          run_id: "bound-run",
          previous_run_id: "previous-run",
          device_id: "bound-device",
          scan: { mode: "safe", ranges: "192.0.2.99", domains: "", ports: "443", ports_udp: "" },
        },
      },
      expect.any(String),
    ]);
    expect(operatorApi.prepare).not.toHaveBeenCalled();
    expect(operatorApi.confirm).not.toHaveBeenCalled();
  });

  it("restores a queued planner task without generating another proposal", async () => {
    vi.mocked(operatorApi.session).mockResolvedValue({ ...session, tasks: [queued] });
    const first = view();
    await screen.findByText("queued");
    first.unmount();
    view();
    await screen.findByText("queued");
    expect(operatorApi.plan).not.toHaveBeenCalled();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
  });

  it("adopts scan parameters only after a click and clears a previous confirmed preview", async () => {
    sessionStorage.setItem('operator-proposal:["tenant-a","alice","s1"]', "old-preview");
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...session,
      tasks: [
        decision("prepare_scan", {
          ranges: "192.0.2.99",
          ports: "443",
          ports_udp: "53",
          intent: "inventory",
          mode: "safe",
          agent_group: "bound-group",
        }),
      ],
    });
    view();
    const oldConfirm = await screen.findByRole("button", { name: "Confirm this plan" });
    await userEvent.click(screen.getByRole("checkbox", { name: /I reviewed/ }));
    expect(oldConfirm).toBeEnabled();
    await userEvent.click(screen.getByRole("button", { name: "Use these parameters" }));
    expect(screen.getByLabelText("IP ranges (one per line)")).toHaveValue("192.0.2.99");
    expect(screen.getByLabelText("Profile")).toHaveValue("safe");
    expect(screen.getByLabelText("UDP ports")).toHaveValue("53");
    expect(screen.getByLabelText("Scan purpose")).toHaveValue("inventory");
    expect(screen.queryByRole("button", { name: "Confirm this plan" })).not.toBeInTheDocument();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
    expect(operatorApi.confirm).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Preview action" }));
    await waitFor(() => expect(operatorApi.prepare).toHaveBeenCalledTimes(1));
    expect(operatorApi.prepare).toHaveBeenCalledWith("tenant-a", "s1", "start_scan", {
      ranges: "192.0.2.99",
      ports: "443",
      ports_udp: "53",
      intent: "inventory",
      mode: "safe",
      agent_group: "bound-group",
    });
    expect(await screen.findByRole("button", { name: "Confirm this plan" })).toBeDisabled();
    expect(operatorApi.confirm).not.toHaveBeenCalled();
  });

  it("adopts a finding remediation context, reads reviewed guidance and revalidates its source", async () => {
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...session,
      tasks: [decision("find_remediation", { vuln_id: "finding-1" })],
    });
    const citation = { source_id: "guide", snapshot_id: "snapshot", source_hash: "a".repeat(64) };
    const lookup = vi.spyOn(operatorApi, "findingRemediation").mockResolvedValue({
      vuln_id: "finding-1",
      state: "complete",
      quality_status: "deterministic",
      reason: null,
      truncated: false,
      items: [
        {
          kind: "configuration_hardening",
          product: "apache_httpd",
          applicability: "administrator_reviewed",
          status: "configuration_guidance",
          directive: "TraceEnable off",
          package: null,
          installed_version: null,
          target_version: null,
          upgrade_command: null,
          cve_ids: [],
          sources: [citation],
          verification: { method: "existing_targeted_scan", requires_confirmation: true },
          limitations: ["no_automatic_application"],
        },
      ],
    });
    const open = vi
      .spyOn(operatorApi, "findingRemediationSource")
      .mockResolvedValue({ directive: "TraceEnable off" });
    view();
    await userEvent.click(await screen.findByRole("button", { name: "Use these parameters" }));
    expect(screen.getByLabelText("Remediation context")).toHaveValue("finding");
    expect(screen.getByLabelText("Network finding ID")).toHaveValue("finding-1");
    expect(lookup).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Find fixes" }));
    await screen.findByText("TraceEnable off");
    expect(lookup).toHaveBeenCalledWith("tenant-a", "finding-1", "en", expect.any(AbortSignal));
    expect(screen.queryByText(/Installed:/)).not.toBeInTheDocument();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /Open authorized source: guide/ }));
    await waitFor(() =>
      expect(open).toHaveBeenCalledWith("tenant-a", "finding-1", citation, expect.any(AbortSignal)),
    );
    await userEvent.selectOptions(screen.getByLabelText("Remediation context"), "device");
    expect(screen.queryByText("TraceEnable off")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Endpoint device ID")).toHaveValue("");
  });

  it("keeps unreviewed finding applicability unknown without offering a directive or write action", async () => {
    vi.spyOn(operatorApi, "findingRemediation").mockResolvedValue({
      vuln_id: "finding-unknown",
      state: "unknown",
      quality_status: "deterministic",
      reason: "application_review_required",
      truncated: false,
      items: [
        {
          kind: "configuration_hardening",
          product: null,
          applicability: "unknown",
          directive: null,
          status: "unknown",
          package: null,
          installed_version: null,
          target_version: null,
          upgrade_command: null,
          cve_ids: [],
          sources: [],
          verification: { method: "existing_targeted_scan", requires_confirmation: true },
          limitations: ["no_automatic_application"],
        },
      ],
    });
    view(false);
    await userEvent.selectOptions(await screen.findByLabelText("Remediation context"), "finding");
    await userEvent.type(screen.getByLabelText("Network finding ID"), "finding-unknown");
    await userEvent.click(screen.getByRole("button", { name: "Find fixes" }));
    await screen.findByText(/application_review_required/);
    expect(screen.queryByText("TraceEnable off")).not.toBeInTheDocument();
    expect(screen.queryByText("Configuration directive for manual review")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /approve|apply|confirm/i }),
    ).not.toBeInTheDocument();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
  });

  it.each([
    ["cancel_scan", "job_id", "Job ID", "cancel_scan"],
    ["verify_finding", "vuln_id", "Finding ID", "verify_finding"],
  ] as const)(
    "adopting %s fills the exact resource without executing it",
    async (tool, field, label, action) => {
      vi.mocked(operatorApi.session).mockResolvedValue({
        ...session,
        tasks: [decision(tool, { [field]: "bound-resource" })],
      });
      view();
      await userEvent.click(await screen.findByRole("button", { name: "Use these parameters" }));
      expect(screen.getByLabelText(label)).toHaveValue("bound-resource");
      expect(screen.getByLabelText("Action")).toHaveValue(action);
      expect(operatorApi.prepare).not.toHaveBeenCalled();
      expect(operatorApi.confirm).not.toHaveBeenCalled();
    },
  );

  it("copies an analysis run but queues nothing until the user explicitly requests analysis", async () => {
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...session,
      tasks: [decision("summarize_run", { run_id: "bound-run" })],
    });
    view();
    await userEvent.click(await screen.findByRole("button", { name: "Use these parameters" }));
    expect(screen.getByLabelText("Run ID")).toHaveValue("bound-run");
    expect(operatorApi.submit).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Queue analysis" }));
    await waitFor(() => expect(operatorApi.submit).toHaveBeenCalledTimes(1));
    expect(operatorApi.submit).toHaveBeenCalledWith(
      "tenant-a",
      "s1",
      { tool: "summarize_run", run_id: "bound-run", language: "en" },
      expect.any(String),
    );
  });

  it("copies comparison context but does not read either run until requested", async () => {
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...session,
      tasks: [decision("compare_runs", { previous_run_id: "previous", current_run_id: "current" })],
    });
    view();
    await userEvent.click(await screen.findByRole("button", { name: "Use these parameters" }));
    expect(screen.getByLabelText("Previous run ID")).toHaveValue("previous");
    expect(screen.getByLabelText("Current run ID")).toHaveValue("current");
    expect(operatorApi.compare).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Compare published runs" }));
    await screen.findByText("Comparison fixture");
  });

  it("copies a device context without fetching remediation or emitting an action", async () => {
    vi.mocked(operatorApi.session).mockResolvedValue({
      ...session,
      tasks: [decision("find_remediation", { device_id: "bound-device" })],
    });
    view();
    await userEvent.click(await screen.findByRole("button", { name: "Use these parameters" }));
    expect(screen.getByLabelText("Endpoint device ID")).toHaveValue("bound-device");
    expect(operatorApi.remediation).not.toHaveBeenCalled();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
  });

  it.each([
    decision("abstain", {}),
    decision("prepare_scan", { ranges: "192.0.2.99", ports: "443" }, { effect_executed: true }),
  ])("does not adopt unsupported or unexpectedly executed results", async (task) => {
    vi.mocked(operatorApi.session).mockResolvedValue({ ...session, tasks: [task] });
    view();
    await screen.findByRole("region", { name: "Ask the operator" });
    expect(screen.queryByRole("button", { name: "Use these parameters" })).not.toBeInTheDocument();
    expect(operatorApi.prepare).not.toHaveBeenCalled();
    expect(operatorApi.confirm).not.toHaveBeenCalled();
  });

  it("drops a pending natural request context on tenant switch and ignores its late response", async () => {
    let resolve!: (task: OperatorTask) => void;
    vi.mocked(operatorApi.plan).mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    const rendered = view();
    const request = await screen.findByLabelText("Your request");
    await userEvent.type(request, "private tenant-a request");
    await userEvent.click(screen.getByRole("button", { name: "Propose the next step" }));
    await waitFor(() => expect(operatorApi.plan).toHaveBeenCalledTimes(1));
    const oldSessionCalls = vi.mocked(operatorApi.session).mock.calls.length;
    act(() => rendered.switchTenant("tenant-b"));
    await screen.findByText("No sessions yet.");
    await act(async () => {
      resolve(queued);
    });
    expect(screen.queryByDisplayValue("private tenant-a request")).not.toBeInTheDocument();
    expect(
      rendered.client.getQueryCache().findAll({ queryKey: operatorKey("tenant-a", "alice") }),
    ).toHaveLength(0);
    expect(
      rendered.client.getMutationCache().findAll({ mutationKey: operatorKey("tenant-a", "alice") }),
    ).toHaveLength(0);
    expect(operatorApi.session).toHaveBeenCalledTimes(oldSessionCalls);
    expect(operatorApi.prepare).not.toHaveBeenCalled();
  });
});
