import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TenantLifecyclePanel } from "@/components/tenants/tenant-lifecycle-panel";
import * as apiModule from "@/lib/api";
import type { TenantDeletion, TenantLifecycle } from "@/lib/api";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const STEPS = ["quiesce", "outbox", "jetstream", "artifacts", "clickhouse", "postgres", "finalize"];

function deletion(overrides: Partial<TenantDeletion> = {}): TenantDeletion {
  return {
    deletion_id: "del_1",
    tenant_id: "acme",
    state: "pending",
    reason: "contract ended",
    requested_by: "root",
    requested_at: "2026-09-10T10:00:00Z",
    purge_after: "2026-09-17T10:00:00Z",
    approved_by: null,
    approved_at: null,
    cancelled_by: null,
    cancelled_at: null,
    completed_at: null,
    attempts: 0,
    last_error: null,
    next_attempt_at: null,
    outcome: null,
    steps: STEPS.map((step, position) => ({
      step,
      position,
      state: "pending",
      attempts: 0,
      started_at: null,
      finished_at: null,
      last_error: null,
      counts: {},
    })),
    ...overrides,
  };
}

function lifecycle(overrides: Partial<TenantLifecycle> = {}): TenantLifecycle {
  return {
    tenant_id: "acme",
    name: "Acme",
    status: "active",
    status_reason: null,
    status_changed_at: null,
    status_changed_by: null,
    legal_hold: null,
    deletion: null,
    history: [],
    grace_days: 7,
    two_person: true,
    ...overrides,
  };
}

function renderPanel() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <TenantLifecyclePanel tenantId="acme" />
    </QueryClientProvider>,
  );
}

describe("TenantLifecyclePanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("suspends only with a reason, and sends whether to revoke credentials", async () => {
    vi.spyOn(apiModule, "fetchTenantLifecycle").mockResolvedValue(lifecycle());
    const suspend = vi
      .spyOn(apiModule, "suspendTenant")
      .mockResolvedValue(lifecycle({ status: "suspended" }));
    renderPanel();

    const button = await screen.findByRole("button", { name: "Suspend tenant" });
    expect(button).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Reason for the suspension"), "invoice unpaid");
    await userEvent.click(screen.getByLabelText(/Revoke the tenant's provisioning keys/));
    await userEvent.click(button);
    expect(suspend).toHaveBeenCalledWith("acme", {
      reason: "invoice unpaid",
      revoke_credentials: false,
    });
  });

  it("requests a deletion only once the tenant id is typed exactly", async () => {
    vi.spyOn(apiModule, "fetchTenantLifecycle").mockResolvedValue(
      lifecycle({ status: "suspended", status_reason: "invoice unpaid" }),
    );
    const request = vi
      .spyOn(apiModule, "requestTenantDeletion")
      .mockResolvedValue(lifecycle({ status: "pending_deletion", deletion: deletion() }));
    renderPanel();

    expect(await screen.findByRole("button", { name: "Resume tenant" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Request deletion" }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: "Request deletion" });
    await userEvent.type(within(dialog).getByLabelText("Reason for the deletion"), "contract ended");
    await userEvent.type(within(dialog).getByLabelText("Type acme to confirm"), "Acme");
    expect(confirm).toBeDisabled();
    await userEvent.clear(within(dialog).getByLabelText("Type acme to confirm"));
    await userEvent.type(within(dialog).getByLabelText("Type acme to confirm"), "acme");
    await userEvent.click(confirm);
    expect(request).toHaveBeenCalledWith("acme", { confirm: "acme", reason: "contract ended" });
  });

  it("disables deletion under a legal hold and shows the platform admin why", async () => {
    vi.spyOn(apiModule, "fetchTenantLifecycle").mockResolvedValue(
      lifecycle({
        legal_hold: {
          tenant_id: "acme",
          reason: "matter 2026-17",
          set_by: "counsel",
          set_at: "2026-09-20T10:00:00Z",
        },
      }),
    );
    renderPanel();

    expect(await screen.findByText(/matter 2026-17 — placed by counsel/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Request deletion" })).toBeDisabled();
  });

  it("holds the approval until the grace period is over, and offers the cancel", async () => {
    const future = new Date(Date.now() + 86_400_000).toISOString();
    vi.spyOn(apiModule, "fetchTenantLifecycle").mockResolvedValue(
      lifecycle({ status: "pending_deletion", deletion: deletion({ purge_after: future }) }),
    );
    const cancel = vi
      .spyOn(apiModule, "cancelTenantDeletion")
      .mockResolvedValue(lifecycle({ status: "suspended" }));
    renderPanel();

    expect(await screen.findByRole("button", { name: "Approve purge" })).toBeDisabled();
    expect(screen.getByText(/other than the requester/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancel deletion" }));
    expect(cancel).toHaveBeenCalledWith("acme");
  });

  it("shows each store's progress and failure, and retries", async () => {
    const running = deletion({
      state: "purging",
      approved_by: "root2",
      last_error: "artifacts: ArtifactStoreError: AccessDenied",
      steps: deletion().steps.map((step) =>
        step.step === "quiesce" || step.step === "outbox"
          ? { ...step, state: "done", counts: { nats_outbox: 3 } }
          : step.step === "artifacts"
            ? { ...step, state: "failed", attempts: 2, last_error: "AccessDenied" }
            : step,
      ),
    });
    vi.spyOn(apiModule, "fetchTenantLifecycle").mockResolvedValue(
      lifecycle({ status: "deleting", deletion: running }),
    );
    const retry = vi
      .spyOn(apiModule, "retryTenantDeletion")
      .mockResolvedValue(lifecycle({ status: "deleting", deletion: running }));
    renderPanel();

    const table = await screen.findByRole("table", { name: "Purge progress by store" });
    const artifacts = within(table).getByText("artifacts").closest("tr") as HTMLElement;
    expect(within(artifacts).getByText("AccessDenied")).toBeInTheDocument();
    expect(within(table).getAllByText("nats_outbox 3")).toHaveLength(2);
    expect(screen.getByRole("alert")).toHaveTextContent("AccessDenied");
    await userEvent.click(screen.getByRole("button", { name: "Retry now" }));
    expect(retry).toHaveBeenCalledWith("acme");
  });
});
