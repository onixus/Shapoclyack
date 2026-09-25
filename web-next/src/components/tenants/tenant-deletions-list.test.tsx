import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TenantDeletionsList } from "@/components/tenants/tenant-deletions-list";
import * as apiModule from "@/lib/api";
import type { TenantDeletion } from "@/lib/api";

function deletion(overrides: Partial<TenantDeletion> = {}): TenantDeletion {
  return {
    deletion_id: "del_1",
    tenant_id: "acme",
    state: "completed",
    reason: "contract ended",
    requested_by: "root",
    requested_at: "2026-09-10T10:00:00Z",
    purge_after: "2026-09-17T10:00:00Z",
    approved_by: "root2",
    approved_at: "2026-09-18T10:00:00Z",
    cancelled_by: null,
    cancelled_at: null,
    completed_at: "2026-09-18T11:00:00Z",
    attempts: 1,
    last_error: null,
    next_attempt_at: null,
    outcome: {
      tenant_id: "acme",
      stores: {
        postgres: { vulnerabilities: 1200, assets: 30, jobs: 0 },
        artifacts: { run_objects: 52, runs: 4 },
        clickhouse: { vulnerabilities: 0 },
      },
      skipped: { jetstream: "NATS declared unused (OCTO_TENANT_PURGE_UNUSED_STORES)" },
    },
    steps: [],
    ...overrides,
  };
}

function renderList() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TenantDeletionsList />
    </QueryClientProvider>,
  );
}

describe("TenantDeletionsList", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a purged tenant's tombstone after the tenant itself is gone", async () => {
    const fetch = vi.spyOn(apiModule, "fetchTenantDeletions").mockResolvedValue([
      deletion(),
      deletion({
        deletion_id: "del_2",
        tenant_id: "globex",
        state: "blocked",
        approved_by: "root2",
        completed_at: null,
        outcome: null,
        last_error: "postgres: legal hold placed by counsel",
      }),
    ]);
    renderList();

    const table = await screen.findByRole("table", { name: "Deleted and deleting tenants" });
    expect(fetch).toHaveBeenCalledWith({ limit: 50, offset: 0 });
    const acme = within(table).getByText("acme").closest("tr") as HTMLElement;
    // Totals per store, the empty one left out, and the store that was skipped.
    expect(within(acme).getByText("postgres 1230 · artifacts 56")).toBeInTheDocument();
    expect(within(acme).getByText("skipped: jetstream")).toBeInTheDocument();
    expect(within(acme).getByText(/root2/)).toBeInTheDocument();
    const globex = within(table).getByText("globex").closest("tr") as HTMLElement;
    expect(within(globex).getByText(/legal hold placed by counsel/)).toBeInTheDocument();
  });

  it("says so when nothing was ever deleted", async () => {
    vi.spyOn(apiModule, "fetchTenantDeletions").mockResolvedValue([]);
    renderList();
    expect(await screen.findByText("No tenant has been deleted.")).toBeInTheDocument();
  });

  it("pages through a journal longer than one page instead of cutting it off", async () => {
    const page = (from: number, count: number) =>
      Array.from({ length: count }, (_, i) =>
        deletion({ deletion_id: `del_${from + i}`, tenant_id: `tenant-${from + i}` }),
      );
    const fetch = vi
      .spyOn(apiModule, "fetchTenantDeletions")
      .mockImplementation(async ({ offset = 0 } = {}) =>
        offset === 0 ? page(0, 50) : page(offset, 3),
      );
    renderList();

    const table = await screen.findByRole("table", { name: "Deleted and deleting tenants" });
    expect(within(table).getAllByRole("row")).toHaveLength(1 + 50);
    await userEvent.click(screen.getByRole("button", { name: "Show earlier deletions" }));
    expect(await within(table).findByText("tenant-52")).toBeInTheDocument();
    expect(fetch).toHaveBeenLastCalledWith({ limit: 50, offset: 50 });
    expect(within(table).getAllByRole("row")).toHaveLength(1 + 53);
    // A short page is the last one.
    expect(screen.queryByRole("button", { name: "Show earlier deletions" })).toBeNull();
  });
});
