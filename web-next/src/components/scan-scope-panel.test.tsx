import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { format } from "date-fns";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ScanScopePanel } from "@/components/scan-scope-panel";
import * as apiModule from "@/lib/api";
import type { PromotedDomainInfo, ScanScopeEntry } from "@/lib/api";

function entry(overrides: Partial<ScanScopeEntry> = {}): ScanScopeEntry {
  return {
    id: 1,
    tenant_id: "default",
    effect: "allow",
    kind: "cidr",
    value: "198.51.100.0/28",
    note: "lab",
    approved_by: "admin",
    approved_at: "2026-09-01T10:00:00Z",
    ...overrides,
  };
}

function promoted(overrides: Partial<PromotedDomainInfo> = {}): PromotedDomainInfo {
  return {
    tenant_id: "default",
    domain: "shop.example.test",
    source_run_id: "run_1",
    promoted_by: "operator",
    promoted_at: "2026-09-02T08:00:00Z",
    ...overrides,
  };
}

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ScanScopePanel tenantId="default" />
    </QueryClientProvider>,
  );
  return queryClient;
}

/** The panel renders timestamps in the reader's timezone, like every other
 * table in the console, so the expectation is computed the same way rather
 * than pinned to the timezone the suite happens to run in. */
function shown(iso: string) {
  return format(new Date(iso), "yyyy-MM-dd HH:mm");
}

describe("ScanScopePanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(apiModule, "fetchPromotedDomains").mockResolvedValue([]);
  });

  it("shows the approved entries with the approval they were written under", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([
      entry(),
      entry({
        id: 2,
        effect: "deny",
        value: "169.254.0.0/16",
        note: "cloud metadata",
        approved_at: "2026-09-03T11:30:00Z",
      }),
    ]);
    vi.spyOn(apiModule, "fetchPromotedDomains").mockResolvedValue([promoted()]);

    renderPanel();

    expect(await screen.findByText("198.51.100.0/28")).toBeInTheDocument();
    expect(screen.getByText("169.254.0.0/16")).toBeInTheDocument();
    expect(screen.getByText("cloud metadata")).toBeInTheDocument();
    expect(screen.getAllByText("admin").length).toBeGreaterThan(0);
    expect(screen.getByText(shown("2026-09-01T10:00:00Z"))).toBeInTheDocument();
    expect(screen.getByText(shown("2026-09-03T11:30:00Z"))).toBeInTheDocument();
    expect(await screen.findByText("shop.example.test")).toBeInTheDocument();
  });

  it("tells the admin a tenant with nothing approved cannot scan", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([]);
    renderPanel();
    expect(await screen.findByText(/cannot start a scan/i)).toBeInTheDocument();
  });

  it("keeps approval disabled until something actually changes", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([entry()]);
    renderPanel();

    // Wait for the editor to be seeded from the approved scope: before that
    // there is nothing to be unchanged from.
    const note = await screen.findByLabelText("Note 1");
    const approve = screen.getByRole("button", { name: /approve scope/i });
    expect(approve).toBeDisabled();

    await userEvent.type(note, " east");
    expect(approve).toBeEnabled();
  });

  it("sends the whole scope, edits and untouched rows alike", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([
      entry(),
      entry({ id: 2, effect: "deny", value: "169.254.0.0/16", note: "cloud metadata" }),
    ]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();

    // Edit the first row and add a third; the second is never touched.
    const value = await screen.findByLabelText("Value 1");
    await userEvent.clear(value);
    await userEvent.type(value, "198.51.100.0/24");
    await userEvent.click(screen.getByRole("button", { name: /add entry/i }));
    await userEvent.type(screen.getByLabelText("Value 3"), "example.test");
    await userEvent.selectOptions(screen.getByLabelText("Kind 3"), "domain");
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith("default", [
        { effect: "allow", kind: "cidr", value: "198.51.100.0/24", note: "lab" },
        { effect: "deny", kind: "cidr", value: "169.254.0.0/16", note: "cloud metadata" },
        { effect: "allow", kind: "domain", value: "example.test", note: "" },
      ]),
    );
  });

  it("warns about a value it does not recognise and sends it anyway", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([entry()]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();
    const value = await screen.findByLabelText("Value 1");
    await userEvent.clear(value);
    await userEvent.type(value, "example.test");

    // A warning under the row, not a refusal: the API is the authority, and
    // an editor that blocked here would be the one deciding what is a value.
    expect(await screen.findByText(/does not look like an IP address/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith("default", [
        { effect: "allow", kind: "cidr", value: "example.test", note: "lab" },
      ]),
    );
  });

  it("sends an IPv4-mapped address the API accepts without calling it wrong", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([entry()]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();
    const value = await screen.findByLabelText("Value 1");
    await userEvent.clear(value);
    await userEvent.type(value, "::ffff:169.254.169.254");

    expect(screen.queryByText(/does not look like an IP address/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith("default", [
        { effect: "allow", kind: "cidr", value: "::ffff:169.254.169.254", note: "lab" },
      ]),
    );
  });

  it("refuses only an empty value, and says which row", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([entry()]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();
    await userEvent.clear(await screen.findByLabelText("Value 1"));

    expect(screen.getByText(/Row 1: a value is required/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /approve scope/i })).toBeDisabled();
    expect(replace).not.toHaveBeenCalled();
  });

  it("shows what the server stored, even when it equals the scope before the edit", async () => {
    // The API normalises a value (10.0.0.5/24 is stored as 10.0.0.0/24), so a
    // successful save can answer with the list the editor started from. The
    // editor must still show the answer: otherwise the field keeps the host
    // address nobody approved and offers to approve it again.
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([
      entry({ value: "10.0.0.0/24", note: "" }),
    ]);
    const replace = vi
      .spyOn(apiModule, "replaceScanScope")
      .mockResolvedValue([entry({ value: "10.0.0.0/24", note: "" })]);

    renderPanel();
    const value = await screen.findByLabelText("Value 1");
    await userEvent.clear(value);
    await userEvent.type(value, "10.0.0.5/24");
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(screen.getByLabelText("Value 1")).toHaveValue("10.0.0.0/24"));
    expect(screen.getByRole("button", { name: /approve scope/i })).toBeDisabled();
  });

  it("does not overwrite a scope another admin changed while the dialog was open", async () => {
    // The endpoint replaces the whole list and offers no ETag, so the check is
    // a fresh read taken at the moment of the write.
    vi.spyOn(apiModule, "fetchScanScope")
      .mockResolvedValueOnce([entry()])
      .mockResolvedValue([entry(), entry({ id: 2, effect: "deny", value: "169.254.0.0/16" })]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();
    await userEvent.type(await screen.findByLabelText("Note 1"), " east");
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    // Nothing was sent, and the editor now starts from what is actually
    // approved — including the entry the other admin added.
    await waitFor(() => expect(screen.getByLabelText("Value 2")).toHaveValue("169.254.0.0/16"));
    expect(replace).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Note 1")).toHaveValue("lab");
  });

  it("warns before an empty scope is approved, and still lets it through", async () => {
    vi.spyOn(apiModule, "fetchScanScope").mockResolvedValue([entry()]);
    const replace = vi.spyOn(apiModule, "replaceScanScope").mockResolvedValue([]);

    renderPanel();
    await userEvent.click(await screen.findByRole("button", { name: /remove entry 1/i }));

    expect(screen.getByText(/will not be able to scan anything/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /approve scope/i }));

    await waitFor(() => expect(replace).toHaveBeenCalledWith("default", []));
  });
});
