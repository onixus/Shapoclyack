import axe from "axe-core";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AssetGroups, normalizeGroupRules } from "@/components/asset/asset-groups";
import {
  assetGroupsApi,
  parseRuleValue,
  ruleOperators,
  type AssetGroup,
  type GroupPreview,
} from "@/lib/asset-groups";
import { useAuthStore } from "@/lib/auth-store";
import type { Me } from "@/lib/api";
const GROUP: AssetGroup = {
  id: "g1",
  name: "Production",
  description: "Declared production context",
  enabled: true,
  priority: 100,
  version: 3,
  rules: { all: [{ field: "ip", op: "cidr", value: "10.0.0.0/8" }] },
  context: { business_service: "Payroll" },
  member_count: 21,
  updated_at: "2026-10-24T00:00:00Z",
  last_success_at: "2026-10-23T12:00:00Z",
};
const PREVIEW: GroupPreview = {
  items: [
    {
      asset_id: "a1",
      matched: true,
      reasons: [{ field: "ip", actual: "10.1.1.1" }],
      changes: { business_service: { old: null, new: "Payroll" } },
      conflicts: [],
      entrant: true,
    },
  ],
  evaluated: 1,
  matched: 1,
  entrants: 1,
  exits: 0,
  changed: 1,
  conflicts: 0,
  has_more: false,
};
function renderGroups() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <AssetGroups />
    </QueryClientProvider>,
  );
}
function setRole(role: "operator" | "viewer") {
  const user: Me = {
    username: "tester",
    role,
    tenant_role: role,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    permissions: [],
    scoped_tenant: "default",
  };
  useAuthStore.setState({ user, activeTenant: "default" });
}
async function createDraft() {
  const user = userEvent.setup();
  await user.click(screen.getByRole("button", { name: "Create group" }));
  const dialog = screen.getByRole("dialog");
  await user.type(within(dialog).getByLabelText("Group name"), "Private fleet");
  await user.type(within(dialog).getByLabelText("Value 1.1"), "10.0.0.0/8");
  return { user, dialog };
}
beforeEach(() => {
  vi.restoreAllMocks();
  setRole("operator");
  vi.spyOn(assetGroupsApi, "get").mockResolvedValue(GROUP);
  vi.spyOn(assetGroupsApi, "list").mockResolvedValue({
    items: [],
    total: 0,
    offset: 0,
    limit: 20,
    has_more: false,
  });
  vi.spyOn(assetGroupsApi, "preview").mockResolvedValue(PREVIEW);
  vi.spyOn(assetGroupsApi, "save").mockResolvedValue(GROUP);
  vi.spyOn(assetGroupsApi, "remove").mockResolvedValue(undefined);
  vi.spyOn(assetGroupsApi, "recalculate").mockResolvedValue(PREVIEW);
  vi.spyOn(assetGroupsApi, "members").mockResolvedValue({
    items: [
      {
        asset_id: "a1",
        reasons: [{ field: "ip", matched: true }],
        version: 3,
        evaluated_at: "2026-10-24T00:00:00Z",
      },
    ],
    total: 21,
    offset: 0,
    limit: 20,
    has_more: true,
  });
  vi.spyOn(assetGroupsApi, "evaluations").mockResolvedValue({
    items: [
      {
        id: "eval1",
        version: 3,
        status: "partial",
        completed_at: "2026-10-24T00:00:00Z",
        report: { evaluated: 100, matched: 20, has_more: true },
        error: "Remaining batch awaiting retry",
      },
    ],
    total: 1,
    offset: 0,
    limit: 10,
    has_more: false,
  });
});
describe("dynamic group workflow", () => {
  it("requires the complete current dry-run before save and invalidates it on edits", async () => {
    vi.mocked(assetGroupsApi.preview)
      .mockResolvedValueOnce({ ...PREVIEW, has_more: true, next_asset_id: "a1" })
      .mockResolvedValueOnce({ ...PREVIEW, items: [{ ...PREVIEW.items[0], asset_id: "a2" }] });
    renderGroups();
    const { user, dialog } = await createDraft();
    const save = within(dialog).getByRole("button", { name: "Save group" });
    expect(save).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Preview dry-run" }));
    expect(await within(dialog).findByText(/Incomplete preview/)).toBeVisible();
    expect(save).toBeDisabled();
    expect(assetGroupsApi.save).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Continue preview" }));
    await within(dialog).findByText("Preview complete");
    expect(assetGroupsApi.preview).toHaveBeenLastCalledWith(
      expect.objectContaining({ name: "Private fleet" }),
      undefined,
      "a1",
    );
    expect(save).toBeEnabled();
    await user.type(within(dialog).getByLabelText("Description"), "edited");
    expect(save).toBeDisabled();
    expect(within(dialog).queryByLabelText("Dry-run results")).not.toBeInTheDocument();
  });
  it("builds nested OR conditions without submitting and saves normalized numbers", async () => {
    renderGroups();
    const { user, dialog } = await createDraft();
    await user.click(within(dialog).getByRole("button", { name: "Add nested group 1" }));
    expect(assetGroupsApi.preview).not.toHaveBeenCalled();
    expect(within(dialog).getByLabelText("Match mode 1.2")).toHaveValue("any");
    await user.selectOptions(within(dialog).getByLabelText("Field 1.2.1"), "asset_criticality");
    await user.selectOptions(within(dialog).getByLabelText("Operator 1.2.1"), "in");
    await user.type(within(dialog).getByLabelText("Value 1.2.1 (comma separated)"), "0,4");
    await user.selectOptions(within(dialog).getByLabelText("Criticality"), "0");
    expect(within(dialog).queryByLabelText("Exposure")).not.toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Preview dry-run" }));
    await within(dialog).findByText("Preview complete");
    await user.click(within(dialog).getByRole("button", { name: "Save group" }));
    await waitFor(() =>
      expect(assetGroupsApi.save).toHaveBeenCalledWith(
        expect.objectContaining({
          context: { asset_criticality: 0 },
          rules: {
            all: [
              { field: "ip", op: "cidr", value: "10.0.0.0/8" },
              { any: [{ field: "asset_criticality", op: "in", value: [0, 4] }] },
            ],
          },
        }),
        undefined,
      ),
    );
  });
  it("keeps failed previews unsavable and exposes failures", async () => {
    vi.mocked(assetGroupsApi.preview).mockRejectedValue(new Error("Inventory evaluation failed"));
    renderGroups();
    const { user, dialog } = await createDraft();
    await user.click(within(dialog).getByRole("button", { name: "Preview dry-run" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "Inventory evaluation failed",
    );
    expect(within(dialog).getByRole("button", { name: "Save group" })).toBeDisabled();
  });
  it("shows rule version, last success, incomplete evaluation, explained members and server paging", async () => {
    vi.mocked(assetGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      total: 1,
      offset: 0,
      limit: 20,
      has_more: false,
    });
    renderGroups();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Members & evaluations: Production" }),
    );
    const section = screen.getByRole("region", { name: "Group Production" });
    expect(
      await within(section).findByText(/Last successful evaluation: 2026-10-23/),
    ).toBeVisible();
    expect(await within(section).findByText(/INCOMPLETE/)).toBeVisible();
    expect(within(section).getByRole("alert")).toHaveTextContent("Remaining batch awaiting retry");
    await user.click(within(section).getByText("a1 · rule v3"));
    expect(within(section).getByRole("link", { name: "Open asset" })).toHaveAttribute(
      "href",
      "/assets/view?assetId=a1&tenantId=default",
    );
    await user.click(within(section).getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(assetGroupsApi.members).toHaveBeenLastCalledWith("g1", 20));
  });
  it("previews before recalculation and keeps incomplete apply resumable", async () => {
    vi.mocked(assetGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      total: 1,
      offset: 0,
      limit: 20,
      has_more: false,
    });
    vi.mocked(assetGroupsApi.recalculate)
      .mockResolvedValueOnce({ ...PREVIEW, has_more: true, next_asset_id: "a1" })
      .mockResolvedValueOnce(PREVIEW);
    renderGroups();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Members & evaluations: Production" }),
    );
    expect(screen.getByRole("button", { name: "Apply recalculation" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Preview recalculation" }));
    await screen.findByText("Preview complete");
    await user.click(screen.getByRole("button", { name: "Apply recalculation" }));
    await screen.findByText(/Recalculation incomplete/);
    await user.click(screen.getByRole("button", { name: "Continue recalculation" }));
    await screen.findByText(/Recalculation completed/);
    expect(assetGroupsApi.recalculate).toHaveBeenLastCalledWith("g1", "a1");
  });
  it("supports keyboard open/edit/close and a read-only tenant role", async () => {
    renderGroups();
    const user = userEvent.setup();
    await user.tab();
    expect(screen.getByRole("button", { name: "Create group" })).toHaveFocus();
    await user.keyboard("{Enter}");
    const dialog = screen.getByRole("dialog");
    await waitFor(() => expect(within(dialog).getByLabelText("Group name")).toHaveFocus());
    await user.keyboard("Keyboard fleet");
    expect(within(dialog).getByLabelText("Group name")).toHaveValue("Keyboard fleet");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    setRole("viewer");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Create group" })).not.toBeInTheDocument(),
    );
  });
  it("has an accessible labeled group editor", async () => {
    renderGroups();
    const { dialog } = await createDraft();
    const result = await axe.run(dialog, { rules: { "color-contrast": { enabled: false } } });
    expect(result.violations).toEqual([]);
  });
  it("requires confirmation to delete and leaves failed deletion open", async () => {
    vi.mocked(assetGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      total: 1,
      offset: 0,
      limit: 20,
      has_more: false,
    });
    vi.mocked(assetGroupsApi.remove).mockRejectedValue(new Error("Deletion refused"));
    renderGroups();
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "Delete Production" }));
    expect(assetGroupsApi.remove).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Delete group" }));
    await waitFor(() => expect(assetGroupsApi.remove).toHaveBeenCalledWith("g1"));
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });
});
describe("tenant isolation and current evaluation", () => {
  it("clears editor and selection when the effective tenant changes under automatic selection", async () => {
    vi.mocked(assetGroupsApi.list)
      .mockResolvedValueOnce({ items: [GROUP], total: 1, offset: 0, limit: 20, has_more: false })
      .mockResolvedValue({
        items: [{ ...GROUP, description: "Tenant B context" }],
        total: 1,
        offset: 0,
        limit: 20,
        has_more: false,
      });
    renderGroups();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Members & evaluations: Production" }),
    );
    await user.click(screen.getByRole("button", { name: "Edit Production" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    const principal = useAuthStore.getState().user!;
    act(() =>
      useAuthStore.setState({
        activeTenant: null,
        user: {
          ...principal,
          scoped_tenant: "tenant-b",
          default_tenant: "tenant-b",
          tenants: ["default", "tenant-b"],
        },
      }),
    );
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Group Production" })).not.toBeInTheDocument();
    expect(await screen.findByText("Tenant B context")).toBeVisible();
    expect(screen.getByText("Tenant: tenant-b")).toBeVisible();
    expect(screen.queryByText("Declared production context")).not.toBeInTheDocument();
  });
  it("uses separate query caches for different accounts in the same tenant", async () => {
    vi.mocked(assetGroupsApi.list)
      .mockResolvedValueOnce({ items: [GROUP], total: 1, offset: 0, limit: 20, has_more: false })
      .mockResolvedValue({ items: [], total: 0, offset: 0, limit: 20, has_more: false });
    renderGroups();
    await screen.findByText("Declared production context");
    const principal = useAuthStore.getState().user!;
    act(() => useAuthStore.setState({ user: { ...principal, username: "other-account" } }));
    expect(screen.queryByText("Declared production context")).not.toBeInTheDocument();
    expect(await screen.findByText("No dynamic groups in this tenant.")).toBeVisible();
    expect(assetGroupsApi.list).toHaveBeenCalledTimes(2);
  });
  it("distinguishes failed current-version evaluation from past success and pages history", async () => {
    vi.mocked(assetGroupsApi.get).mockResolvedValue({ ...GROUP, version: 4 });
    vi.mocked(assetGroupsApi.list).mockResolvedValue({
      items: [
        {
          ...GROUP,
          version: 4,
          latest_evaluation: {
            id: "failed4",
            version: 4,
            status: "failed",
            error: "Worker failed",
          },
        },
      ],
      total: 1,
      offset: 0,
      limit: 20,
      has_more: false,
    });
    vi.mocked(assetGroupsApi.evaluations).mockResolvedValue({
      items: [{ id: "old3", version: 3, status: "completed", completed_at: GROUP.last_success_at }],
      total: 21,
      offset: 0,
      limit: 20,
      has_more: true,
    });
    renderGroups();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Members & evaluations: Production" }),
    );
    const region = screen.getByRole("region", { name: "Group Production" });
    expect(await within(region).findByText(/Current rule v4: failed/)).toBeVisible();
    expect(within(region).getByRole("alert")).toHaveTextContent("Worker failed");
    expect(within(region).getByText(/Last success above may belong to an earlier/)).toBeVisible();
    expect(
      await within(region).findByText(/previous rule version, awaiting reevaluation/),
    ).toBeVisible();
    await user.click(within(region).getByRole("button", { name: "Next evaluations page" }));
    await waitFor(() => expect(assetGroupsApi.evaluations).toHaveBeenLastCalledWith("g1", 20));
  });
  it("refreshes the selected rule version independently of the current list page", async () => {
    vi.mocked(assetGroupsApi.list).mockResolvedValue({
      items: [GROUP],
      total: 21,
      offset: 0,
      limit: 20,
      has_more: true,
    });
    vi.mocked(assetGroupsApi.get).mockResolvedValue({ ...GROUP, version: 5 });
    renderGroups();
    const user = userEvent.setup();
    await user.click(
      await screen.findByRole("button", { name: "Members & evaluations: Production" }),
    );
    const region = screen.getByRole("region", { name: "Group Production" });
    expect(await within(region).findByText(/Current rule v5: awaiting evaluation/)).toBeVisible();
    expect(await within(region).findByText(/rule v3 · previous rule version/)).toBeVisible();
    expect(assetGroupsApi.get).toHaveBeenCalledWith("g1");
  });
  it("offers only confirmed endpoint OS families and shows source freshness with observed snapshot evidence", async () => {
    vi.mocked(assetGroupsApi.preview).mockResolvedValue({
      ...PREVIEW,
      items: [
        {
          ...PREVIEW.items[0],
          reasons: [
            {
              field: "os_family",
              op: "eq",
              value: "windows",
              actual: ["windows"],
              result: "matched",
              evidence: {
                source: "endpoint_inventory",
                state: "confirmed",
                freshness_hours: 48,
                observations: [
                  {
                    device_id: "dev1",
                    snapshot_id: "snap1",
                    family: "windows",
                    collected_at: "2026-10-24T12:00:00Z",
                    received_at: "2026-10-24T12:01:00Z",
                    reconciliation_status: "linked",
                  },
                ],
              },
            },
          ],
          changes: {
            business_service: { old: null, new: "Payroll", group_id: "winner-group", version: 9 },
          },
        },
      ],
    });
    renderGroups();
    const { user, dialog } = await createDraft();
    await user.selectOptions(within(dialog).getByLabelText("Field 1.1"), "os_family");
    expect(within(dialog).getByText(/All linked devices must agree/)).toBeVisible();
    expect(within(dialog).getByLabelText("Operator 1.1").querySelectorAll("option")).toHaveLength(
      4,
    );
    await user.selectOptions(within(dialog).getByLabelText("Value 1.1"), "windows");
    await user.click(within(dialog).getByRole("button", { name: "Preview dry-run" }));
    await within(dialog).findByText("Preview complete");
    expect(assetGroupsApi.preview).toHaveBeenCalledWith(
      expect.objectContaining({
        rules: { all: [{ field: "os_family", op: "eq", value: "windows" }] },
      }),
      undefined,
      undefined,
    );
    await user.click(within(dialog).getByText(/a1 · matches/));
    expect(
      within(dialog).getByText(
        /Source: authenticated endpoint inventory · confirmed · freshness limit 48 hours/,
      ),
    ).toBeVisible();
    expect(within(dialog).getByText(/Device dev1 · snapshot snap1/)).toBeVisible();
    expect(within(dialog).getByText(/group winner-group · rule v9/)).toBeVisible();
    expect(
      within(dialog).getByText(/Context changes resolve priorities across all active groups/),
    ).toBeVisible();
  });
});
describe("typed group input", () => {
  it("limits IP operators and validates numeric lists without converting empty input to zero", () => {
    expect(ruleOperators("ip")).toEqual(["eq", "ne", "in", "not_in", "cidr"]);
    expect(ruleOperators("asset_criticality")).not.toContain("contains");
    expect(ruleOperators("os_family")).toEqual(["eq", "ne", "in", "not_in"]);
    expect(parseRuleValue("os_family", "in", "windows,linux")).toEqual(["windows", "linux"]);
    expect(() => parseRuleValue("os_family", "eq", "guessed-windows")).toThrow(
      /Confirmed OS family/,
    );
    expect(parseRuleValue("asset_criticality", "in", "0,4")).toEqual([0, 4]);
    expect(() => parseRuleValue("asset_criticality", "eq", "")).toThrow(/empty/);
    expect(() => parseRuleValue("asset_criticality", "eq", "5")).toThrow(/0–4/);
    expect(
      normalizeGroupRules({ any: [{ field: "status", op: "eq", value: "active" }], negate: true }),
    ).toEqual({ any: [{ field: "status", op: "eq", value: "active" }], negate: true });
  });
});
