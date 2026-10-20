import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AxiosError } from "axios";
import { beforeEach, describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { SavedViews } from "@/components/saved-views";
import { useAuthStore } from "@/lib/auth-store";
import * as views from "@/lib/saved-views";
import type { Me } from "@/lib/api";

vi.mock("@/lib/saved-views", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/saved-views")>()),
  fetchViews: vi.fn(),
  createView: vi.fn(),
  renameView: vi.fn(),
  deleteView: vi.fn(),
}));
const state: views.ViewState = {
  version: 1,
  search: "router",
  sort: "last_seen",
  order: "desc",
  filters: { unowned: true },
};
const saved = {
  view_id: "view-a",
  page: "assets" as const,
  name: "My routers",
  compatible: true,
  state,
};
function renderViews() {
  const onApply = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(
    <QueryClientProvider client={client}>
      <SavedViews page="assets" state={state} onApply={onApply} />
    </QueryClientProvider>,
  );
  return { ...result, onApply };
}
// A server-side list the mocked endpoints really mutate, so a test only passes
// when the component refetches after a mutation.
let server: (typeof saved)[] = [];
function refused(status: number, code?: string) {
  return new AxiosError("refused", "ERR_BAD_REQUEST", undefined, undefined, {
    status,
    data: code ? { detail: { code, message: "refused" } } : {},
    statusText: "",
    headers: {},
    config: {} as never,
  });
}
beforeEach(() => {
  vi.resetAllMocks();
  server = [saved];
  useAuthStore.setState({
    user: { username: "alice", default_tenant: "alpha" } as Me,
    activeTenant: "alpha",
  });
  vi.mocked(views.fetchViews).mockImplementation(async () => structuredClone(server));
  vi.mocked(views.createView).mockImplementation(async () => saved);
  vi.mocked(views.renameView).mockImplementation(async (id, name) => {
    server = server.map((item) => (item.view_id === id ? { ...item, name } : item));
    return server.find((item) => item.view_id === id)!;
  });
  vi.mocked(views.deleteView).mockImplementation(async (id) => {
    server = server.filter((item) => item.view_id !== id);
  });
});

describe("personal saved views", () => {
  it("creates, applies, renames and deletes a view using labeled keyboard controls", async () => {
    const user = userEvent.setup();
    const { onApply } = renderViews();
    await screen.findByRole("option", { name: saved.name });
    await user.tab();
    expect(screen.getByRole("combobox", { name: "Saved views" })).toHaveFocus();
    await user.tab();
    expect(screen.getByLabelText("View name")).toHaveFocus();
    await user.type(screen.getByLabelText("View name"), saved.name);
    await user.tab();
    await user.keyboard("{Enter}");
    await waitFor(() =>
      expect(views.createView).toHaveBeenCalledWith("assets", saved.name, state, "alpha"),
    );
    await screen.findByText("Saved views updated.");
    expect(screen.getByRole("button", { name: "Save current filters" })).toHaveFocus();
    await user.click(screen.getByRole("button", { name: "Apply" }));
    expect(onApply).toHaveBeenCalledWith(state);
    expect(screen.getByRole("status")).toHaveTextContent("View applied");
    await user.clear(screen.getByLabelText("View name"));
    await user.type(screen.getByLabelText("View name"), "Renamed");
    await user.click(screen.getByRole("button", { name: "Rename" }));
    await waitFor(() =>
      expect(views.renameView).toHaveBeenCalledWith(saved.view_id, "Renamed", "alpha"),
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Rename" })).toHaveFocus());
    // The list is refetched: the select now shows the new name, not the old one.
    expect(await screen.findByRole("option", { name: "Renamed" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: saved.name })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(views.deleteView).toHaveBeenCalledWith(saved.view_id, "alpha"));
    await waitFor(() =>
      expect(screen.queryByRole("option", { name: "Renamed" })).not.toBeInTheDocument(),
    );
    await waitFor(() => expect(screen.getByLabelText("View name")).toHaveFocus());
  });
  it("isolates selection and fetches across account and tenant changes", async () => {
    const user = userEvent.setup();
    renderViews();
    await screen.findByRole("option", { name: saved.name });
    await user.selectOptions(screen.getByRole("combobox", { name: "Saved views" }), saved.view_id);
    act(() => useAuthStore.setState({ activeTenant: "beta" }));
    expect(screen.getByLabelText("View name")).toHaveValue("");
    await waitFor(() =>
      expect(views.fetchViews).toHaveBeenCalledWith("assets", "beta", expect.any(AbortSignal)),
    );
    act(() => useAuthStore.setState({ user: { username: "bob", default_tenant: "beta" } as Me }));
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    await waitFor(() => expect(views.fetchViews).toHaveBeenCalledTimes(3));
  });
  it("refuses incompatible schema and announces load failures", async () => {
    vi.mocked(views.fetchViews).mockResolvedValue([{ ...saved, compatible: false }]);
    const user = userEvent.setup();
    renderViews();
    await screen.findByRole("option", { name: saved.name });
    await user.selectOptions(screen.getByRole("combobox", { name: "Saved views" }), saved.view_id);
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    expect(screen.getByRole("alert")).toHaveTextContent("incompatible filter schema");
  });
  it("has no automated WCAG A/AA violations for the saved-view controls", async () => {
    const { container } = renderViews();
    await screen.findByRole("option", { name: saved.name });
    const result = await axe.run(container, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"] },
      rules: { "color-contrast": { enabled: false } },
    });
    expect(result.violations).toEqual([]);
  });
  it.each([
    [409, "saved_view_limit", "already have 50 saved views"],
    [409, "saved_view_duplicate_name", "view with this name on this page"],
    [422, undefined, "filters cannot be saved"],
    [400, undefined, "Could not update saved views"],
    [500, undefined, "Could not update saved views"],
  ])("explains a %i %s refusal of the save", async (status, code, text) => {
    vi.mocked(views.createView).mockRejectedValue(refused(status, code));
    const user = userEvent.setup();
    renderViews();
    await screen.findByRole("option", { name: saved.name });
    await user.type(screen.getByLabelText("View name"), "Another");
    await user.click(screen.getByRole("button", { name: "Save current filters" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(text);
  });
  it("refreshes the list and clears the selection when the view was deleted elsewhere", async () => {
    const user = userEvent.setup();
    renderViews();
    await screen.findByRole("option", { name: saved.name });
    await user.selectOptions(screen.getByRole("combobox", { name: "Saved views" }), saved.view_id);
    server = [];
    vi.mocked(views.renameView).mockRejectedValue(refused(404));
    await user.clear(screen.getByLabelText("View name"));
    await user.type(screen.getByLabelText("View name"), "Renamed");
    await user.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no longer exists");
    await waitFor(() =>
      expect(screen.queryByRole("option", { name: saved.name })).not.toBeInTheDocument(),
    );
    expect(screen.getByRole("combobox", { name: "Saved views" })).toHaveValue("");
    expect(screen.getByLabelText("View name")).toHaveValue("");
  });
});
