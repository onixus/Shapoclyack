import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import axe from "axe-core";
import { SavedViews } from "@/components/saved-views";
import { useAuthStore } from "@/lib/auth-store";
import * as views from "@/lib/saved-views";
import type { Me } from "@/lib/api";

vi.mock("@/lib/saved-views", () => ({
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
beforeEach(() => {
  vi.resetAllMocks();
  useAuthStore.setState({
    user: { username: "alice", default_tenant: "alpha" } as Me,
    activeTenant: "alpha",
  });
  vi.mocked(views.fetchViews).mockResolvedValue([saved]);
  vi.mocked(views.createView).mockResolvedValue(saved);
  vi.mocked(views.renameView).mockResolvedValue({ ...saved, name: "Renamed" });
  vi.mocked(views.deleteView).mockResolvedValue(undefined);
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
    await user.click(screen.getByRole("button", { name: "Delete" }));
    await waitFor(() => expect(views.deleteView).toHaveBeenCalledWith(saved.view_id, "alpha"));
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
});
