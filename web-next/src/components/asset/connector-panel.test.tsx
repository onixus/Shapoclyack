import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AssetConnectorPanel } from "./connector-panel";
import { api } from "@/lib/api";

const preview = {
  dry_run: true,
  counts: { create: 1, update: 0, unchanged: 0, conflict: 0, invalid: 0 },
  rows: [
    {
      row: 1,
      key: "10.0.0.1",
      status: "create",
      changes: { owner_email: { old: null, new: "ada@example.com" } },
    },
  ],
};

describe("ServiceNow connector", () => {
  afterEach(() => vi.restoreAllMocks());
  it("loads no credential, requires preview and invalidates it on edits", async () => {
    vi.spyOn(api, "get").mockResolvedValue({
      data: {
        servicenow: {
          base_url: "https://snow.example",
          table: "cmdb_ci_computer",
          field_mapping: { ip: "ip_address" },
          interval_seconds: 3600,
          enabled: false,
        },
      },
    });
    const save = vi.spyOn(api, "put").mockResolvedValue({ data: {} });
    const run = vi.spyOn(api, "post").mockResolvedValue({ data: preview });
    render(<AssetConnectorPanel />);
    await waitFor(() =>
      expect(screen.getByLabelText("ServiceNow HTTPS origin")).toHaveValue("https://snow.example"),
    );
    expect(screen.getByText(/LDAP\/AD computer sync is unavailable/)).toBeInTheDocument();
    expect(screen.getByLabelText(/Bearer token/)).toHaveValue("");
    expect(screen.getByRole("button", { name: "Apply after preview" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Preview source" }));
    await waitFor(() => expect(screen.getByText("10.0.0.1")).toBeInTheDocument());
    expect(run).toHaveBeenCalledWith("/assets/import/connector/run", { dry_run: true });
    expect(screen.getByRole("button", { name: "Apply after preview" })).toBeEnabled();
    fireEvent.change(screen.getByLabelText("Table"), { target: { value: "cmdb_ci_server" } });
    expect(screen.getByRole("button", { name: "Apply after preview" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Save connector" }));
    await waitFor(() => expect(save).toHaveBeenCalled());
    expect(save.mock.calls[0][1]).toMatchObject({ token: null, table: "cmdb_ci_server" });
  });
});
