import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AssetImportButton } from "@/components/asset/import-dialog";
import * as apiModule from "@/lib/api";
import type { AssetImportReport, Me } from "@/lib/api";
import { useAppearanceStore } from "@/lib/appearance";
import { useAuthStore } from "@/lib/auth-store";

function member(role: string, permissions: string[], global: Me["role"] = "viewer"): Me {
  return {
    username: "cmdb-owner",
    role: global,
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: false,
    tenant_role: role,
    permissions,
    scoped_tenant: "default",
  };
}

function renderButton() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <AssetImportButton />
    </QueryClientProvider>,
  );
}

const PREVIEW: AssetImportReport = {
  dry_run: true,
  format: "csv",
  sha256: "abc",
  context_source: "cmdb",
  overwrite_operator_edits: false,
  link_new_identifiers: false,
  total: 2,
  counts: { create: 1, update: 0, unchanged: 0, conflict: 1, invalid: 0 },
  codes: { operator_override: 1 },
  ignored_columns: [],
  rows: [
    {
      row: 1,
      status: "create",
      key: "10.0.0.1",
      code: null,
      message: null,
      asset_id: "a1",
      changes: { owner_email: { old: null, new: "ada@example.com" } },
      identifiers_added: ["ip:10.0.0.1"],
      conflicting_fields: [],
    },
    {
      row: 2,
      status: "conflict",
      key: "10.0.0.2",
      code: "operator_override",
      message: "an operator set owner_email by hand",
      asset_id: "a2",
      changes: {},
      identifiers_added: [],
      conflicting_fields: ["owner_email"],
    },
  ],
  replayed: false,
};

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function csvFile(text: string, name = "export.csv"): File {
  return new File([text], name, { type: "text/csv" });
}

/** A file whose bytes arrive only when the test says so. */
function slowFile(text: string, name = "next.csv") {
  const file = csvFile(text, name);
  const bytes = deferred<ArrayBuffer>();
  Object.defineProperty(file, "arrayBuffer", { value: () => bytes.promise });
  return { file, arrive: () => bytes.resolve(new TextEncoder().encode(text).buffer) };
}

function pick(file: File) {
  const input = document.getElementById("asset-import-file") as HTMLInputElement;
  fireEvent.change(input, { target: { files: [file] } });
}

describe("AssetImportButton", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: null });
    useAppearanceStore.setState({ locale: "en" });
  });

  it("offers neither button while a newly picked file is still being read", async () => {
    useAuthStore.setState({ user: member("admin", ["asset.import"]) });
    const importAssets = vi
      .spyOn(apiModule, "importAssets")
      .mockImplementation(async (body) => ({ ...PREVIEW, dry_run: body.dry_run }));
    renderButton();
    fireEvent.click(screen.getByRole("button", { name: /Import/ }));
    pick(csvFile("ip\n10.0.0.1\n"));
    const previewButton = await screen.findByRole("button", { name: "Preview" });
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);
    await waitFor(() => expect(screen.getByRole("button", { name: "Apply" })).toBeEnabled());

    const next = slowFile("ip\n10.9.9.9\n");
    pick(next.file);

    // Until the new text is in hand, Preview would send the previous file and
    // its answer would unlock Apply for this one.
    await waitFor(() => expect(screen.getByRole("button", { name: "Preview" })).toBeDisabled());
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    await act(async () => next.arrive());
    await waitFor(() => expect(screen.getByRole("button", { name: "Preview" })).toBeEnabled());
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(importAssets).toHaveBeenCalledTimes(2));
    expect(importAssets.mock.calls[1][0]).toMatchObject({ content: "ip\n10.9.9.9\n" });
  });

  it("drops a preview answer that arrives after the file changed", async () => {
    useAuthStore.setState({ user: member("admin", ["asset.import"]) });
    const answer = deferred<AssetImportReport>();
    vi.spyOn(apiModule, "importAssets").mockImplementation(() => answer.promise);
    renderButton();
    fireEvent.click(screen.getByRole("button", { name: /Import/ }));
    pick(csvFile("ip\n10.0.0.1\n"));
    const previewButton = await screen.findByRole("button", { name: "Preview" });
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);

    pick(csvFile("ip\n10.9.9.9\n", "other.csv"));
    await screen.findByText(/other\.csv/);
    await act(async () => answer.resolve(PREVIEW));

    expect(screen.queryByTestId("asset-import-report")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();
  });

  it("says what the apply did in the console's language", async () => {
    useAuthStore.setState({ user: member("admin", ["asset.import"]) });
    useAppearanceStore.setState({ locale: "ru" });
    const success = vi.spyOn(toast, "success");
    vi.spyOn(apiModule, "importAssets").mockImplementation(async (body) => ({
      ...PREVIEW,
      dry_run: body.dry_run,
    }));
    renderButton();
    fireEvent.click(screen.getByRole("button", { name: /Импорт/ }));
    pick(csvFile("ip\n10.0.0.1\n"));
    const previewButton = await screen.findByRole("button", { name: "Предпросмотр" });
    await waitFor(() => expect(previewButton).toBeEnabled());
    fireEvent.click(previewButton);
    const applyButton = screen.getByRole("button", { name: "Применить" });
    await waitFor(() => expect(applyButton).toBeEnabled());
    fireEvent.click(applyButton);

    await waitFor(() =>
      expect(success).toHaveBeenCalledWith("Импорт применён: создано 1, обновлено 0"),
    );
  });

  it("is not offered to a global operator who lacks asset.import in this tenant", () => {
    // The global role used to be the gate across the console; the import is a
    // tenant permission, and a global operator does not hold it.
    useAuthStore.setState({ user: member("operator", ["scan.cancel"], "operator") });
    renderButton();
    expect(screen.queryByRole("button", { name: /Import/ })).not.toBeInTheDocument();
  });

  it("is offered to a tenant admin whose account is globally a viewer", () => {
    useAuthStore.setState({ user: member("admin", ["asset.import"]) });
    renderButton();
    expect(screen.getByRole("button", { name: /Import/ })).toBeInTheDocument();
  });

  it("previews as a dry run and applies the same file without dry_run", async () => {
    useAuthStore.setState({ user: member("admin", ["asset.import"]) });
    const importAssets = vi
      .spyOn(apiModule, "importAssets")
      .mockImplementation(async (body) => ({ ...PREVIEW, dry_run: body.dry_run }));
    renderButton();
    fireEvent.click(screen.getByRole("button", { name: /Import/ }));

    const input = document.getElementById("asset-import-file") as HTMLInputElement;
    const file = new File(["ip,owner\n10.0.0.1,ada@example.com\n"], "export.csv", {
      type: "text/csv",
    });
    fireEvent.change(input, { target: { files: [file] } });
    const previewButton = await screen.findByRole("button", { name: "Preview" });
    await waitFor(() => expect(previewButton).toBeEnabled());
    // Apply is not offered before a preview of this file.
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled();

    fireEvent.click(previewButton);
    await screen.findByText("an operator set owner_email by hand");
    expect(importAssets).toHaveBeenLastCalledWith(
      expect.objectContaining({ format: "csv", dry_run: true, context_source: "cmdb" }),
    );

    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    await waitFor(() => expect(importAssets).toHaveBeenCalledTimes(2));
    const [body, options] = importAssets.mock.calls[1];
    expect(body).toMatchObject({ dry_run: false, content: "ip,owner\n10.0.0.1,ada@example.com\n" });
    expect(options?.idempotencyKey).toBeTruthy();
  });
});
