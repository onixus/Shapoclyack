import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OperatorSettings } from "./operator-settings";
import { operatorSettingsApi, type SettingsSnapshot } from "@/lib/operator-settings-api";
import { useAppearanceStore } from "@/lib/appearance";

const snapshot: SettingsSnapshot = {
  enabled: true,
  worker_enabled: true,
  external_permitted: false,
  effective: {
    provider: "local",
    base_url: "http://10.0.0.5/v1",
    model: "m",
    allow_external: false,
    timeout_seconds: 120,
    max_output_tokens: 1024,
    api_key_set: true,
  },
  deployment: {
    provider: "local",
    base_url: "",
    model: "original",
    allow_external: false,
    timeout_seconds: 120,
    max_output_tokens: 1024,
  },
  override: null,
  valid: true,
  error: null,
};
function setup() {
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <OperatorSettings actor="root" />
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  vi.restoreAllMocks();
  useAppearanceStore.setState({ locale: "en" });
  vi.spyOn(operatorSettingsApi, "get").mockResolvedValue(snapshot);
  vi.spyOn(operatorSettingsApi, "save").mockResolvedValue(snapshot);
  vi.spyOn(operatorSettingsApi, "reset").mockResolvedValue(undefined);
  vi.spyOn(operatorSettingsApi, "test").mockResolvedValue({
    ok: true,
    error: null,
    completion: "not_checked",
    models: [{ id: "discovered", context_tokens: 8192 }],
  });
});
describe("installation operator settings", () => {
  it("tests an unsaved candidate, lists models and only sends editable fields", async () => {
    setup();
    await screen.findByText("AI connection settings (installation-wide)");
    const user = userEvent.setup();
    await user.click(screen.getByText("AI connection settings (installation-wide)"));
    await user.clear(screen.getByLabelText("API base URL"));
    await user.type(screen.getByLabelText("API base URL"), "http://10.0.0.9/v1");
    await user.click(screen.getByRole("button", { name: "Discover models" }));
    await waitFor(() =>
      expect(operatorSettingsApi.test).toHaveBeenCalledWith(
        {
          provider: "local",
          base_url: "http://10.0.0.9/v1",
          model: "m",
          allow_external: false,
          timeout_seconds: 120,
          max_output_tokens: 1024,
          api_key: undefined,
        },
        false,
      ),
    );
    expect(operatorSettingsApi.save).not.toHaveBeenCalled();
    expect(screen.getByText(/Discovered models/)).toHaveTextContent("discovered");
    expect(screen.getByLabelText("Allow sending task data to this cloud provider")).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(operatorSettingsApi.save).toHaveBeenCalled());
    expect(operatorSettingsApi.save).toHaveBeenCalledWith(
      expect.not.objectContaining({ api_key_set: true }),
    );
  });
  it("clears the password after saving and restores deployment settings", async () => {
    setup();
    await screen.findByText("AI connection settings (installation-wide)");
    const user = userEvent.setup();
    await user.click(screen.getByText("AI connection settings (installation-wide)"));
    const password = screen.getByLabelText(/API key \(blank/);
    await user.type(password, "test-key");
    await user.click(screen.getByRole("button", { name: "Save connection" }));
    await waitFor(() => expect(password).toHaveValue(""));
    expect(operatorSettingsApi.save).toHaveBeenCalledWith(
      expect.objectContaining({ api_key: "test-key" }),
    );
    await user.click(screen.getByRole("button", { name: "Restore deployment settings" }));
    await waitFor(() => expect(operatorSettingsApi.reset).toHaveBeenCalled());
  });
});
