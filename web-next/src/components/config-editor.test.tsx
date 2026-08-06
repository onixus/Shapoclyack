import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfigEditor } from "@/components/config-editor";

const SECRET_MASK = "••••••••";

/** The API masks a stored secret, so that is what the editor is handed. */
const CONFIG = {
  editable_paths: ["enrichment.cvss4.nvd_api_key", "nuclei.retries"],
  defaults: { "nuclei.retries": 1 },
  effective: { "enrichment.cvss4.nvd_api_key": SECRET_MASK, "nuclei.retries": 1 },
  overrides: {},
};

vi.mock("@/hooks/use-config", () => ({
  useConfig: () => ({ data: CONFIG, isLoading: false, error: null }),
  useUpdateConfig: () => ({ mutate: vi.fn(), isPending: false }),
}));

function renderEditor(canEdit = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ConfigEditor canEdit={canEdit} />
    </QueryClientProvider>,
  );
}

describe("ConfigEditor secret fields", () => {
  it("renders an API key as a password input, not readable text", () => {
    renderEditor();
    const input = screen.getByDisplayValue(SECRET_MASK);
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "off");
  });

  it("renders a non-secret field as a normal input", () => {
    renderEditor();
    const input = screen.getByDisplayValue("1");
    expect(input).not.toHaveAttribute("type", "password");
  });

  it("disables the key field for a user who cannot edit", () => {
    renderEditor(false);
    expect(screen.getByDisplayValue(SECRET_MASK)).toBeDisabled();
  });
});
