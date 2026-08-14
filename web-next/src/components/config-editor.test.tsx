import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfigEditor } from "@/components/config-editor";

const SECRET_MASK = "••••••••";

/** The API masks a stored secret, so that is what the editor is handed. */
const CONFIG = {
  editable_paths: [
    "enrichment.cvss4.nvd_api_key",
    "nuclei.retries",
    // A boolean whose path does not end in ".enabled" — it must still get a
    // checkbox, since a number input would send 0/1 and the API rejects that.
    "tls_posture.hostname_mismatch",
    // naabu takes only 100 or 1000 here, so this is a choice, not a number.
    "profiles.safe.top_ports",
  ],
  defaults: {
    "nuclei.retries": 1,
    "tls_posture.hostname_mismatch": true,
    "profiles.safe.top_ports": 100,
  },
  effective: {
    "enrichment.cvss4.nvd_api_key": SECRET_MASK,
    "nuclei.retries": 1,
    "tls_posture.hostname_mismatch": true,
    "profiles.safe.top_ports": 100,
  },
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

  it("renders any boolean setting as a checkbox, not a number input", () => {
    renderEditor();
    const box = screen.getByRole("checkbox");
    expect(box).toHaveAttribute("data-state", "checked");
    expect(screen.queryByDisplayValue("true")).toBeNull();
  });

  it("renders top_ports as a choice, not a free number input", () => {
    renderEditor();
    // A number input would happily accept 500, which naabu cannot parse and
    // the API rejects — the operator only gets the two port sets that work.
    expect(screen.queryByDisplayValue("100")).toBeNull();
    expect(screen.getByRole("combobox")).toHaveTextContent("100");
  });

  it("disables the key field for a user who cannot edit", () => {
    renderEditor(false);
    expect(screen.getByDisplayValue(SECRET_MASK)).toBeDisabled();
  });
});
