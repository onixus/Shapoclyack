import { useAppearanceStore } from "@/lib/appearance";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ConfigEditor } from "@/components/config-editor";

const updateMock = vi.hoisted(() => vi.fn());
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
  useUpdateConfig: () => ({ mutate: updateMock, isPending: false }),
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
  it("shows Russian labels, preserves technical keys and never copies secrets into disclosures", async () => {
    useAppearanceStore.setState({ locale: "ru" });
    renderEditor();
    expect(screen.getByText("Профиль: Безопасный")).toBeVisible();
    expect(screen.getByText("Проверять соответствие имени сертификата")).toBeVisible();
    expect(screen.getByRole("button", { name: "Сохранить изменения" })).toBeVisible();
    for (const pre of Array.from(document.querySelectorAll("pre")))
      expect(pre).not.toHaveTextContent(SECRET_MASK);
    const keyInput = screen.getByDisplayValue(SECRET_MASK);
    expect(keyInput).toHaveAttribute("type", "password");
    const technical = keyInput.closest("details")!;
    expect(technical).not.toHaveAttribute("open");
    await userEvent.setup().click(technical.querySelector("summary")!);
    expect(keyInput).toHaveAttribute("type", "password");
    expect(document.body.textContent).toContain("enrichment.cvss4.nvd_api_key");
    await userEvent
      .setup()
      .click(screen.getByLabelText("Проверять соответствие имени сертификата"));
    await userEvent.setup().click(screen.getByRole("button", { name: "Сохранить изменения" }));
    expect(updateMock.mock.calls.at(-1)?.[0]).toMatchObject({
      "tls_posture.hostname_mismatch": false,
    });
  });

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

describe("ConfigEditor Pulse plugin repositories", () => {
  const saved = {
    paths: [...CONFIG.editable_paths],
    defaults: { ...CONFIG.defaults },
    effective: { ...CONFIG.effective },
  };

  function usePluginConfig() {
    CONFIG.editable_paths = [
      "service_probe.pulse.plugins_dir",
      "service_probe.pulse.plugin_sources",
    ];
    CONFIG.defaults = {
      "service_probe.pulse.plugins_dir": "",
      "service_probe.pulse.plugin_sources": [],
    } as unknown as typeof CONFIG.defaults;
    // The fixture's effective value also carries the NVD key. A spread of the
    // plugin defaults is a different shape, so the assignment needs the same cast.
    CONFIG.effective = {
      "service_probe.pulse.plugins_dir": "",
      "service_probe.pulse.plugin_sources": [],
    } as unknown as typeof CONFIG.effective;
  }

  function restore() {
    CONFIG.editable_paths = saved.paths;
    CONFIG.defaults = saved.defaults;
    CONFIG.effective = saved.effective;
  }

  it("edits a repository and saves the source list, not a number", async () => {
    const locale = useAppearanceStore.getState().locale;
    useAppearanceStore.setState({ locale: "en" });
    usePluginConfig();
    try {
      renderEditor();
      expect(screen.getByText("pulse.plugins_dir")).toBeVisible();
      expect(screen.getByText(/Empty uses the scripts in this checkout/)).toBeVisible();
      await userEvent.setup().click(screen.getByRole("button", { name: "Add repository" }));
      await userEvent.setup().type(screen.getByLabelText("Source name"), "acme");
      await userEvent
        .setup()
        .type(screen.getByLabelText("Repository URL"), "https://git.example/sec/plugins.git");
      await userEvent.setup().type(screen.getByLabelText("Git ref"), "v3");
      await userEvent.setup().click(screen.getByRole("button", { name: "Save Overrides" }));
      expect(updateMock.mock.calls.at(-1)?.[0]).toEqual({
        "service_probe.pulse.plugin_sources": [
          {
            name: "acme",
            repo: "https://git.example/sec/plugins.git",
            ref: "v3",
            commit: "",
            path: "",
          },
        ],
      });
    } finally {
      restore();
      useAppearanceStore.setState({ locale });
    }
  });

  it("shows the Russian labels and keeps the fields visible", () => {
    const locale = useAppearanceStore.getState().locale;
    useAppearanceStore.setState({ locale: "ru" });
    usePluginConfig();
    try {
      renderEditor();
      expect(screen.getByText("Каталог плагинов Pulse")).toBeVisible();
      expect(screen.getByText("Репозитории плагинов Pulse")).toBeVisible();
      expect(screen.getByRole("button", { name: "Добавить репозиторий" })).toBeVisible();
      expect(screen.getByText(/Пустой список не требует квитанцию загрузки/)).toBeVisible();
    } finally {
      restore();
      useAppearanceStore.setState({ locale });
    }
  });
});

describe("ConfigEditor stored Nmap backend (#548)", () => {
  it("shows a saved nmap backend flagged as removed instead of an empty select", () => {
    const saved = {
      paths: CONFIG.editable_paths,
      effective: CONFIG.effective,
    };
    CONFIG.editable_paths = ["service_probe.backend"];
    CONFIG.effective = { "service_probe.backend": "nmap" } as unknown as typeof CONFIG.effective;
    try {
      renderEditor();
      const select = screen.getByRole("combobox");
      expect(select).toHaveTextContent("nmap (removed");
      expect(select).toHaveTextContent("choose pulse");
    } finally {
      CONFIG.editable_paths = saved.paths;
      CONFIG.effective = saved.effective;
    }
  });
});
