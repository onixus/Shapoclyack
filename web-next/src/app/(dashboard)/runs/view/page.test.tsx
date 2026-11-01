import { useAppearanceStore } from "@/lib/appearance";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import RunDetailPage from "@/app/(dashboard)/runs/view/page";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("runId=run-a&tab=screenshots"),
}));
vi.mock("@/hooks/use-run-report", () => ({
  useRunReport: () => ({
    detail: { run_id: "run-a", artifacts: [] },
    filters: { host: null, port: null, severity: "all" },
    hosts: [],
    ports: [],
    vulns: [],
    grouped: {},
    severityCounts: {},
  }),
}));
vi.mock("@/components/run/run-metrics", () => ({ RunMetrics: () => null }));
vi.mock("@/components/run/severity-filter", () => ({ SeverityFilter: () => null }));
vi.mock("@/components/run/findings-list", () => ({
  FindingsList: () => <div>Existing findings</div>,
}));
vi.mock("@/components/run/controls-matrix", () => ({ ControlsMatrix: () => null }));
vi.mock("@/components/run/related-domains", () => ({ RelatedDomainsPanel: () => null }));
vi.mock("@/components/run/artifacts-panel", () => ({ ArtifactsPanel: () => null }));

// A saved operator URL must stay usable after the unsupported capture tab is
// withdrawn. Rendering the page also guards against mounting its fetch hook.
describe("RunDetailPage withdrawn screenshot capture", () => {
  it("translates run headings and tabs without changing tab routing", () => {
    useAppearanceStore.setState({ locale: "ru" });
    render(<RunDetailPage />);
    expect(screen.getByRole("heading", { name: /Прогон run-a/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Находки/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /Хосты/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Порты/ })).toBeVisible();
    expect(screen.getByRole("tab", { name: /Файлы отчёта/ })).toBeVisible();
  });
  it("opens findings for a legacy screenshot link without advertising capture", () => {
    render(<RunDetailPage />);
    expect(screen.queryByRole("tab", { name: /screenshots/i })).not.toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /findings/i })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Existing findings")).toBeVisible();
  });
});
