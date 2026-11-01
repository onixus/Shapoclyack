import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import userEvent from "@testing-library/user-event";
import { useAppearanceStore } from "@/lib/appearance";
import { SeverityFilter } from "./severity-filter";
import { ArtifactsPanel } from "./artifacts-panel";
import { RunDiffPanel } from "./run-diff-panel";
import { runText } from "@/lib/run-presentation";
describe("Russian run presentation", () => {
  it("keeps severity filter protocol values", async () => {
    useAppearanceStore.setState({ locale: "ru" });
    const onChange = vi.fn();
    render(
      <SeverityFilter
        counts={{ critical: 1, high: 2, medium: 0, low: 0, unknown: 0 }}
        active="all"
        total={3}
        onChange={onChange}
      />,
    );
    await userEvent.setup().click(screen.getByRole("button", { name: /высокий/i }));
    expect(onChange).toHaveBeenCalledWith("high");
  });
  it("translates artifact controls while preserving filenames", () => {
    useAppearanceStore.setState({ locale: "ru" });
    render(<ArtifactsPanel runId="run-a" artifacts={["summary.pdf", "summary.json"]} />);
    expect(screen.getByRole("button", { name: "Скачать PDF" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Просмотр" })).toBeVisible();
    expect(screen.getByText("summary.json")).toBeVisible();
  });
  it("keeps added/removed counts in the translated diff", () => {
    useAppearanceStore.setState({ locale: "ru" });
    render(<RunDiffPanel counts={{ hosts_added: 3, ports_removed: 2 }} />);
    expect(screen.getByText("Хосты:")).toBeVisible();
    expect(screen.getByText("+3")).toBeVisible();
    expect(screen.getByText("-2")).toBeVisible();
  });
  it("preserves English locale and interpolated report limits", () => {
    expect(runText("en", "{count} findings", { count: 8 })).toBe("8 findings");
    expect(runText("ru", "{count} findings", { count: 8 })).toBe("Находок: 8");
  });
});
