import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatusBadge } from "@/components/status-badge";
import { useAppearanceStore } from "@/lib/appearance";
import { JOB_STATUS } from "@/lib/config/statuses";

describe("StatusBadge", () => {
  it("renders the label and color class from the map", () => {
    render(<StatusBadge value="succeeded" map={JOB_STATUS} />);
    const badge = screen.getByText("succeeded").closest("div");
    expect(badge).toBeInTheDocument();
    expect(badge?.className).toContain("bg-success-subtle");
  });

  it("draws the tone's icon next to the word", () => {
    const { container } = render(<StatusBadge value="failed" map={JOB_STATUS} />);
    const badge = container.querySelector("[data-tone]");
    expect(badge?.getAttribute("data-tone")).toBe("danger");
    expect(badge?.querySelector("svg")).not.toBeNull();
    expect(badge).toHaveTextContent("failed");
  });

  it("renders the destructive variant for failed", () => {
    render(<StatusBadge value="failed" map={JOB_STATUS} />);
    expect(screen.getByText("failed").closest("div")?.className).toContain("bg-danger-subtle");
  });

  it("falls back to a secondary badge with the raw value for unknown statuses", () => {
    render(<StatusBadge value="mystery" map={JOB_STATUS} />);
    expect(screen.getByText("mystery").closest("div")?.className).toContain("bg-secondary");
  });

  it("renders the Russian label when the locale is ru", () => {
    useAppearanceStore.setState({ locale: "ru", theme: "dark", hydrated: true });
    render(<StatusBadge value="succeeded" map={JOB_STATUS} />);
    expect(screen.getByText("успешно")).toBeInTheDocument();
  });

  it("prefers an explicit fallback when provided", () => {
    render(
      <StatusBadge
        value="mystery"
        map={JOB_STATUS}
        fallback={{ label: "n/a", variant: "outline" }}
      />,
    );
    expect(screen.getByText("n/a")).toBeInTheDocument();
  });
});
