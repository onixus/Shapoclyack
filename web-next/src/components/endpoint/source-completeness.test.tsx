import { render, screen, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SourceCompleteness } from "./source-completeness";

vi.mock("@/lib/i18n", () => ({ useT: () => (key: string) => key }));
vi.mock("@/lib/i18n/datetime", () => ({ useRelativeTime: () => () => "2 days ago" }));
afterEach(cleanup);

const complete = {
  source: "dpkg",
  status: "complete" as const,
  collected_at: "2026-10-06T00:00:00Z",
  last_complete_at: "2026-10-06T00:00:00Z",
  collector_version: "0.5.0",
  diagnostic_code: null,
};

describe("source completeness", () => {
  it("shows a failed collector's last complete age independently of receipt time", () => {
    render(
      <SourceCompleteness
        sources={[
          complete,
          { ...complete, source: "pip", status: "failed", diagnostic_code: "permission_denied" },
        ]}
      />,
    );
    expect(screen.getByText("pip")).toBeTruthy();
    expect(screen.queryByText("dpkg")).toBeNull();
    expect(screen.getByTitle("permission_denied").textContent).toContain("2 days ago");
  });
  it("shows unknown freshness when the source has never completed", () => {
    render(
      <SourceCompleteness sources={[{ ...complete, status: "partial", last_complete_at: null }]} />,
    );
    expect(screen.getByRole("listitem").textContent).toContain("common.never");
  });
  it("adds no degradation warning for legacy or fully complete inventories", () => {
    const { rerender } = render(<SourceCompleteness />);
    expect(screen.queryByRole("list")).toBeNull();
    rerender(<SourceCompleteness sources={[complete]} />);
    expect(screen.queryByRole("list")).toBeNull();
  });
});
