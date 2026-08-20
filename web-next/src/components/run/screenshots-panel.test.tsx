import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScreenshotsGallery, skipReasonCopy } from "@/components/run/screenshots-panel";
import type { ScreenshotManifest } from "@/lib/api";

function manifest(overrides: Partial<ScreenshotManifest> = {}): ScreenshotManifest {
  return {
    skipped_reason: null,
    captured_count: 0,
    redacted_fields: 0,
    truncated: false,
    retention_days: 14,
    items: [],
    ...overrides,
  };
}

describe("ScreenshotsGallery", () => {
  it("states the redaction limit and retention window", () => {
    render(<ScreenshotsGallery runId="run-a" manifest={manifest()} />);
    expect(screen.getByText(/obvious form fields/i)).toBeInTheDocument();
    expect(screen.getByText(/older than 14 days/i)).toBeInTheDocument();
  });

  it("explains a disabled skip without claiming capture ran", () => {
    render(
      <ScreenshotsGallery
        runId="run-a"
        manifest={manifest({ skipped_reason: "screenshots.disabled" })}
      />,
    );
    expect(screen.getByText(/opt-in/i)).toBeInTheDocument();
    expect(screen.queryByText(/deleted by retention/i)).not.toBeInTheDocument();
  });

  it("marks a capped run and an expired file", () => {
    render(
      <ScreenshotsGallery
        runId="run-a"
        manifest={manifest({
          truncated: true,
          captured_count: 1,
          items: [
            {
              host: "10.0.0.1",
              port: 443,
              scheme: "https",
              url: "https://10.0.0.1",
              file: "screenshots/dead.png",
              redacted_fields: 3,
              available: false,
            },
          ],
        })}
      />,
    );
    expect(screen.getByText(/capped at the configured maximum/i)).toBeInTheDocument();
    expect(screen.getByText("https://10.0.0.1:443")).toBeInTheDocument();
    expect(screen.getByText(/3 fields redacted/i)).toBeInTheDocument();
    expect(screen.getByText(/deleted by retention/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /save/i })).not.toBeInTheDocument();
  });
});

describe("skipReasonCopy", () => {
  it("does not invent a capture when playwright is missing", () => {
    expect(skipReasonCopy("playwright.unavailable")).toMatch(/no pixels were taken/i);
  });
});
