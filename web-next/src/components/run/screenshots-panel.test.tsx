import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ScreenshotsGallery, skipReasonKey } from "@/components/run/screenshots-panel";
import type { ScreenshotManifest } from "@/lib/api";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return {
    ...actual,
    fetchScreenshotBlob: vi.fn(async () => new Blob([new Uint8Array([137, 80, 78, 71])], { type: "image/png" })),
    downloadArtifact: vi.fn(async () => undefined),
  };
});

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
  it("states the redaction limit and that retention deletes pixels", () => {
    render(<ScreenshotsGallery runId="run-a" manifest={manifest()} />);
    expect(screen.getByText(/obvious form fields only/i)).toBeInTheDocument();
    expect(screen.getByText(/personal data/i)).toBeInTheDocument();
    expect(screen.getByText(/operator-only/i)).toBeInTheDocument();
    expect(screen.getByText(/deletes pixels older than 14 days/i)).toBeInTheDocument();
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

  it("says capture is skipped when the isolated worker is not deployed", () => {
    render(
      <ScreenshotsGallery
        runId="run-a"
        manifest={manifest({ skipped_reason: "worker.unavailable" })}
      />,
    );
    expect(screen.getByText(/isolated worker/i)).toBeInTheDocument();
    expect(screen.getByText(/worker\.unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/no pixels were taken/i)).toBeInTheDocument();
  });

  it("opens an available screenshot when the thumbnail is clicked", async () => {
    const user = userEvent.setup();
    render(
      <ScreenshotsGallery
        runId="run-a"
        manifest={manifest({
          items: [
            {
              host: "203.0.113.10",
              port: 443,
              scheme: "https",
              url: "https://203.0.113.10/",
              file: "screenshots/live.png",
              redacted_fields: 1,
              available: true,
            },
          ],
        })}
      />,
    );
    const open = await screen.findByRole("button", { name: /open screenshot/i });
    await user.click(open);
    expect(await screen.findByRole("dialog")).toBeVisible();
    expect(screen.getByRole("dialog")).toHaveTextContent("https://203.0.113.10/");
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

describe("skipReasonKey", () => {
  it("maps a legacy playwright skip without inventing a capture", () => {
    expect(skipReasonKey("playwright.unavailable")).toBe("screenshots.skip.playwrightUnavailable");
  });

  it("maps a missing worker and an empty candidate set", () => {
    expect(skipReasonKey("worker.unavailable")).toBe("screenshots.skip.workerUnavailable");
    expect(skipReasonKey("no_web_ports")).toBe("screenshots.skip.noWebPorts");
    expect(skipReasonKey(null)).toBeNull();
  });
});
