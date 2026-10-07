import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { JobMaintenanceWait } from "@/components/scans/job-maintenance-wait";
import type { JobInfo } from "@/lib/api";

function job(waiting: unknown, status: JobInfo["status"] = "queued"): JobInfo {
  return {
    job_id: "waiting-job",
    status,
    run_id: null,
    mode: "safe",
    started_at: null,
    finished_at: null,
    exit_code: null,
    error: null,
    requested_by: "op",
    scan_options: { maintenance_wait: waiting },
  };
}

describe("JobMaintenanceWait", () => {
  it("shows why the job waits and when the window opens", () => {
    render(
      <JobMaintenanceWait
        job={job({
          allowed: false,
          reason: "maintenance_blackout",
          detail: "Migration window",
          retry_at: "2026-10-07T18:00:00Z",
        })}
      />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Waiting for the maintenance blackout to end",
    );
    expect(screen.getByRole("status")).toHaveTextContent("Migration window");
    expect(screen.getByRole("status")).toHaveTextContent("Next calendar opening:");
  });

  it("does not invent a retry time for an indefinite freeze", () => {
    render(
      <JobMaintenanceWait job={job({ allowed: false, reason: "change_freeze", retry_at: null })} />,
    );
    expect(screen.getByRole("status")).toHaveTextContent(
      "Waiting for the change freeze to be lifted",
    );
    expect(screen.getByRole("status")).toHaveTextContent("recheck the calendar before starting");
  });

  it("explains the wait on a compact table indicator", () => {
    render(
      <JobMaintenanceWait
        compact
        job={job({ allowed: false, reason: "outside_allowed_window" })}
      />,
    );
    expect(screen.getByRole("img", { name: "Waiting for an allowed scan window" })).toHaveAttribute(
      "title",
      expect.stringContaining("recheck the calendar"),
    );
  });

  it.each([null, "invalid", { allowed: true }])(
    "ignores an absent or invalid refusal: %s",
    (waiting) => {
      const { container } = render(<JobMaintenanceWait job={job(waiting)} />);
      expect(container).toBeEmptyDOMElement();
    },
  );

  it("hides a stale refusal once the job starts", () => {
    const { container } = render(<JobMaintenanceWait job={job({ allowed: false }, "running")} />);
    expect(container).toBeEmptyDOMElement();
  });
});
