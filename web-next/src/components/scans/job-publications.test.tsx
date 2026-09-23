import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { JobPublications } from "@/components/scans/job-publications";
import * as apiModule from "@/lib/api";
import type { JobInfo, Me, RunPublicationInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function job(overrides: Partial<JobInfo> = {}): JobInfo {
  return {
    job_id: "abc123def456",
    status: "succeeded",
    run_id: "20260923T101010Z-1a2b3c",
    mode: "balanced",
    started_at: "2026-09-23T10:10:10Z",
    finished_at: "2026-09-23T10:20:10Z",
    exit_code: 0,
    error: "; run not published (publication pub-1): ArtifactStoreError: bucket unreachable",
    requested_by: "op",
    ...overrides,
  };
}

function publication(overrides: Partial<RunPublicationInfo> = {}): RunPublicationInfo {
  return {
    publication_id: "pub-1",
    job_id: "abc123def456",
    run_id: "20260923T101010Z-1a2b3c",
    tenant_id: "default",
    status: "dead",
    state: "dead",
    resolution: "requeue",
    attempts: 5,
    max_attempts: 5,
    claims: 0,
    lease_lapses: 0,
    last_error: "ArtifactStoreError: bucket unreachable",
    stored_at: null,
    tree_kept_until: "2026-09-24T10:20:10Z",
    next_attempt_at: null,
    leased_until: null,
    silent: false,
    orphan_deadline_at: null,
    actionable: true,
    actionable_at: null,
    created_at: "2026-09-23T10:20:10Z",
    updated_at: "2026-09-23T10:40:10Z",
    replica: null,
    staging_path: null,
    archive_path: null,
    ...overrides,
  };
}

function member(role: string, platformAdmin = false): Me {
  return {
    username: "on-call",
    role: platformAdmin ? "admin" : "viewer",
    tenants: ["default"],
    default_tenant: "default",
    is_platform_admin: platformAdmin,
    tenant_role: role,
    permissions: [],
    scoped_tenant: "default",
  };
}

function renderSection(current: JobInfo = job()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <JobPublications job={current} open />
    </QueryClientProvider>,
  );
}

describe("JobPublications", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useAuthStore.setState({ user: member("admin"), canOperate: true });
  });

  it("renders nothing for the ordinary job, and does not ask a job still running", async () => {
    const fetched = vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([]);
    renderSection();
    await waitFor(() => expect(fetched).toHaveBeenCalledWith("abc123def456"));
    expect(screen.queryByText("Publication")).not.toBeInTheDocument();

    fetched.mockClear();
    renderSection(job({ job_id: "running00001", status: "running" }));
    expect(fetched).not.toHaveBeenCalled();
  });

  it("shows a dead row and lets a tenant admin requeue it", async () => {
    vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([publication()]);
    const requeued = vi
      .spyOn(apiModule, "requeueJobPublication")
      .mockResolvedValue(publication({ status: "pending", state: "retrying", attempts: 0 }));
    renderSection();

    expect(await screen.findByText("needs an operator")).toBeInTheDocument();
    expect(screen.getByText("5 / 5")).toBeInTheDocument();
    expect(screen.getByText("ArtifactStoreError: bucket unreachable")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Requeue" }));
    await waitFor(() => expect(requeued).toHaveBeenCalledWith("abc123def456", "pub-1"));
  });

  it("asks before discarding, and discards only on confirmation", async () => {
    vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([publication()]);
    const discarded = vi.spyOn(apiModule, "discardJobPublication").mockResolvedValue(undefined);
    renderSection();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Discard" }));
    const dialog = await screen.findByRole("alertdialog");
    // A day from the acceptance, not from now: the sweep reads the staging
    // directory's mtime, which only its first entry sets.
    expect(dialog).toHaveTextContent("until a day after the upload was accepted (2026-09-2");
    expect(discarded).not.toHaveBeenCalled();
    await user.click(screen.getAllByRole("button", { name: "Discard" }).at(-1)!);
    await waitFor(() => expect(discarded).toHaveBeenCalledWith("abc123def456", "pub-1"));
  });

  it("holds both buttons while an attempt at the dead row is still running", async () => {
    // The API refuses with 409 then; the console says why before anyone clicks.
    vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([
      publication({ actionable: false, actionable_at: "2026-09-23T10:41:10Z" }),
    ]);
    renderSection();
    expect(await screen.findByRole("button", { name: "Requeue" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Discard" })).toBeDisabled();
    expect(screen.getByText(/is still running/)).toBeInTheDocument();
  });

  it("does not offer the decision to an operator", async () => {
    useAuthStore.setState({ user: member("operator"), canOperate: true });
    vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([publication()]);
    renderSection();
    expect(await screen.findByText("needs an operator")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Requeue" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Discard" })).not.toBeInTheDocument();
  });

  it("says a row from a pod that is gone needs a re-scan, before and after its deadline", async () => {
    vi.spyOn(apiModule, "fetchJobPublications").mockResolvedValue([
      publication({
        status: "pending",
        state: "retrying",
        resolution: "wait",
        attempts: 1,
        silent: true,
        orphan_deadline_at: "2026-09-23T11:40:10Z",
        actionable: false,
      }),
      publication({
        publication_id: "pub-2",
        resolution: "rescan",
        last_error:
          "the replica that accepted this upload is gone and no peer can see the extracted tree; this run needs a re-scan",
        replica: "shapoclyack-api-7d9f-evicted",
        staging_path: "/var/lib/shapoclyack/cache/.ingest-x",
      }),
    ]);
    useAuthStore.setState({ user: member("admin", true), canOperate: true });
    renderSection();

    expect(await screen.findByText(/declared dead at/)).toBeInTheDocument();
    expect(screen.getByText(/requeue will not help: discard and re-scan/)).toBeInTheDocument();
    // The pod and the path are shown when the API sends them (platform admin).
    expect(screen.getByText("shapoclyack-api-7d9f-evicted")).toBeInTheDocument();
    expect(screen.getByText("/var/lib/shapoclyack/cache/.ingest-x")).toBeInTheDocument();
    // Requeue is not the suggested action for it, but stays possible.
    expect(screen.getAllByRole("button", { name: "Requeue" })).toHaveLength(1);
  });
});
