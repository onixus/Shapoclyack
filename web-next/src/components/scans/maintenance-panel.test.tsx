import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { format } from "date-fns";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MaintenancePanel } from "@/components/scans/maintenance-panel";
import { windowCadence, windowScope } from "@/hooks/use-maintenance";
import * as apiModule from "@/lib/api";
import type { MaintenanceCalendar, MaintenanceWindow } from "@/lib/api";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function windowRow(overrides: Partial<MaintenanceWindow> = {}): MaintenanceWindow {
  return {
    window_id: "mw_1",
    tenant_id: "default",
    name: "Saturday night",
    kind: "blackout",
    enabled: true,
    timezone: "Europe/Berlin",
    rrule: "FREQ=WEEKLY;BYDAY=SA",
    dtstart_local: "2026-09-12T22:00",
    duration_minutes: 240,
    scope_kind: "tenant",
    asset_group: null,
    scope_targets: [],
    note: "",
    created_at: "2026-09-01T10:00:00Z",
    created_by: "admin",
    updated_at: null,
    updated_by: null,
    open_now: false,
    open_until: null,
    next_start_at: "2026-09-12T20:00:00Z",
    ...overrides,
  };
}

function calendar(overrides: Partial<MaintenanceCalendar> = {}): MaintenanceCalendar {
  return {
    tenant_id: "default",
    change_freeze: false,
    change_freeze_note: "",
    change_freeze_at: null,
    change_freeze_by: null,
    admission: {
      allowed: true,
      reason: "",
      detail: "",
      window_id: "",
      window_name: "",
      retry_at: null,
    },
    windows: [windowRow()],
    ...overrides,
  };
}

function renderPanel(props: { canRead?: boolean; canAdmin?: boolean } = {}) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <MaintenancePanel canRead={props.canRead ?? true} canAdmin={props.canAdmin ?? false} />
    </QueryClientProvider>,
  );
  return queryClient;
}

/** Instants render in the reader's timezone, like every other timestamp in the
 * console, so the expectation is computed the same way rather than pinned to
 * the zone the suite happens to run in. */
function shown(iso: string) {
  return format(new Date(iso), "yyyy-MM-dd HH:mm");
}

describe("MaintenancePanel", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("stays out of an operator's way when nothing is configured", async () => {
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(
      calendar({ windows: [] }),
    );
    renderPanel({ canAdmin: false });
    await waitFor(() =>
      expect(apiModule.fetchMaintenanceCalendar).toHaveBeenCalled(),
    );
    expect(screen.queryByLabelText("Maintenance calendar")).toBeNull();
  });

  it("still offers an admin the freeze switch before anything is configured", async () => {
    // The control an admin reaches for in a hurry must not be one that only
    // appears after somebody has already used the API to freeze the tenant.
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(
      calendar({ windows: [] }),
    );
    renderPanel({ canAdmin: true });
    expect(await screen.findByRole("button", { name: "Freeze changes" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("lists the windows with their recurrence and when each opens next", async () => {
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(calendar());
    renderPanel();

    expect(await screen.findByText("Saturday night")).toBeInTheDocument();
    expect(screen.getByText("blackout")).toBeInTheDocument();
    expect(screen.getByText("whole tenant")).toBeInTheDocument();
    // The rule is shown verbatim, with the wall clock and the zone it is read
    // in — the point of the feature is that the window is not in the server's
    // timezone.
    expect(
      screen.getByText("FREQ=WEEKLY;BYDAY=SA at 22:00 Europe/Berlin, 4h"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(`next ${shown("2026-09-12T20:00:00Z")}`),
    ).toBeInTheDocument();
    // Nothing is blocked right now, so there is no banner.
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows the server's own refusal, and when scanning resumes", async () => {
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(
      calendar({
        admission: {
          allowed: false,
          reason: "maintenance_blackout",
          detail: "maintenance blackout 'Saturday night' is open until 2026-09-13T00:00:00Z",
          window_id: "mw_1",
          window_name: "Saturday night",
          retry_at: "2026-09-13T00:00:00Z",
        },
        windows: [
          windowRow({ open_now: true, open_until: "2026-09-13T00:00:00Z", next_start_at: null }),
        ],
      }),
    );
    renderPanel();

    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent("Scanning is paused by the maintenance calendar");
    expect(banner).toHaveTextContent(`Scans resume at ${shown("2026-09-13T00:00:00Z")}`);
    expect(
      screen.getByText(`open until ${shown("2026-09-13T00:00:00Z")}`),
    ).toBeInTheDocument();
  });

  it("says a change freeze has no end and names who set it", async () => {
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(
      calendar({
        change_freeze: true,
        change_freeze_note: "migration weekend",
        change_freeze_by: "admin",
        admission: {
          allowed: false,
          reason: "change_freeze",
          detail: "tenant default is under a change freeze: migration weekend",
          window_id: "",
          window_name: "",
          // A freeze does not expire on its own, so there is no retry time to
          // render — and the banner must not invent one.
          retry_at: null,
        },
      }),
    );
    renderPanel();

    const banner = await screen.findByRole("alert");
    expect(banner).toHaveTextContent("Change freeze is on");
    expect(banner).toHaveTextContent("migration weekend");
    expect(banner).toHaveTextContent("set by admin");
    expect(banner).not.toHaveTextContent("resume at");
  });

  it("offers the freeze switch to an admin only, and sends the note with it", async () => {
    vi.spyOn(apiModule, "fetchMaintenanceCalendar").mockResolvedValue(calendar());
    const setFreeze = vi
      .spyOn(apiModule, "setChangeFreeze")
      .mockResolvedValue({
        tenant_id: "default",
        change_freeze: true,
        change_freeze_note: "quarter close",
        change_freeze_at: "2026-09-10T09:00:00Z",
        change_freeze_by: "admin",
      });

    renderPanel({ canAdmin: false });
    expect(await screen.findByText("Saturday night")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Freeze changes" })).toBeNull();

    renderPanel({ canAdmin: true });
    const user = userEvent.setup();
    await user.type(await screen.findByLabelText("Change freeze note"), "quarter close");
    await user.click(screen.getByRole("button", { name: "Freeze changes" }));

    await waitFor(() =>
      expect(setFreeze).toHaveBeenCalledWith(
        { change_freeze: true, note: "quarter close" },
        undefined,
      ),
    );
  });
});

describe("window summaries", () => {
  it("spells out a sub-hour duration and an asset group's targets", () => {
    expect(windowCadence(windowRow({ duration_minutes: 45 }))).toContain("45m");
    expect(windowCadence(windowRow({ duration_minutes: 150 }))).toContain("2h 30m");
    expect(
      windowScope(
        windowRow({
          scope_kind: "asset_group",
          asset_group: "payments",
          scope_targets: ["10.0.5.0/24", "shop.example.com"],
        }),
      ),
    ).toBe("payments: 10.0.5.0/24, shop.example.com");
  });

  it("says so when a group covers nothing, rather than reading as tenant-wide", () => {
    expect(
      windowScope(windowRow({ scope_kind: "asset_group", asset_group: "payments" })),
    ).toContain("matches nothing");
  });
});
