"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchMaintenanceCalendar,
  setChangeFreeze,
  type MaintenanceWindow,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** The tenant's maintenance calendar and the verdict a scan started right now
 * would get (#352).
 *
 * Refetched on an interval because the interesting part of it *changes without
 * anybody clicking*: a blackout opens at 22:00 whether or not the schedules
 * page is reloaded, and a banner that says "scanning allowed" ten minutes into
 * a blackout is worse than no banner.
 */
export function useMaintenanceCalendar(enabled: boolean, tenantId?: string) {
  return useQuery({
    queryKey: queryKeys.maintenanceCalendar(tenantId ?? null),
    queryFn: () => fetchMaintenanceCalendar(tenantId),
    enabled,
    refetchInterval: 60_000,
  });
}

export function useSetChangeFreeze(tenantId?: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: { change_freeze: boolean; note?: string }) =>
      setChangeFreeze(body, tenantId),
    onSuccess: async (state) => {
      toast.success(state.change_freeze ? "Change freeze on" : "Change freeze lifted", {
        description: state.change_freeze
          ? `No scan will start in ${state.tenant_id} until it is lifted`
          : `Scanning in ${state.tenant_id} follows the maintenance calendar again`,
      });
      // Invalidated rather than patched: the freeze changes the *admission*
      // too, and that verdict is the server's to compute.
      await queryClient.invalidateQueries({
        queryKey: queryKeys.maintenanceCalendar(tenantId ?? null),
      });
    },
    onError: (err) => {
      toast.error("Failed to change the freeze", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

/** The window's recurrence in one line, for a table cell.
 *
 * The stored RRULE is shown verbatim rather than prettified: it is the thing an
 * admin edits and the thing the API validates, and a paraphrase that drifts
 * from it would be the console lying about what is stored. What is added is the
 * part no reader can compute from the rule alone — the wall clock and the zone
 * it is read in, because the whole point is that the window is not in the
 * server's timezone.
 */
export function windowCadence(window: MaintenanceWindow): string {
  const localTime = window.dtstart_local.split("T")[1] ?? window.dtstart_local;
  const hours = Math.floor(window.duration_minutes / 60);
  const minutes = window.duration_minutes % 60;
  const length = hours > 0 ? `${hours}h${minutes ? ` ${minutes}m` : ""}` : `${minutes}m`;
  return `${window.rrule} at ${localTime} ${window.timezone}, ${length}`;
}

/** Who the window applies to. An asset group has no first-class entity on the
 * platform, so it is named and then defined by the targets it covers — both
 * are shown, because the name alone tells a reader nothing about whether their
 * scan is inside it. */
export function windowScope(window: MaintenanceWindow): string {
  if (window.scope_kind !== "asset_group") return "whole tenant";
  const targets = window.scope_targets.join(", ");
  return `${window.asset_group ?? "group"}: ${targets || "(no targets — matches nothing)"}`;
}
