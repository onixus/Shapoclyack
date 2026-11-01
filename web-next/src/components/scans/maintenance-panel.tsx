"use client";

import { useState } from "react";
import { useT } from "@/lib/i18n";
import { format } from "date-fns";
import { CalendarClock, Snowflake } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/status-badge";
import {
  useMaintenanceCalendar,
  useSetChangeFreeze,
  windowCadence,
  windowScope,
} from "@/hooks/use-maintenance";
import { MAINTENANCE_WINDOW_KIND } from "@/lib/config/statuses";

/** An instant the API already resolved to UTC, in the reader's timezone —
 * like every other timestamp in the console. */
function shown(iso: string | null | undefined): string {
  return iso ? format(new Date(iso), "yyyy-MM-dd HH:mm") : "—";
}

/**
 * The maintenance calendar above the schedules table (#352).
 *
 * Why it lives on this page: a schedule that did not fire last night and a
 * blackout that was open last night are the same fact, and until now the
 * console could show the first without the second. The banner is the answer to
 * "why is nothing running", and it is rendered from the server's own admission
 * verdict rather than recomputed here — two implementations of "is a blackout
 * open" would eventually disagree, and the one the operator can see is not the
 * one that decides.
 *
 * Windows are created and edited over the API (`/api/maintenance-windows`);
 * this panel shows them and offers the one control an admin reaches for in a
 * hurry, the change freeze.
 */
export function MaintenancePanel({
  canRead,
  canAdmin,
  tenantId,
}: {
  canRead: boolean;
  canAdmin: boolean;
  tenantId?: string;
}) {
  const t = useT();
  const { data, isLoading } = useMaintenanceCalendar(canRead, tenantId);
  const freezeMutation = useSetChangeFreeze(tenantId);
  const [note, setNote] = useState("");

  if (!canRead || isLoading || !data) return null;
  const { admission, windows } = data;
  // Nothing configured, nothing frozen and no right to freeze: no banner, no
  // empty table. The page looked like this before the feature existed and
  // should keep doing so for the installations that never write a calendar.
  // An admin still gets the switch — a control that only appears once it has
  // been used elsewhere is a control nobody can reach in a hurry.
  if (!data.change_freeze && windows.length === 0 && !canAdmin) return null;

  return (
    <section className="space-y-3" aria-label={t("scanCopy.calendarLabel")}>
      {data.change_freeze ? (
        <Alert variant="destructive">
          <Snowflake className="h-4 w-4" />
          <AlertTitle>{t("ui.changeFreezeIsOn")}</AlertTitle>
          <AlertDescription>
            {t("scanCopy.freezeDescription", { tenant: data.tenant_id })}
            {data.change_freeze_note ? `: ${data.change_freeze_note}` : ""}
            {data.change_freeze_by ? t("scanCopy.setBy", { actor: data.change_freeze_by }) : ""}.
          </AlertDescription>
        </Alert>
      ) : !admission.allowed ? (
        <Alert variant="warning">
          <CalendarClock className="h-4 w-4" />
          <AlertTitle>{t("ui.scanningIsPausedByTheMaintenance")}</AlertTitle>
          <AlertDescription>
            {t.locale === "ru" ? t("scanCopy.paused") : admission.detail}
            {admission.detail && t.locale === "ru" ? (
              <details>
                <summary>{t("scanCopy.technical")}</summary>
                {admission.detail}
              </details>
            ) : null}
            {admission.retry_at ? t("scanCopy.resumeAt", { time: shown(admission.retry_at) }) : ""}
          </AlertDescription>
        </Alert>
      ) : null}

      {windows.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <table className="w-full text-sm">
            <thead className="bg-muted text-left text-xs text-muted-foreground font-medium">
              <tr>
                <th className="px-3 py-2">{t("ui.window")}</th>
                <th className="px-3 py-2">{t("scanCopy.kind")}</th>
                <th className="px-3 py-2">{t("ui.appliesTo")}</th>
                <th className="px-3 py-2">{t("ui.recurrence")}</th>
                <th className="px-3 py-2">{t("scanCopy.now")}</th>
              </tr>
            </thead>
            <tbody>
              {windows.map((window) => (
                <tr key={window.window_id} className="border-t">
                  <td className="px-3 py-2 font-medium">
                    {window.name}
                    {!window.enabled && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {t("scanCopy.disabled")}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <StatusBadge value={window.kind} map={MAINTENANCE_WINDOW_KIND} />
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {windowScope(window, t.locale)}
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {windowCadence(window, t.locale)}
                    <details className="mt-1 break-words">
                      <summary className="cursor-pointer">{t("scanCopy.technical")}</summary>
                      <pre className="whitespace-pre-wrap">
                        {JSON.stringify(
                          {
                            window_id: window.window_id,
                            kind: window.kind,
                            scope_kind: window.scope_kind,
                            rrule: window.rrule,
                            dtstart_local: window.dtstart_local,
                            timezone: window.timezone,
                            duration_minutes: window.duration_minutes,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                  </td>
                  <td className="px-3 py-2">
                    {window.open_now
                      ? t("scanCopy.openUntil", { time: shown(window.open_until) })
                      : window.enabled
                        ? t("scanCopy.next", { time: shown(window.next_start_at) })
                        : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {canAdmin && (
        <div className="flex flex-wrap items-center gap-2">
          {!data.change_freeze && (
            <Input
              className="max-w-xs"
              placeholder={t("scanCopy.freezePlaceholder")}
              value={note}
              onChange={(event) => setNote(event.target.value)}
              aria-label={t("scanCopy.freezeNote")}
            />
          )}
          <Button
            variant={data.change_freeze ? "outline" : "destructive"}
            disabled={freezeMutation.isPending}
            onClick={() => freezeMutation.mutate({ change_freeze: !data.change_freeze, note })}
          >
            {data.change_freeze ? t("scanCopy.unfreeze") : t("scanCopy.freeze")}
          </Button>
        </div>
      )}
    </section>
  );
}
