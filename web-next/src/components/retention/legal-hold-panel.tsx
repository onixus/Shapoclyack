"use client";

import { useEffect, useState } from "react";
import { Gavel, Unlock } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { usePlaceLegalHold, useReleaseLegalHold } from "@/hooks/use-retention";
import { type LegalHold } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";

/**
 * Whether this tenant is on legal hold, and — for a platform admin — placing
 * and releasing one (#332).
 *
 * The tenant's own admin sees that a hold is in force and since when, and
 * nothing else: the API does not send them who placed it or why, because the
 * matter behind a hold can be one the tenant must not learn of from here.
 */
export function LegalHoldPanel({
  tenantId,
  hold,
  canManage,
}: {
  tenantId: string;
  hold: LegalHold | null;
  canManage: boolean;
}) {
  const t = useT();
  const when = useAbsoluteTime();
  const place = usePlaceLegalHold(tenantId);
  const release = useReleaseLegalHold(tenantId);
  const [reason, setReason] = useState(hold?.reason ?? "");
  const [confirmRelease, setConfirmRelease] = useState(false);

  useEffect(() => {
    setReason(hold?.reason ?? "");
  }, [hold?.reason]);

  return (
    <section className="space-y-3">
      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {t("retention.hold.title")}
      </p>
      {hold ? (
        <div
          className="space-y-1 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm"
          role="status"
        >
          <p className="flex items-center gap-2 font-semibold text-foreground">
            <Gavel className="h-4 w-4 text-amber-500" />
            {t("retention.hold.active", { since: when(hold.set_at) })}
          </p>
          <p className="text-xs text-muted-foreground">{t("retention.hold.activeHint")}</p>
          {hold.reason ? (
            <p className="text-xs text-foreground">
              {t("retention.hold.reasonShown", { reason: hold.reason, who: hold.set_by ?? "—" })}
            </p>
          ) : null}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">{t("retention.hold.none")}</p>
      )}

      {canManage ? (
        <div className="space-y-2">
          <Textarea
            aria-label={t("retention.hold.reason")}
            placeholder={t("retention.hold.reasonPlaceholder")}
            value={reason}
            maxLength={1000}
            onChange={(event) => setReason(event.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              className="gap-2 bg-amber-600 text-foreground hover:bg-amber-500"
              disabled={!reason.trim() || reason.trim() === (hold?.reason ?? "") || place.isPending}
              onClick={() => place.mutate(reason.trim())}
            >
              <Gavel className="h-4 w-4" />
              {hold ? t("retention.hold.update") : t("retention.hold.place")}
            </Button>
            {hold ? (
              <Button
                type="button"
                variant="outline"
                className="gap-2 border-border"
                disabled={release.isPending}
                onClick={() => setConfirmRelease(true)}
              >
                <Unlock className="h-4 w-4" />
                {t("retention.hold.release")}
              </Button>
            ) : null}
          </div>
        </div>
      ) : (
        <p className="text-[11px] text-muted-foreground">{t("retention.hold.platformOnly")}</p>
      )}

      <AlertDialog open={confirmRelease} onOpenChange={setConfirmRelease}>
        <AlertDialogContent className="border-border bg-card text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              {t("retention.hold.releaseTitle", { tenant: tenantId })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs text-muted-foreground">
              {t("retention.hold.releaseHint")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">
              {t("ui.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-foreground hover:bg-rose-500"
              onClick={() => release.mutate()}
            >
              {t("retention.hold.release")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
