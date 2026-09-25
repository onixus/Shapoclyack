"use client";

import { useState } from "react";
import { Ban, Gavel, Play, RotateCcw, Trash2, Undo2 } from "lucide-react";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import {
  useApproveTenantDeletion,
  useCancelTenantDeletion,
  useRequestTenantDeletion,
  useResumeTenant,
  useRetryTenantDeletion,
  useSuspendTenant,
  useTenantLifecycle,
} from "@/hooks/use-tenant-lifecycle";
import { type TenantDeletion, type TenantDeletionStep } from "@/lib/api";
import { TENANT_DELETION_STEP_STATUS, TENANT_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";

type Confirming = "delete" | "approve" | null;

/** What a step removed, as `table 3 · other 1`, zeros left out. */
function countsSummary(counts: Record<string, number>): string {
  return Object.entries(counts)
    .filter(([, value]) => typeof value === "number" && value > 0)
    .map(([key, value]) => `${key} ${value}`)
    .join(" · ");
}

function StepRow({ step }: { step: TenantDeletionStep }) {
  const t = useT();
  const summary = countsSummary(step.counts);
  return (
    <tr className="border-t border-border align-top">
      <td className="py-1.5 pr-3 font-mono text-xs text-foreground">{step.step}</td>
      <td className="py-1.5 pr-3">
        <StatusBadge value={step.state} map={TENANT_DELETION_STEP_STATUS} />
      </td>
      <td className="py-1.5 pr-3 text-xs tabular-nums text-muted-foreground">{step.attempts}</td>
      <td className="py-1.5 text-xs text-muted-foreground">
        {summary ? <p>{summary}</p> : null}
        {step.last_error ? (
          <p className={step.state === "failed" ? "text-rose-500" : undefined}>
            {step.last_error}
          </p>
        ) : null}
        {!summary && !step.last_error ? t("lifecycle.step.nothing") : null}
      </td>
    </tr>
  );
}

function DeletionProgress({ deletion }: { deletion: TenantDeletion }) {
  const t = useT();
  return (
    <table className="w-full text-left" aria-label={t("lifecycle.progress")}>
      <thead>
        <tr className="text-[11px] uppercase tracking-wider text-muted-foreground">
          <th className="pb-1 pr-3 font-semibold">{t("lifecycle.col.store")}</th>
          <th className="pb-1 pr-3 font-semibold">{t("lifecycle.col.state")}</th>
          <th className="pb-1 pr-3 font-semibold">{t("lifecycle.col.attempts")}</th>
          <th className="pb-1 font-semibold">{t("lifecycle.col.detail")}</th>
        </tr>
      </thead>
      <tbody>
        {deletion.steps.map((step) => (
          <StepRow key={step.step} step={step} />
        ))}
      </tbody>
    </table>
  );
}

/**
 * Suspend, resume and delete one tenant, and watch its purge (#325).
 *
 * Platform admins only — the page renders it for nobody else, and the API
 * refuses every call here to anyone else. Each change is behind the API's
 * step-up; the typed confirmations are the console's courtesy, and the API
 * compares the typed id itself.
 *
 * A legal hold disables the delete and approve buttons and says why, with
 * the hold's reason: the platform admin is the one person the reason is for.
 */
export function TenantLifecyclePanel({ tenantId }: { tenantId: string }) {
  const t = useT();
  const when = useAbsoluteTime();
  const { data, isLoading, error } = useTenantLifecycle(tenantId, true);
  const suspend = useSuspendTenant(tenantId);
  const resume = useResumeTenant(tenantId);
  const request = useRequestTenantDeletion(tenantId);
  const cancel = useCancelTenantDeletion(tenantId);
  const approve = useApproveTenantDeletion(tenantId);
  const retry = useRetryTenantDeletion(tenantId);
  const [reason, setReason] = useState("");
  const [revoke, setRevoke] = useState(true);
  const [confirming, setConfirming] = useState<Confirming>(null);
  const [typed, setTyped] = useState("");

  if (error) {
    return (
      <p className="text-sm text-rose-500" role="alert">
        {error instanceof Error ? error.message : t("lifecycle.loadFailed")}
      </p>
    );
  }
  if (isLoading || !data) {
    return <p className="text-sm text-muted-foreground">{t("lifecycle.loading")}</p>;
  }

  const hold = data.legal_hold;
  const deletion = data.deletion;
  const status = data.status;
  const graceOver =
    deletion?.purge_after != null && new Date(deletion.purge_after).getTime() <= Date.now();
  const canRetry =
    deletion != null &&
    (deletion.state === "blocked" || deletion.steps.some((step) => step.state === "failed"));

  const closeConfirm = () => {
    setConfirming(null);
    setTyped("");
  };

  return (
    <section className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {status === "deleted" ? (
          <span className="font-semibold text-foreground">{t("lifecycle.deleted")}</span>
        ) : (
          <StatusBadge value={status} map={TENANT_STATUS} />
        )}
        {data.status_reason ? (
          <span className="text-xs text-muted-foreground">
            {t("lifecycle.reasonShown", {
              reason: data.status_reason,
              who: data.status_changed_by ?? "—",
              when: when(data.status_changed_at),
            })}
          </span>
        ) : null}
      </div>

      {hold ? (
        <div
          className="space-y-1 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3"
          role="status"
        >
          <p className="flex items-center gap-2 font-semibold text-foreground">
            <Gavel className="h-4 w-4 text-amber-500" />
            {t("lifecycle.hold", { since: when(hold.set_at) })}
          </p>
          <p className="text-xs text-foreground">
            {t("retention.hold.reasonShown", { reason: hold.reason ?? "—", who: hold.set_by ?? "—" })}
          </p>
          <p className="text-xs text-muted-foreground">{t("lifecycle.holdBlocks")}</p>
        </div>
      ) : null}

      {status === "active" ? (
        <div className="space-y-2">
          <Textarea
            aria-label={t("lifecycle.reason")}
            placeholder={t("lifecycle.reasonPlaceholder")}
            value={reason}
            maxLength={1000}
            onChange={(event) => setReason(event.target.value)}
          />
          <label className="flex items-center gap-2 text-xs text-foreground">
            <input
              type="checkbox"
              checked={revoke}
              onChange={(event) => setRevoke(event.target.checked)}
            />
            {t("lifecycle.revoke")}
          </label>
          <p className="text-[11px] text-muted-foreground">{t("lifecycle.suspendHint")}</p>
          <Button
            type="button"
            className="gap-2 bg-amber-600 text-foreground hover:bg-amber-500"
            disabled={!reason.trim() || suspend.isPending}
            onClick={() => suspend.mutate({ reason: reason.trim(), revoke_credentials: revoke })}
          >
            <Ban className="h-4 w-4" />
            {t("lifecycle.suspend")}
          </Button>
        </div>
      ) : null}

      {status === "suspended" ? (
        <div className="space-y-1">
          <Button
            type="button"
            variant="outline"
            className="gap-2 border-border"
            disabled={resume.isPending}
            onClick={() => resume.mutate(undefined)}
          >
            <Play className="h-4 w-4" />
            {t("lifecycle.resume")}
          </Button>
          <p className="text-[11px] text-muted-foreground">{t("lifecycle.resumeHint")}</p>
        </div>
      ) : null}

      {status === "active" || status === "suspended" ? (
        <div className="space-y-1 border-t border-border pt-3">
          <Button
            type="button"
            className="gap-2 bg-rose-600 text-foreground hover:bg-rose-500"
            disabled={hold != null}
            onClick={() => setConfirming("delete")}
          >
            <Trash2 className="h-4 w-4" />
            {t("lifecycle.requestDeletion")}
          </Button>
          <p className="text-[11px] text-muted-foreground">
            {t("lifecycle.requestHint", { days: data.grace_days })}
          </p>
        </div>
      ) : null}

      {deletion && status === "pending_deletion" ? (
        <div className="space-y-2 rounded-lg border border-rose-500/40 bg-rose-500/5 p-3">
          <p className="text-foreground">
            {t("lifecycle.pending", {
              who: deletion.requested_by,
              after: when(deletion.purge_after),
            })}
          </p>
          <p className="text-xs text-muted-foreground">{deletion.reason}</p>
          {data.two_person ? (
            <p className="text-[11px] text-muted-foreground">{t("lifecycle.twoPerson")}</p>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="outline"
              className="gap-2 border-border"
              disabled={cancel.isPending}
              onClick={() => cancel.mutate(undefined)}
            >
              <Undo2 className="h-4 w-4" />
              {t("lifecycle.cancel")}
            </Button>
            <Button
              type="button"
              className="gap-2 bg-rose-600 text-foreground hover:bg-rose-500"
              disabled={hold != null || !graceOver}
              onClick={() => setConfirming("approve")}
            >
              <Trash2 className="h-4 w-4" />
              {t("lifecycle.approve")}
            </Button>
          </div>
        </div>
      ) : null}

      {deletion && status === "deleting" ? (
        <div className="space-y-2">
          <p className="text-foreground">
            {deletion.state === "blocked"
              ? t("lifecycle.blocked")
              : t("lifecycle.purging", { who: deletion.approved_by ?? "—" })}
          </p>
          {deletion.last_error ? (
            <p className="text-xs text-rose-500" role="alert">
              {deletion.last_error}
            </p>
          ) : null}
          <DeletionProgress deletion={deletion} />
          {canRetry ? (
            <Button
              type="button"
              variant="outline"
              className="gap-2 border-border"
              disabled={retry.isPending || (deletion.state === "blocked" && hold != null)}
              onClick={() => retry.mutate(undefined)}
            >
              <RotateCcw className="h-4 w-4" />
              {t("lifecycle.retry")}
            </Button>
          ) : null}
        </div>
      ) : null}

      {status === "deleted" && data.history[0] ? (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground">
            {t("lifecycle.completed", { when: when(data.history[0].completed_at) })}
          </p>
          <DeletionProgress deletion={data.history[0]} />
        </div>
      ) : null}

      <AlertDialog open={confirming !== null} onOpenChange={(open) => (open ? null : closeConfirm())}>
        <AlertDialogContent className="border-border bg-card text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              {confirming === "approve"
                ? t("lifecycle.approveTitle", { tenant: tenantId })
                : t("lifecycle.deleteTitle", { tenant: tenantId })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs text-muted-foreground">
              {confirming === "approve"
                ? t("lifecycle.approveHint")
                : t("lifecycle.deleteHint", { days: data.grace_days })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          {confirming === "delete" ? (
            <Textarea
              aria-label={t("lifecycle.deletionReason")}
              value={reason}
              maxLength={1000}
              onChange={(event) => setReason(event.target.value)}
            />
          ) : null}
          <Input
            aria-label={t("lifecycle.typeToConfirm", { tenant: tenantId })}
            placeholder={tenantId}
            value={typed}
            onChange={(event) => setTyped(event.target.value)}
          />
          <AlertDialogFooter>
            <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">
              {t("ui.cancel")}
            </AlertDialogCancel>
            <Button
              type="button"
              className="bg-rose-600 text-foreground hover:bg-rose-500"
              disabled={
                typed !== tenantId ||
                (confirming === "delete" && !reason.trim()) ||
                request.isPending ||
                approve.isPending
              }
              onClick={() => {
                if (confirming === "approve") {
                  approve.mutate(typed);
                } else {
                  request.mutate({ confirm: typed, reason: reason.trim() });
                }
                closeConfirm();
              }}
            >
              {confirming === "approve" ? t("lifecycle.approve") : t("lifecycle.requestDeletion")}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
