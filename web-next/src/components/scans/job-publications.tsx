"use client";

import { useState } from "react";
import { format } from "date-fns";
import { Hourglass, RotateCcw, TriangleAlert, Trash2 } from "lucide-react";
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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  useDiscardPublication,
  useJobPublications,
  useRequeuePublication,
} from "@/hooks/use-jobs";
import { type JobInfo, type RunPublicationInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { isTenantAdmin } from "@/lib/authz";
import { type MsgKey, useT } from "@/lib/i18n";

/** A publication row exists only once the job's terminal status is written. */
const ENDED: ReadonlyArray<JobInfo["status"]> = ["succeeded", "failed", "cancelled"];

function stamp(iso: string | null | undefined): string | null {
  return iso ? format(new Date(iso), "yyyy-MM-dd HH:mm:ss") : null;
}

const STATE_TONE: Record<RunPublicationInfo["state"], string> = {
  publishing: "border-sky-500/40 text-sky-700 dark:text-sky-300",
  retrying: "border-amber-500/40 text-amber-700 dark:text-amber-300",
  dead: "border-rose-500/40 text-rose-700 dark:text-rose-300",
};

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid grid-cols-[minmax(0,9rem)_1fr] items-start gap-3 py-1 text-xs">
      <dt className="font-semibold text-muted-foreground" title={hint}>
        {label}
      </dt>
      <dd className="min-w-0 break-words text-foreground">{children}</dd>
    </div>
  );
}

/**
 * What a finished job's accepted run still owes before it is visible (#425):
 * the `run_publications` rows, with the operator's two ways out of a dead one.
 * Renders nothing for the ordinary job, whose row was deleted when it landed.
 */
export function JobPublications({ job, open }: { job: JobInfo; open: boolean }) {
  const t = useT();
  const user = useAuthStore((s) => s.user);
  const canDecide = Boolean(user?.is_platform_admin) || isTenantAdmin(user);
  const publications = useJobPublications(job.job_id, open && ENDED.includes(job.status));
  const requeue = useRequeuePublication(job.job_id);
  const discard = useDiscardPublication(job.job_id);
  const [discardTarget, setDiscardTarget] = useState<RunPublicationInfo | null>(null);

  const rows = publications.data ?? [];
  if (rows.length === 0) return null;

  return (
    <section className="mt-5" aria-label={t("jobs.publication.title")}>
      <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
        {t("jobs.publication.title")}
      </h4>
      <p className="mt-1 text-xs text-muted-foreground">{t("jobs.publication.hint")}</p>
      {rows.map((row) => (
        <div
          key={row.publication_id}
          className="mt-2 rounded-lg border border-border bg-muted/30 px-3 py-2"
          data-testid="run-publication"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] text-muted-foreground">
              {row.publication_id}
            </span>
            <Badge variant="outline" className={`text-[10px] ${STATE_TONE[row.state]}`}>
              {t(`jobs.publication.state.${row.state}` as MsgKey)}
            </Badge>
          </div>
          <dl className="mt-1 divide-y divide-border/60">
            <Field label={t("jobs.publication.attempts")}>
              <span className="font-mono">
                {row.attempts} / {row.max_attempts}
              </span>
            </Field>
            {row.last_error ? (
              <Field label={t("jobs.publication.lastError")}>
                <span className="font-mono text-rose-700 dark:text-rose-300">
                  {row.last_error}
                </span>
              </Field>
            ) : null}
            {row.stored_at ? (
              <Field label={t("jobs.publication.stored")} hint={t("jobs.publication.storedHint")}>
                <span className="font-mono">{stamp(row.stored_at)}</span>
              </Field>
            ) : null}
            {row.status === "pending" && row.next_attempt_at ? (
              <Field label={t("jobs.publication.nextAttempt")}>
                <span className="font-mono">{stamp(row.next_attempt_at)}</span>
              </Field>
            ) : null}
            {row.lease_lapses > 0 ? (
              <Field
                label={t("jobs.publication.leaseLapses")}
                hint={t("jobs.publication.leaseLapsesHint")}
              >
                <span className="font-mono text-amber-700 dark:text-amber-300">
                  {row.lease_lapses}
                </span>
              </Field>
            ) : null}
            {row.replica ? (
              <Field label={t("jobs.publication.replica")}>
                <span className="font-mono">{row.replica}</span>
              </Field>
            ) : null}
            {row.staging_path ? (
              <Field label={t("jobs.publication.stagingPath")}>
                <span className="font-mono">{row.staging_path}</span>
              </Field>
            ) : null}
          </dl>

          {row.silent ? (
            <p className="mt-2 flex items-start gap-1.5 text-xs text-amber-800 dark:text-amber-200">
              <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {t("jobs.publication.silent", {
                deadline: stamp(row.orphan_deadline_at) ?? "—",
              })}
            </p>
          ) : null}
          <p className="mt-2 text-xs text-muted-foreground">
            {t(`jobs.publication.resolution.${row.resolution}` as MsgKey)}
          </p>
          {row.status === "dead" && !row.actionable ? (
            <p className="mt-1 flex items-start gap-1.5 text-xs text-muted-foreground">
              <Hourglass className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {t("jobs.publication.inFlight", { at: stamp(row.actionable_at) ?? "—" })}
            </p>
          ) : null}

          {canDecide && row.status === "dead" ? (
            <div className="mt-2 flex flex-wrap gap-2">
              <Button
                type="button"
                size="sm"
                // A requeue of a tree no replica can reach walks back to dead an
                // hour later; it stays possible (the disk may have come back),
                // but it is not the suggested action.
                variant={row.resolution === "requeue" ? "default" : "outline"}
                disabled={!row.actionable || requeue.isPending}
                onClick={() => requeue.mutate(row.publication_id)}
              >
                <RotateCcw className="mr-1 h-3.5 w-3.5" />
                {t("jobs.publication.requeue")}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="text-rose-700 dark:text-rose-300"
                disabled={!row.actionable || discard.isPending}
                onClick={() => setDiscardTarget(row)}
              >
                <Trash2 className="mr-1 h-3.5 w-3.5" />
                {t("jobs.publication.discard")}
              </Button>
            </div>
          ) : null}
        </div>
      ))}

      <AlertDialog
        open={Boolean(discardTarget)}
        onOpenChange={(isOpen) => !isOpen && setDiscardTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("jobs.publication.discardTitle", { id: discardTarget?.publication_id ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs">
              {t("jobs.publication.discardBody")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("jobs.publication.keep")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-foreground hover:bg-rose-500"
              onClick={() => {
                if (discardTarget) discard.mutate(discardTarget.publication_id);
                setDiscardTarget(null);
              }}
            >
              {t("jobs.publication.discard")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
