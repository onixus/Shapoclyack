"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { CategoryBadge, CategoryCards, ProgressBar } from "@/components/campaign/campaign-progress";
import {
  useAddCampaignMembers,
  useCampaign,
  useCampaignEvents,
  useCampaignMembers,
  useCampaignStatusChange,
  useExcludeCampaignMembers,
  useUpdateCampaign,
  useVerifyCampaign,
} from "@/hooks/use-campaigns";
import { usePagination } from "@/hooks/use-pagination";
import { useAuthStore } from "@/lib/auth-store";
import {
  CONSOLE_RESUME_REASON,
  dueAtFromInput,
  localDateInput,
  type CampaignCategory,
  type CampaignMember,
  type VerifyReport,
} from "@/lib/campaigns";
import { CAMPAIGN_STATUS, SEVERITY_STATUS, VULN_LIFECYCLE_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";
import { normalizeSeverity } from "@/lib/run-data";
import { vulnDetailHref } from "@/lib/vuln-lifecycle";

function ReasonDialog({
  open,
  onOpenChange,
  title,
  fieldLabel,
  submitLabel,
  onSubmit,
  children,
  extra,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  fieldLabel: string;
  submitLabel: string;
  onSubmit: (reason: string, extra: string) => void;
  children?: React.ReactNode;
  extra?: { label: string };
}) {
  const t = useT();
  const [reason, setReason] = useState("");
  const [more, setMore] = useState("");
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{children}</DialogDescription>
        </DialogHeader>
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault();
            onSubmit(reason.trim(), more);
            setReason("");
            setMore("");
          }}
        >
          {extra ? (
            <div className="space-y-1.5">
              <Label htmlFor="campaign-extra">{extra.label}</Label>
              <Textarea
                id="campaign-extra"
                value={more}
                onChange={(event) => setMore(event.target.value)}
                rows={5}
                className="font-mono text-xs"
              />
            </div>
          ) : null}
          <div className="space-y-1.5">
            <Label htmlFor="campaign-reason">{fieldLabel}</Label>
            <Input
              id="campaign-reason"
              value={reason}
              minLength={3}
              maxLength={1000}
              required
              onChange={(event) => setReason(event.target.value)}
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t("campaign.cancel")}
            </Button>
            <Button type="submit" disabled={reason.trim().length < 3 || (Boolean(extra) && !more.trim())}>
              {submitLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function VerifyReportDialog({ report, onClose }: { report: VerifyReport | null; onClose: () => void }) {
  const t = useT();
  return (
    <Dialog open={Boolean(report)} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{t("campaign.verify.report")}</DialogTitle>
          <DialogDescription data-testid="verify-summary">
            {report
              ? Object.entries(report.summary)
                  .map(([outcome, count]) => `${outcome}: ${count}`)
                  .join(" · ") || "—"
              : ""}
          </DialogDescription>
        </DialogHeader>
        <ul className="space-y-1.5 text-xs">
          {report?.results.map((item) => (
            <li key={item.id} className="rounded border border-border p-2">
              <span className="font-mono">{item.id}</span> — <strong>{item.outcome}</strong>
              {item.detail ? <p className="mt-0.5 text-muted-foreground">{item.detail}</p> : null}
            </li>
          ))}
        </ul>
      </DialogContent>
    </Dialog>
  );
}

export function CampaignDetail({ id }: { id: string }) {
  const t = useT();
  const ago = useRelativeTime();
  const { canOperate } = useAuthStore();
  const campaign = useCampaign(id);
  const [category, setCategory] = useState<CampaignCategory | "">("");
  const [selected, setSelected] = useState<string[]>([]);
  const members = usePagination({ sort: "severity", order: "desc" });
  const membersQuery = useCampaignMembers(id, members.params, { status: "included", category });
  const events = useCampaignEvents(id, { limit: 50 });
  const update = useUpdateCampaign(id);
  const add = useAddCampaignMembers(id);
  const exclude = useExcludeCampaignMembers(id);
  const verify = useVerifyCampaign(id);
  const statusChange = useCampaignStatusChange(id);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [dialog, setDialog] = useState<"add" | "exclude" | "cancel" | null>(null);
  const [editing, setEditing] = useState(false);

  const data = campaign.data;
  const rows = membersQuery.data?.items ?? [];
  const total = membersQuery.data?.total ?? 0;

  const columns = useMemo<ColumnDef<CampaignMember>[]>(
    () => [
      {
        id: "finding",
        header: t("col.finding"),
        enableSorting: false,
        cell: ({ row }) => (
          <Link href={vulnDetailHref(row.original.vuln_id)} className="group space-y-0.5">
            <p className="whitespace-nowrap font-mono text-sm font-bold text-sky-600 group-hover:underline dark:text-sky-400">
              {row.original.cve || row.original.title || row.original.problem_key}
            </p>
            <p className="text-xs text-muted-foreground">
              {row.original.recurred ? `${t("campaign.recurred")} · ` : ""}
              {row.original.problem_key}
            </p>
          </Link>
        ),
      },
      { id: "asset_id", header: t("col.asset"), accessorKey: "asset_id", cell: ({ row }) => <span className="font-mono text-xs">{row.original.asset_id}</span> },
      {
        id: "severity",
        accessorFn: (row) => row.severity,
        header: t("col.severity"),
        cell: ({ row }) => <StatusBadge value={normalizeSeverity(row.original.severity)} map={SEVERITY_STATUS} />,
      },
      {
        id: "state",
        accessorFn: (row) => row.state,
        header: t("col.lifecycle"),
        cell: ({ row }) => <StatusBadge value={row.original.state} map={VULN_LIFECYCLE_STATUS} />,
      },
      {
        id: "category",
        header: t("campaign.col.progress"),
        enableSorting: false,
        cell: ({ row }) => <CategoryBadge category={row.original.category} />,
      },
      {
        id: "ticket",
        header: t("campaign.col.ticket"),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.ticket_key ? (
            row.original.ticket_url ? (
              <a href={row.original.ticket_url} target="_blank" rel="noreferrer" className="text-xs text-sky-600 hover:underline dark:text-sky-400">
                {row.original.ticket_key}
              </a>
            ) : (
              <span className="text-xs">{row.original.ticket_key}</span>
            )
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
      {
        id: "verification",
        header: t("campaign.col.verification"),
        enableSorting: false,
        cell: ({ row }) => {
          const { verification, last_verify: last } = row.original;
          if (!verification && !last.outcome) return <span className="text-xs text-muted-foreground">—</span>;
          return (
            <div className="space-y-0.5 text-xs">
              {last.outcome ? (
                <p>
                  <strong>{last.outcome}</strong>
                  {last.detail ? <span className="text-muted-foreground"> — {last.detail}</span> : null}
                </p>
              ) : null}
              {verification ? (
                <p className="text-muted-foreground">
                  {verification.kind.replace("verification_", "")}
                  {verification.gaps?.length ? `: ${verification.gaps.join("; ")}` : ""}
                </p>
              ) : null}
            </div>
          );
        },
      },
    ],
    [t],
  );

  if (campaign.isLoading) return <p className="text-sm text-muted-foreground">{t("campaign.loading")}</p>;
  if (campaign.error || !data) {
    return (
      <p role="alert" className="text-sm text-rose-600 dark:text-rose-400">
        {campaign.error?.message ?? t("campaign.notFound")}
      </p>
    );
  }
  const cancelled = data.status === "cancelled";

  return (
    <div className="space-y-6">
      <Link href="/campaigns" className="inline-flex items-center gap-1 text-xs text-sky-600 hover:underline dark:text-sky-400">
        <ArrowLeft className="h-3 w-3" /> {t("campaign.detail.back")}
      </Link>

      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold tracking-tight">{data.name}</h1>
            <StatusBadge value={data.status} map={CAMPAIGN_STATUS} />
            {data.past_due ? (
              <span className="text-xs font-medium text-rose-600 dark:text-rose-400">{t("campaign.pastDue")}</span>
            ) : null}
          </div>
          <p className="text-xs text-muted-foreground">
            {data.owner ?? "—"} · {data.due_at ? new Date(data.due_at).toLocaleDateString() : "—"} ·{" "}
            {data.created_by ?? "—"} · {ago(data.created_at)}
            {data.reopen_count ? ` · ${t("campaign.detail.reopened", { count: data.reopen_count })}` : ""}
          </p>
          <p className="max-w-3xl whitespace-pre-wrap text-sm" data-testid="campaign-action">
            <span className="text-xs text-muted-foreground">{t("campaign.detail.action")}: </span>
            {data.description || t("campaign.detail.noAction")}
          </p>
          <ProgressBar progress={data.progress} />
        </div>
        {canOperate ? (
          <div className="flex flex-wrap gap-2">
            {!cancelled ? (
              <>
                <Button variant="outline" size="sm" onClick={() => setEditing((v) => !v)}>
                  {t("campaign.edit")}
                </Button>
                <Button
                  size="sm"
                  disabled={verify.isPending}
                  onClick={() => verify.mutate(undefined, { onSuccess: setReport })}
                >
                  {t("campaign.verify")}
                </Button>
                <Button variant="outline" size="sm" onClick={() => setDialog("add")}>
                  {t("campaign.members.add")}
                </Button>
                <Button variant="outline" size="sm" onClick={() => setDialog("cancel")}>
                  {t("campaign.cancelAction")}
                </Button>
              </>
            ) : (
              <Button size="sm" onClick={() => statusChange.mutate({ action: "resume", reason: CONSOLE_RESUME_REASON })}>
                {t("campaign.resume")}
              </Button>
            )}
          </div>
        ) : null}
      </div>

      {editing && canOperate ? (
        <form
          className="grid gap-3 rounded-md border border-border p-3 sm:grid-cols-2"
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            const due = String(form.get("due") || "");
            update.mutate(
              {
                name: String(form.get("name") || data.name),
                owner: String(form.get("owner") || "") || null,
                description: String(form.get("description") || ""),
                due_at: dueAtFromInput(due),
              },
              { onSuccess: () => setEditing(false) },
            );
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="edit-name">{t("campaign.field.name")}</Label>
            <Input id="edit-name" name="name" defaultValue={data.name} required />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-owner">{t("campaign.field.owner")}</Label>
            <Input id="edit-owner" name="owner" defaultValue={data.owner ?? ""} />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="edit-due">{t("campaign.field.due")}</Label>
            <Input id="edit-due" name="due" type="date" defaultValue={localDateInput(data.due_at)} />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="edit-description">{t("campaign.field.action")}</Label>
            <Textarea id="edit-description" name="description" defaultValue={data.description} />
          </div>
          <div className="sm:col-span-2">
            <Button type="submit" size="sm" disabled={update.isPending}>
              {t("campaign.save")}
            </Button>
          </div>
        </form>
      ) : null}

      <CategoryCards progress={data.progress} active={category} onSelect={(next) => { setCategory(next); setSelected([]); members.reset(); }} />

      <section aria-label={t("campaign.members.title")} className="space-y-2">
        <h2 className="text-sm font-semibold">{t("campaign.members.title")}</h2>
        <DataTable
          columns={columns}
          data={rows}
          isLoading={membersQuery.isLoading}
          error={membersQuery.error}
          emptyMessage={t("campaign.members.empty")}
          meta={`${total}`}
          selection={
            canOperate && !cancelled
              ? {
                  rowId: (row) => row.vuln_id,
                  selected,
                  onChange: setSelected,
                  max: 200,
                  selectAllLabel: t("campaign.members.selectAll"),
                  actions: (ids) => (
                    <>
                      <Button
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() => verify.mutate(ids, { onSuccess: setReport })}
                      >
                        {t("campaign.verify.selected")}
                      </Button>
                      <Button variant="outline" size="sm" className="h-7 text-xs" onClick={() => setDialog("exclude")}>
                        {t("campaign.members.exclude")}
                      </Button>
                    </>
                  ),
                }
              : undefined
          }
          serverPagination={{
            offset: members.offset,
            limit: members.limit,
            total,
            onOffsetChange: (offset) => { setSelected([]); members.setOffset(offset); },
            search: "",
            searchRevision: 0,
            onSearchChange: () => undefined,
            sortableColumns: ["severity", "state", "asset_id"],
            sort: members.sort,
            order: members.order,
            onSortChange: (sort, order) => { setSelected([]); members.setSort(sort, order); },
          }}
        />
      </section>

      <section aria-label={t("campaign.events.title")} className="space-y-2">
        <h2 className="text-sm font-semibold">{t("campaign.events.title")}</h2>
        <ol className="space-y-1.5 text-xs">
          {(events.data?.items ?? []).map((event) => (
            <li key={event.id} className="rounded border border-border p-2">
              <span className="font-medium">{event.kind.replace(/_/g, " ")}</span>
              <span className="text-muted-foreground">
                {" "}· {event.actor ?? "system"} · {ago(event.occurred_at)}
              </span>
              {event.reason ? <p className="mt-0.5">{event.reason}</p> : null}
            </li>
          ))}
        </ol>
      </section>

      <ReasonDialog
        open={dialog === "add"}
        onOpenChange={(open) => !open && setDialog(null)}
        title={t("campaign.members.add")}
        fieldLabel={t("campaign.members.reason")}
        submitLabel={t("campaign.members.add")}
        extra={{ label: t("campaign.members.ids") }}
        onSubmit={(reason, ids) => {
          const vulnIds = ids.split(/\s+/).map((s) => s.trim()).filter(Boolean);
          add.mutate({ selection: { vuln_ids: vulnIds }, reason }, { onSuccess: () => setDialog(null) });
        }}
      />
      <ReasonDialog
        open={dialog === "exclude"}
        onOpenChange={(open) => !open && setDialog(null)}
        title={t("campaign.members.exclude")}
        fieldLabel={t("campaign.members.reason")}
        submitLabel={t("campaign.members.exclude")}
        onSubmit={(reason) =>
          exclude.mutate(
            { vulnIds: selected, reason },
            { onSuccess: () => { setSelected([]); setDialog(null); } },
          )
        }
      >
        {t("campaign.members.excludeCount", { count: selected.length })}
      </ReasonDialog>
      <ReasonDialog
        open={dialog === "cancel"}
        onOpenChange={(open) => !open && setDialog(null)}
        title={t("campaign.cancelAction")}
        fieldLabel={t("campaign.members.reason")}
        submitLabel={t("campaign.cancelAction")}
        onSubmit={(reason) =>
          statusChange.mutate({ action: "cancel", reason }, { onSuccess: () => setDialog(null) })
        }
      />
      <VerifyReportDialog report={report} onClose={() => setReport(null)} />
    </div>
  );
}
