"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Download, ScrollText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { DataTable } from "@/components/data-table";
import { useAuditEvents, useAuditExport } from "@/hooks/use-audit";
import { usePagination } from "@/hooks/use-pagination";
import { type AuditEventInfo, type AuditFilters } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";
import { changeShape, changedFields } from "@/lib/audit-change";

const INPUT_CLASS = "h-9 w-40";

/** The actions the API records (api/services/audit.py). Listed rather than
 * free-typed: the filter is an exact match, so a typo would silently answer
 * "nothing happened". */
const ACTIONS = [
  "user.create",
  "user.role_change",
  "user.disable",
  "user.delete",
  "user.password_reset",
  "user.password_change",
  // Data-subject requests and retention (#332).
  "user.export",
  "user.erase",
  "membership.grant",
  "membership.revoke",
  "service_token.create",
  "service_token.revoke",
  "provisioning_key.create",
  "provisioning_key.revoke",
  "agent.register",
  "agent.disable",
  "agent.enable",
  "agent.quarantine",
  "agent.delete",
  "report.download",
  "scan_scope.replace",
  "config.update",
  "maintenance_window.create",
  "maintenance_window.update",
  "maintenance_window.delete",
  "tenant.change_freeze",
  // Not an operator's edit but the platform's own refusal: the filter that
  // answers "which window stopped our scans last night" (#352).
  "scan.maintenance_block",
  "notification_channel.create",
  "notification_channel.update",
  "notification_channel.delete",
  "vulnerability.bulk",
  "asset.bulk",
  "retention_policy.update",
  "legal_hold.place",
  "legal_hold.release",
  // The tenant lifecycle (#325). Platform-level rows: a platform admin's
  // filter, and the last three are the purge worker's own.
  "tenant.suspend",
  "tenant.resume",
  "tenant.delete.request",
  "tenant.delete.cancel",
  "tenant.delete.approve",
  "tenant.delete.retry",
  "tenant.delete.fail",
  "tenant.delete.block",
  "tenant.delete.complete",
] as const;

/** ISO instant from a `datetime-local` value, or undefined when it is empty.
 * The input is in the operator's own zone; `new Date()` reads it that way and
 * `toISOString` sends the instant, which is what the API compares. */
function instant(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

/** How many changed fields a row shows before it says "+N more". The row is a
 * summary; the whole document is one click away. */
const FIELDS_IN_SUMMARY = 3;

/** One row's change: the fields that differ, and the document behind them. */
function ChangeCell({ event }: { event: AuditEventInfo }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const fields = changedFields(event.before, event.after);

  // A creation has no `before` and a deletion no `after`. Saying which is more
  // use than listing every field of the document as "changed".
  const kind = changeShape(event.before, event.after);
  const shape = kind === "created" ? t("audit.change.created") : kind === "removed" ? t("audit.change.removed") : null;

  return (
    <div className="w-[17rem] max-w-[17rem] space-y-1">
      {shape ? (
        <p className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
          {shape}
        </p>
      ) : null}
      {fields.length === 0 ? (
        <p className="text-[11px] text-muted-foreground">{t("audit.change.none")}</p>
      ) : (
        <ul className="space-y-0.5">
          {fields.slice(0, FIELDS_IN_SUMMARY).map((field) => (
            <li
              key={field.key}
              // One line per field, clipped rather than wrapped: a row whose
              // height depends on how long somebody's note was is the problem
              // this cell had. The title carries the untruncated pair, and the
              // document below carries all of it.
              className="flex items-baseline gap-1 truncate text-[11px]"
              title={`${field.key}: ${field.from} → ${field.to}`}
            >
              <span className="font-mono font-semibold text-foreground">{field.key}</span>
              <span className="font-mono text-muted-foreground line-through">{field.from}</span>
              <span className="text-muted-foreground">→</span>
              <span className="truncate font-mono text-foreground">{field.to}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="flex items-baseline gap-2 text-[11px]">
        {fields.length > FIELDS_IN_SUMMARY ? (
          <span className="text-muted-foreground">
            {t("audit.change.more", { count: fields.length - FIELDS_IN_SUMMARY })}
          </span>
        ) : null}
        <button
          type="button"
          className="font-medium text-primary hover:underline"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? t("audit.change.hide") : t("audit.change.show")}
        </button>
      </div>
      {open ? (
        <pre className="max-h-64 overflow-auto rounded-md border border-border bg-muted p-2 font-mono text-[11px] text-foreground">
          {JSON.stringify({ before: event.before, after: event.after }, null, 2)}
        </pre>
      ) : null}
    </div>
  );
}

export default function AuditPage() {
  const t = useT();
  const when = useAbsoluteTime();
  const { activeTenant } = useAuthStore();
  const pagination = usePagination();
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [resourceId, setResourceId] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");

  // Naming a tenant narrows the answer; a platform admin with none selected
  // reads every tenant. Which of the two the caller is entitled to is the API's
  // decision, not this component's — it answers 403 for a tenant the caller
  // does not administer.
  const filters = useMemo<AuditFilters>(
    () => ({
      tenantId: activeTenant ?? undefined,
      action: action || undefined,
      actor: actor.trim() || undefined,
      resourceId: resourceId.trim() || undefined,
      from: instant(from),
      to: instant(to),
    }),
    [activeTenant, action, actor, resourceId, from, to],
  );

  // Enabled unconditionally: "admin" on the API means admin *in the tenant*,
  // which the console cannot know from the account's global role — a tenant
  // admin signed in as a global viewer would otherwise be shown an empty page
  // instead of their own trail.
  const { data, isLoading, error } = useAuditEvents(true, pagination.params, filters);
  const exporter = useAuditExport(filters);
  const events = data?.items ?? [];

  const columns = useMemo<ColumnDef<AuditEventInfo>[]>(
    () => [
      {
        accessorKey: "occurred_at",
        header: t("audit.column.time"),
        enableSorting: false,
        cell: ({ row }) => (
          // Formatted, and not wrapped: the raw ISO instant broke across three
          // lines in a column this narrow, so the one column every audit row is
          // read by was the hardest to read.
          <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
            {when(row.original.occurred_at)}
          </span>
        ),
      },
      {
        accessorKey: "actor",
        header: t("audit.column.actor"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs font-semibold text-foreground">
            {row.original.actor || "—"}
            <span className="ml-1 font-sans font-normal text-muted-foreground">
              ({row.original.actor_type})
            </span>
          </span>
        ),
      },
      {
        accessorKey: "action",
        header: t("audit.column.action"),
        enableSorting: false,
        cell: ({ row }) => <span className="font-mono text-xs">{row.original.action}</span>,
      },
      {
        accessorKey: "resource_id",
        header: t("audit.column.resource"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.resource_type}/{row.original.resource_id || "—"}
          </span>
        ),
      },
      {
        accessorKey: "tenant_id",
        header: t("audit.column.tenant"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.tenant_id ?? t("audit.platformLevel")}
          </span>
        ),
      },
      {
        accessorKey: "client_ip",
        header: t("audit.column.ip"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.client_ip || "—"}
          </span>
        ),
      },
      {
        id: "change",
        header: t("audit.column.change"),
        enableSorting: false,
        // The changed fields, in the row; the whole document a click away.
        //
        // This used to be `JSON.stringify({before, after})` in a `break-all`
        // <pre>, which is the answer this page exists for rendered as an
        // unreadable ribbon: one row grew to a quarter of the screen and
        // squeezed every other column, including the timestamp, into a
        // wrapping sliver. The summary keeps the answer in the row and the
        // table legible; the document is still there for the reader who needs
        // the exact text, and is still redacted server-side either way.
        cell: ({ row }) => <ChangeCell event={row.original} />,
      },
    ],
    [t, when],
  );

  return (
    <div className="space-y-6 p-6">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <ScrollText className="h-5 w-5" />
          {t("nav.audit")}
        </h1>
        <p className="text-sm text-muted-foreground">{t("audit.note")}</p>
      </header>
      <DataTable
        columns={columns}
        data={events}
        isLoading={isLoading}
        error={error}
        loadingMessage={t("audit.loading")}
        emptyMessage={t("audit.empty")}
        meta={t("audit.meta", { total: data?.total ?? 0 })}
        toolbar={
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label={t("audit.column.action")}
              className="h-9 rounded-md border border-input bg-background px-2 text-sm"
              value={action}
              onChange={(event) => {
                setAction(event.target.value);
                pagination.reset();
              }}
            >
              <option value="">{t("audit.allActions")}</option>
              {ACTIONS.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
            <Input
              aria-label={t("audit.column.actor")}
              className={INPUT_CLASS}
              placeholder={t("audit.filter.actor")}
              value={actor}
              onChange={(event) => {
                setActor(event.target.value);
                pagination.reset();
              }}
            />
            <Input
              aria-label={t("audit.column.resource")}
              className={INPUT_CLASS}
              placeholder={t("audit.filter.resource")}
              value={resourceId}
              onChange={(event) => {
                setResourceId(event.target.value);
                pagination.reset();
              }}
            />
            <Input
              aria-label={t("audit.filter.from")}
              className={INPUT_CLASS}
              type="datetime-local"
              value={from}
              onChange={(event) => {
                setFrom(event.target.value);
                pagination.reset();
              }}
            />
            <Input
              aria-label={t("audit.filter.to")}
              className={INPUT_CLASS}
              type="datetime-local"
              value={to}
              onChange={(event) => {
                setTo(event.target.value);
                pagination.reset();
              }}
            />
            <Button
              variant="outline"
              size="sm"
              disabled={exporter.isPending}
              onClick={() => exporter.mutate("csv")}
            >
              <Download className="mr-1 h-4 w-4" />
              {t("audit.export.csv")}
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={exporter.isPending}
              onClick={() => exporter.mutate("ndjson")}
            >
              <Download className="mr-1 h-4 w-4" />
              {t("audit.export.ndjson")}
            </Button>
          </div>
        }
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: data?.total ?? 0,
          onOffsetChange: pagination.setOffset,
        }}
      />
    </div>
  );
}
