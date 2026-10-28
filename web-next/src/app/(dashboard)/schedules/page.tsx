"use client";
import { scanIntentLabel, scanModeLabel } from "@/lib/scan-labels";
import { ScanTechnicalDetails } from "@/components/scans/scan-technical-details";

import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Pencil, Plus, Timer, Trash2 } from "lucide-react";
import { MaintenancePanel } from "@/components/scans/maintenance-panel";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { scheduleSurface, type ScanSurface } from "@/lib/scan-surface";
import { translate, type Locale } from "@/lib/i18n";
import { useT } from "@/lib/i18n";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { CheckboxOption, Field, FieldGrid } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import {
  useCreateSchedule,
  useDeleteSchedule,
  useSchedules,
  useUpdateSchedule,
} from "@/hooks/use-schedules";
import { usePagination } from "@/hooks/use-pagination";
import { useSystemStatus } from "@/hooks/use-system";
import { type CreateScheduleBody, type ScanSchedule } from "@/lib/api";
import { SCHEDULE_ENABLED_STATUS } from "@/lib/config/statuses";
import { useAuthStore } from "@/lib/auth-store";
import { isTenantAdmin } from "@/lib/authz";

type CadenceKind = "cron" | "interval";

const EMPTY_FORM = {
  name: "",
  cadenceKind: "cron" as CadenceKind,
  cron: "0 * * * *",
  intervalSeconds: "3600",
  mode: "balanced" as CreateScheduleBody["mode"],
  intent: "inventory" as NonNullable<CreateScheduleBody["intent"]> | "",
  // "" lets the server derive the surface from the targets.
  surface: "" as ScanSurface | "",
  delta: true,
  skipNse: false,
  notify: false,
  ranges: "",
  domains: "",
  ports: "",
  portsUdp: "",
};

function targetsSummary(schedule: ScanSchedule, locale: Locale): string {
  const parts: string[] = [];
  if (schedule.targets.ranges)
    parts.push(
      translate(locale, "scanCopy.rangeCount", {
        count: schedule.targets.ranges.split(/\s+/).filter(Boolean).length,
      }),
    );
  if (schedule.targets.domains)
    parts.push(
      translate(locale, "scanCopy.domainCount", {
        count: schedule.targets.domains.split(/\s+/).filter(Boolean).length,
      }),
    );
  if (!parts.length) return translate(locale, "scanCopy.defaults");
  return parts.join(", ");
}

function cadenceSummary(schedule: ScanSchedule, locale: Locale): string {
  if (schedule.cron)
    return locale === "ru" ? translate(locale, "scanCopy.calendar") : `cron: ${schedule.cron}`;
  if (schedule.interval_seconds)
    return translate(locale, "scanCopy.every", { seconds: schedule.interval_seconds });
  return "—";
}

export default function SchedulesPage() {
  const t = useT();
  const { user, canOperate } = useAuthStore();
  // `PUT …/maintenance` is `require_tenant(Role.admin)`: the tenant's own
  // admin, whose global role is usually viewer.
  const isAdmin = isTenantAdmin(user);

  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<ScanSchedule | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [deleteTarget, setDeleteTarget] = useState<ScanSchedule | null>(null);

  // Server-side paging/search/sort (ROADMAP P3.3): the schedule list is unbounded.
  const pagination = usePagination({ sort: "created_at", order: "desc" });
  const { data, isLoading, error, isFetching } = useSchedules(canOperate, pagination.params);
  const schedules = data?.items ?? [];
  const scheduleTotal = data?.total ?? 0;
  const createMutation = useCreateSchedule();
  const updateMutation = useUpdateSchedule();
  const deleteMutation = useDeleteSchedule();
  const { data: systemStatus } = useSystemStatus();
  const serviceBackend = systemStatus?.scan_config.service_backend;

  function openCreate() {
    setEditing(null);
    setForm(EMPTY_FORM);
    setOpen(true);
  }

  function openEdit(schedule: ScanSchedule) {
    setEditing(schedule);
    setForm({
      name: schedule.name,
      cadenceKind: schedule.cron ? "cron" : "interval",
      cron: schedule.cron ?? EMPTY_FORM.cron,
      intervalSeconds: String(schedule.interval_seconds ?? 3600),
      mode: schedule.scan_options.mode,
      intent: (schedule.scan_options.intent as CreateScheduleBody["intent"]) || "",
      surface: scheduleSurface(schedule) ?? "",
      delta: schedule.scan_options.delta,
      skipNse: schedule.scan_options.skip_nse,
      notify: schedule.scan_options.notify,
      ranges: schedule.targets.ranges ?? "",
      domains: schedule.targets.domains ?? "",
      ports: schedule.targets.ports ?? "",
      portsUdp: schedule.targets.ports_udp ?? "",
    });
    setOpen(true);
  }

  function buildBody(): CreateScheduleBody {
    // Explicit `null` (not `undefined`) for the inactive cadence field and any
    // cleared target so the PATCH actually clears it server-side, rather than
    // being dropped from the JSON body and leaving the stored value untouched.
    return {
      name: form.name.trim(),
      cron: form.cadenceKind === "cron" ? form.cron.trim() : null,
      interval_seconds:
        form.cadenceKind === "interval" ? Number(form.intervalSeconds) || null : null,
      mode: form.mode,
      intent: form.intent || null,
      surface: form.surface || null,
      delta: form.delta,
      skip_nse: form.intent ? false : form.skipNse,
      notify: form.notify,
      ranges: form.ranges.trim() || null,
      domains: form.domains.trim() || null,
      ports: form.ports.trim() || null,
      ports_udp: form.portsUdp.trim() || null,
    };
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const body = buildBody();
    if (editing) {
      updateMutation.mutate(
        { scheduleId: editing.schedule_id, body },
        { onSuccess: () => setOpen(false) },
      );
    } else {
      createMutation.mutate(body, { onSuccess: () => setOpen(false) });
    }
  }

  const columns = useMemo<ColumnDef<ScanSchedule>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("col.schedule"),
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-foreground">{row.original.name}</p>
            <p className="text-xs text-muted-foreground">
              {scanIntentLabel(t.locale, row.original.scan_options.intent)} ·{" "}
              {scanModeLabel(t.locale, row.original.scan_options.mode)}
            </p>
            <ScanTechnicalDetails
              id={row.original.schedule_id}
              intent={row.original.scan_options.intent || "legacy"}
              mode={row.original.scan_options.mode}
              cron={row.original.cron}
              interval={row.original.interval_seconds}
            />
          </div>
        ),
      },
      {
        id: "enabled",
        header: t("col.status"),
        accessorFn: (schedule) => (schedule.enabled ? "enabled" : "disabled"),
        cell: ({ row }) => (
          <StatusBadge
            value={row.original.enabled ? "enabled" : "disabled"}
            map={SCHEDULE_ENABLED_STATUS}
          />
        ),
      },
      {
        id: "surface",
        header: t("col.surface"),
        enableSorting: false,
        cell: ({ row }) => <SurfaceBadge surface={scheduleSurface(row.original)} link />,
      },
      {
        id: "cadence",
        header: t("col.cadence"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-foreground">
            {cadenceSummary(row.original, t.locale)}
          </span>
        ),
      },
      {
        id: "targets",
        header: t("col.targets"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-xs text-foreground">{targetsSummary(row.original, t.locale)}</span>
        ),
      },
      {
        accessorKey: "last_run_at",
        header: t("col.lastRun"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.last_run_at ? (
            <span className="font-mono text-xs text-muted-foreground">
              {format(new Date(row.original.last_run_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: "next_run_at",
        header: t("col.nextRun"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.next_run_at ? (
            <span className="font-mono text-xs text-muted-foreground">
              {format(new Date(row.original.next_run_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => {
          const schedule = row.original;
          return (
            <div className="flex items-center justify-end gap-1.5">
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 border-border bg-muted text-xs text-foreground hover:bg-muted"
                disabled={updateMutation.isPending}
                onClick={() =>
                  updateMutation.mutate({
                    scheduleId: schedule.schedule_id,
                    body: { enabled: !schedule.enabled },
                  })
                }
              >
                {schedule.enabled ? t("common.disable") : t("common.enable")}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 w-7 border-border bg-muted p-0 text-foreground hover:bg-muted"
                onClick={() => openEdit(schedule)}
                aria-label={t("scanCopy.editAction")}
              >
                <Pencil className="h-3.5 w-3.5" />
              </Button>
              {isAdmin ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-7 w-7 border-rose-300 dark:border-rose-900/50 bg-muted p-0 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:bg-rose-950"
                  onClick={() => setDeleteTarget(schedule)}
                  aria-label={t("scanCopy.deleteAction")}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              ) : null}
            </div>
          );
        },
      },
    ],
    [isAdmin, t, updateMutation],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-border bg-card p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">
          {t("page.schedules.title")}
        </h1>
        <p className="text-xs text-muted-foreground">{t("page.schedules.denied")}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 shadow-md">
            <Timer className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              {t("page.schedules.title")}
            </h1>
            <p className="text-xs text-muted-foreground">
              {t("page.schedules.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>

        <Dialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) {
              setEditing(null);
              setForm(EMPTY_FORM);
            }
          }}
        >
          <DialogTrigger asChild>
            <Button className="gap-2" onClick={openCreate}>
              <Plus className="h-4 w-4" />
              {t("scanCopy.create")}
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border text-foreground max-w-2xl max-h-[90dvh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-foreground">
                {editing ? t("scanCopy.edit") : t("scanCopy.create")}
              </DialogTitle>
              <DialogDescription className="text-xs text-muted-foreground">
                {t("prose.recurringScansRunThroughThe")}
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={onSubmit} className="space-y-5 py-2">
              <FieldGrid cols={2}>
                <Field
                  label={t("scanCopy.name")}
                  htmlFor="schedule-name"
                  reserveHint={false}
                  className="sm:col-span-2"
                >
                  <Input
                    id="schedule-name"
                    value={form.name}
                    onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                    placeholder={t("scanCopy.namePlaceholder")}
                  />
                </Field>
                <Field label={t("ui.cadence")} htmlFor="schedule-cadence" reserveHint={false}>
                  <Select
                    value={form.cadenceKind}
                    onValueChange={(value) =>
                      setForm((f) => ({ ...f, cadenceKind: value as CadenceKind }))
                    }
                  >
                    <SelectTrigger id="schedule-cadence">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="cron">{t("ui.cronExpression2")}</SelectItem>
                      <SelectItem value="interval">{t("ui.fixedInterval")}</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                {form.cadenceKind === "cron" ? (
                  <Field label={t("ui.cronExpression")} htmlFor="schedule-cron" reserveHint={false}>
                    <Input
                      id="schedule-cron"
                      value={form.cron}
                      onChange={(e) => setForm((f) => ({ ...f, cron: e.target.value }))}
                      placeholder="0 * * * *"
                      className="font-mono"
                    />
                  </Field>
                ) : (
                  <Field
                    label={t("ui.intervalSeconds")}
                    htmlFor="schedule-interval"
                    reserveHint={false}
                  >
                    <Input
                      id="schedule-interval"
                      type="number"
                      min={60}
                      value={form.intervalSeconds}
                      onChange={(e) => setForm((f) => ({ ...f, intervalSeconds: e.target.value }))}
                      className="font-mono tabular-nums"
                    />
                  </Field>
                )}
                <Field
                  label={t("surface.filterLabel")}
                  htmlFor="schedule-surface"
                  reserveHint={false}
                  className="sm:col-span-2"
                >
                  <Select
                    value={form.surface || "__auto__"}
                    onValueChange={(value) =>
                      setForm((f) => ({
                        ...f,
                        surface: value === "__auto__" ? "" : (value as ScanSurface),
                      }))
                    }
                  >
                    <SelectTrigger id="schedule-surface">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="__auto__">{t("schedules.surfaceAuto")}</SelectItem>
                      <SelectItem value="external">
                        {t("surface.external")} — {t("surface.hint.external")}
                      </SelectItem>
                      <SelectItem value="internal">
                        {t("surface.internal")} — {t("surface.hint.internal")}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label={t("ui.scanIntent")} htmlFor="schedule-intent" reserveHint={false}>
                  <Select
                    value={form.intent || "__none__"}
                    onValueChange={(value) =>
                      setForm((f) => ({
                        ...f,
                        intent:
                          value === "__none__"
                            ? ""
                            : (value as NonNullable<CreateScheduleBody["intent"]>),
                      }))
                    }
                  >
                    <SelectTrigger id="schedule-intent">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="inventory">{t("launcher.intent.inventory")}</SelectItem>
                      <SelectItem value="vuln">{t("launcher.intent.vuln")}</SelectItem>
                      <SelectItem value="full">{t("launcher.intent.full")}</SelectItem>
                      <SelectItem value="delta">{t("launcher.intent.delta")}</SelectItem>
                      <SelectItem value="__none__">{t("launcher.intent.legacy")}</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
                <Field label={t("ui.speedProfile")} htmlFor="schedule-mode" reserveHint={false}>
                  <Select
                    value={form.mode}
                    onValueChange={(value) =>
                      setForm((f) => ({ ...f, mode: value as CreateScheduleBody["mode"] }))
                    }
                  >
                    <SelectTrigger id="schedule-mode">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="safe">{t("launcher.mode.safe")}</SelectItem>
                      <SelectItem value="balanced">{t("launcher.mode.balanced")}</SelectItem>
                      <SelectItem value="fast">{t("launcher.mode.fast")}</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </FieldGrid>

              <div className="space-y-2">
                <FieldGrid cols={3} className="gap-y-2">
                  <CheckboxOption
                    label={t("scanCopy.deltaDiscovery")}
                    checked={form.intent === "delta" ? true : form.delta}
                    disabled={form.intent === "delta"}
                    onCheckedChange={(checked) => setForm((f) => ({ ...f, delta: checked }))}
                  />
                  {!form.intent ? (
                    <CheckboxOption
                      label={t("prose.portsOnlyNoServiceoscveProbe")}
                      checked={form.skipNse}
                      onCheckedChange={(checked) => setForm((f) => ({ ...f, skipNse: checked }))}
                    />
                  ) : null}
                  <CheckboxOption
                    label={t("scanCopy.notify")}
                    checked={form.notify}
                    onCheckedChange={(checked) => setForm((f) => ({ ...f, notify: checked }))}
                  />
                </FieldGrid>
                {serviceBackend ? (
                  <p className="text-xs text-muted-foreground">{t("scanCopy.backendHint")}</p>
                ) : null}
              </div>

              <FieldGrid cols={2}>
                <Field
                  label={t("ui.targetCidrRangesOptional")}
                  htmlFor="schedule-ranges"
                  reserveHint={false}
                >
                  <Textarea
                    id="schedule-ranges"
                    className="min-h-[72px] font-mono text-xs"
                    value={form.ranges}
                    onChange={(e) => setForm((f) => ({ ...f, ranges: e.target.value }))}
                    placeholder={"10.0.0.0/24\n192.168.1.0/28"}
                    spellCheck={false}
                  />
                </Field>
                <Field
                  label={t("ui.targetDomainsOptional")}
                  htmlFor="schedule-domains"
                  reserveHint={false}
                >
                  <Textarea
                    id="schedule-domains"
                    className="min-h-[72px] font-mono text-xs"
                    value={form.domains}
                    onChange={(e) => setForm((f) => ({ ...f, domains: e.target.value }))}
                    placeholder={"api.example.com\nportal.internal"}
                    spellCheck={false}
                  />
                </Field>
                <Field
                  label={t("scanCopy.tcp")}
                  htmlFor="schedule-ports"
                  optional={t("launcher.optional")}
                  reserveHint={false}
                >
                  <Input
                    id="schedule-ports"
                    className="font-mono text-xs"
                    value={form.ports}
                    onChange={(e) => setForm((f) => ({ ...f, ports: e.target.value }))}
                    placeholder="22,80,443"
                    spellCheck={false}
                  />
                </Field>
                <Field
                  label={t("scanCopy.udp")}
                  htmlFor="schedule-ports-udp"
                  optional={t("launcher.optional")}
                  reserveHint={false}
                >
                  <Input
                    id="schedule-ports-udp"
                    className="font-mono text-xs"
                    value={form.portsUdp}
                    onChange={(e) => setForm((f) => ({ ...f, portsUdp: e.target.value }))}
                    placeholder="53,123,161"
                    spellCheck={false}
                  />
                </Field>
              </FieldGrid>

              <ScanTechnicalDetails
                intent={form.intent}
                mode={form.mode}
                backend={serviceBackend}
                cron={form.cadenceKind === "cron" ? form.cron : null}
                interval={form.cadenceKind === "interval" ? Number(form.intervalSeconds) : null}
              />
              <DialogFooter>
                <Button
                  type="submit"
                  disabled={
                    !form.name.trim() ||
                    (form.cadenceKind === "cron"
                      ? !form.cron.trim()
                      : !Number(form.intervalSeconds)) ||
                    createMutation.isPending ||
                    updateMutation.isPending
                  }
                >
                  {editing
                    ? updateMutation.isPending
                      ? t("scanCopy.saving")
                      : t("scanCopy.save")
                    : createMutation.isPending
                      ? t("scanCopy.creating")
                      : t("scanCopy.create")}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {/* Above the schedules, not beside them: "why did nothing run last
          night" is a question about the calendar, and the answer has to be on
          the page where the missing run is (#352). */}
      <MaintenancePanel canRead={canOperate} canAdmin={isAdmin} />

      <DataTable
        columns={columns}
        data={schedules}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("search.schedules")}
        meta={t("meta.schedules", { count: scheduleTotal })}
        loadingMessage={t("loading.schedules")}
        emptyMessage={t("empty.schedules")}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: scheduleTotal,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: [
            "created_at",
            "name",
            "next_run_at",
            "last_run_at",
            "enabled",
            "tenant_id",
          ],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />

      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(next) => !next && setDeleteTarget(null)}
      >
        <AlertDialogContent className="bg-card border-border text-foreground">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-foreground">
              {t("scanCopy.deleteConfirm", { name: deleteTarget?.name || "" })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-muted-foreground text-xs">
              {t("prose.thisStopsFutureAutomaticRuns")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">
              {t("ui.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-foreground hover:bg-rose-500"
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget.schedule_id);
                setDeleteTarget(null);
              }}
            >
              {t("scanCopy.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
