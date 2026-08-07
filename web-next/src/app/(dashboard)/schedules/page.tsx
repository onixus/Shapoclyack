"use client";

import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Pencil, Plus, Timer, Trash2 } from "lucide-react";
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
import { Checkbox } from "@/components/ui/checkbox";
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
import { Label } from "@/components/ui/label";
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

type CadenceKind = "cron" | "interval";

const EMPTY_FORM = {
  name: "",
  cadenceKind: "cron" as CadenceKind,
  cron: "0 * * * *",
  intervalSeconds: "3600",
  mode: "balanced" as CreateScheduleBody["mode"],
  delta: true,
  skipNse: false,
  notify: false,
  ranges: "",
  domains: "",
  ports: "",
  portsUdp: "",
};

function targetsSummary(schedule: ScanSchedule): string {
  const parts: string[] = [];
  if (schedule.targets.ranges) parts.push(schedule.targets.ranges.split(/\s+/).filter(Boolean).length + " range(s)");
  if (schedule.targets.domains) parts.push(schedule.targets.domains.split(/\s+/).filter(Boolean).length + " domain(s)");
  if (!parts.length) return "server defaults";
  return parts.join(", ");
}

function cadenceSummary(schedule: ScanSchedule): string {
  if (schedule.cron) return `cron: ${schedule.cron}`;
  if (schedule.interval_seconds) return `every ${schedule.interval_seconds}s`;
  return "—";
}

export default function SchedulesPage() {
  const { user, canOperate } = useAuthStore();
  const isAdmin = user?.role === "admin";

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
      interval_seconds: form.cadenceKind === "interval" ? Number(form.intervalSeconds) || null : null,
      mode: form.mode,
      delta: form.delta,
      skip_nse: form.skipNse,
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
        header: "Schedule",
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-slate-100">{row.original.name}</p>
            <p className="font-mono text-[10px] text-slate-400">{row.original.schedule_id}</p>
          </div>
        ),
      },
      {
        id: "enabled",
        header: "Status",
        accessorFn: (schedule) => (schedule.enabled ? "enabled" : "disabled"),
        cell: ({ row }) => <StatusBadge value={row.original.enabled ? "enabled" : "disabled"} map={SCHEDULE_ENABLED_STATUS} />,
      },
      {
        id: "cadence",
        header: "Cadence",
        enableSorting: false,
        cell: ({ row }) => <span className="font-mono text-xs text-slate-300">{cadenceSummary(row.original)}</span>,
      },
      {
        id: "targets",
        header: "Targets",
        enableSorting: false,
        cell: ({ row }) => <span className="text-xs text-slate-300">{targetsSummary(row.original)}</span>,
      },
      {
        accessorKey: "last_run_at",
        header: "Last Run",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.last_run_at ? (
            <span className="font-mono text-xs text-slate-400">{format(new Date(row.original.last_run_at), "yyyy-MM-dd HH:mm")}</span>
          ) : (
            <span className="text-slate-500">—</span>
          ),
      },
      {
        accessorKey: "next_run_at",
        header: "Next Run",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.next_run_at ? (
            <span className="font-mono text-xs text-slate-400">{format(new Date(row.original.next_run_at), "yyyy-MM-dd HH:mm")}</span>
          ) : (
            <span className="text-slate-500">—</span>
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
                className="h-7 border-slate-800 bg-slate-950 text-xs text-slate-300 hover:bg-slate-800"
                disabled={updateMutation.isPending}
                onClick={() =>
                  updateMutation.mutate({ scheduleId: schedule.schedule_id, body: { enabled: !schedule.enabled } })
                }
              >
                {schedule.enabled ? "Disable" : "Enable"}
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="h-7 w-7 border-slate-800 bg-slate-950 p-0 text-slate-300 hover:bg-slate-800"
                onClick={() => openEdit(schedule)}
                aria-label="Edit schedule"
              >
                <Pencil className="h-3.5 w-3.5" />
              </Button>
              {isAdmin ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-7 w-7 border-rose-900/50 bg-slate-950 p-0 text-rose-400 hover:bg-rose-950"
                  onClick={() => setDeleteTarget(schedule)}
                  aria-label="Delete schedule"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              ) : null}
            </div>
          );
        },
      },
    ],
    [isAdmin, updateMutation],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Continuous Scan Schedules</h1>
        <p className="text-xs text-slate-400">
          Operator or admin role privileges required to manage scan schedules.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Timer className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Continuous Scan Schedules</h1>
            <p className="text-xs text-slate-400">
              Recurring recon jobs dispatched automatically by cron or interval cadence.
              {isFetching ? " · Refreshing schedules…" : ""}
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
            <Button className="gap-2 bg-sky-600 hover:bg-sky-500 text-white shadow-md" onClick={openCreate}>
              <Plus className="h-4 w-4" />
              Create Schedule
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-slate-900 border-slate-800 text-slate-100 max-w-2xl">
            <DialogHeader>
              <DialogTitle className="text-slate-100">{editing ? "Edit Schedule" : "Create Schedule"}</DialogTitle>
              <DialogDescription className="text-xs text-slate-400">
                Recurring scans run through the existing job dispatcher on the configured cadence.
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={onSubmit} className="space-y-4 py-2">
              <div className="grid gap-2">
                <Label htmlFor="schedule-name" className="text-xs font-semibold text-slate-300">Name</Label>
                <Input
                  id="schedule-name"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="Nightly external sweep"
                  className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
                />
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="grid gap-2">
                  <Label className="text-xs font-semibold text-slate-300">Cadence</Label>
                  <Select
                    value={form.cadenceKind}
                    onValueChange={(value) => setForm((f) => ({ ...f, cadenceKind: value as CadenceKind }))}
                  >
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                      <SelectItem value="cron">Cron expression</SelectItem>
                      <SelectItem value="interval">Fixed interval</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {form.cadenceKind === "cron" ? (
                  <div className="grid gap-2">
                    <Label htmlFor="schedule-cron" className="text-xs font-semibold text-slate-300">Cron Expression</Label>
                    <Input
                      id="schedule-cron"
                      value={form.cron}
                      onChange={(e) => setForm((f) => ({ ...f, cron: e.target.value }))}
                      placeholder="0 * * * *"
                      className="bg-slate-950 border-slate-800 font-mono text-xs text-slate-100"
                    />
                  </div>
                ) : (
                  <div className="grid gap-2">
                    <Label htmlFor="schedule-interval" className="text-xs font-semibold text-slate-300">Interval (seconds)</Label>
                    <Input
                      id="schedule-interval"
                      type="number"
                      min={60}
                      value={form.intervalSeconds}
                      onChange={(e) => setForm((f) => ({ ...f, intervalSeconds: e.target.value }))}
                      className="bg-slate-950 border-slate-800 font-mono text-xs text-slate-100"
                    />
                  </div>
                )}
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="grid gap-2">
                  <Label className="text-xs font-semibold text-slate-300">Scan Profile Mode</Label>
                  <Select value={form.mode} onValueChange={(value) => setForm((f) => ({ ...f, mode: value as CreateScheduleBody["mode"] }))}>
                    <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                      <SelectItem value="safe">safe (500 pps · low load)</SelectItem>
                      <SelectItem value="balanced">balanced (2,000 pps · standard)</SelectItem>
                      <SelectItem value="fast">fast (5,000 pps · aggressive)</SelectItem>
                      <SelectItem value="test">test (smoke test · top 100 ports, short nuclei)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex flex-wrap items-end gap-4 text-xs text-slate-300">
                  <Label className="flex items-center gap-2 font-semibold cursor-pointer">
                    <Checkbox checked={form.delta} onCheckedChange={(c) => setForm((f) => ({ ...f, delta: c === true }))} className="border-slate-700" />
                    Delta Mode
                  </Label>
                  <Label className="flex items-center gap-2 font-semibold cursor-pointer">
                    <Checkbox checked={form.skipNse} onCheckedChange={(c) => setForm((f) => ({ ...f, skipNse: c === true }))} className="border-slate-700" />
                    Ports only (no service/OS/CVE probe)
                  </Label>
                  <Label className="flex items-center gap-2 font-semibold cursor-pointer">
                    <Checkbox checked={form.notify} onCheckedChange={(c) => setForm((f) => ({ ...f, notify: c === true }))} className="border-slate-700" />
                    Notify
                  </Label>
                  {serviceBackend ? (
                    <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/60 px-2 py-1 text-[11px] font-mono text-slate-400">
                      Full probe uses <span className="text-sky-400">{serviceBackend}</span> backend
                    </span>
                  ) : null}
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="grid gap-2">
                  <Label htmlFor="schedule-ranges" className="text-xs font-semibold text-slate-300">Target CIDR Ranges (Optional)</Label>
                  <Textarea
                    id="schedule-ranges"
                    className="min-h-[72px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
                    value={form.ranges}
                    onChange={(e) => setForm((f) => ({ ...f, ranges: e.target.value }))}
                    placeholder={"10.0.0.0/24\n192.168.1.0/28"}
                    spellCheck={false}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-domains" className="text-xs font-semibold text-slate-300">Target Domains (Optional)</Label>
                  <Textarea
                    id="schedule-domains"
                    className="min-h-[72px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
                    value={form.domains}
                    onChange={(e) => setForm((f) => ({ ...f, domains: e.target.value }))}
                    placeholder={"api.example.com\nportal.internal"}
                    spellCheck={false}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-ports" className="text-xs font-semibold text-slate-300">TCP Ports Override (Optional)</Label>
                  <Textarea
                    id="schedule-ports"
                    className="min-h-[60px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
                    value={form.ports}
                    onChange={(e) => setForm((f) => ({ ...f, ports: e.target.value }))}
                    placeholder={"22,80,443"}
                    spellCheck={false}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="schedule-ports-udp" className="text-xs font-semibold text-slate-300">UDP Ports Override (Optional)</Label>
                  <Textarea
                    id="schedule-ports-udp"
                    className="min-h-[60px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
                    value={form.portsUdp}
                    onChange={(e) => setForm((f) => ({ ...f, portsUdp: e.target.value }))}
                    placeholder={"53,123,161"}
                    spellCheck={false}
                  />
                </div>
              </div>

              <DialogFooter>
                <Button
                  type="submit"
                  className="bg-sky-600 hover:bg-sky-500 text-white"
                  disabled={
                    !form.name.trim() ||
                    (form.cadenceKind === "cron" ? !form.cron.trim() : !Number(form.intervalSeconds)) ||
                    createMutation.isPending ||
                    updateMutation.isPending
                  }
                >
                  {editing
                    ? updateMutation.isPending
                      ? "Saving…"
                      : "Save Changes"
                    : createMutation.isPending
                      ? "Creating…"
                      : "Create Schedule"}
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      <DataTable
        columns={columns}
        data={schedules}
        isLoading={isLoading}
        error={error}
        searchPlaceholder="Filter schedules by name…"
        meta={`${scheduleTotal} schedule${scheduleTotal === 1 ? "" : "s"}`}
        loadingMessage="Retrieving scan schedules…"
        emptyMessage="No continuous schedules configured yet."
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: scheduleTotal,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["created_at", "name", "next_run_at", "last_run_at", "enabled", "tenant_id"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />

      <AlertDialog open={deleteTarget !== null} onOpenChange={(next) => !next && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-slate-900 border-slate-800 text-slate-100">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-slate-100">Delete schedule &quot;{deleteTarget?.name}&quot;?</AlertDialogTitle>
            <AlertDialogDescription className="text-slate-400 text-xs">
              This stops future automatic runs. Past runs and reports are unaffected. This cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800">Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-white hover:bg-rose-500"
              onClick={() => {
                if (deleteTarget) deleteMutation.mutate(deleteTarget.schedule_id);
                setDeleteTarget(null);
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
