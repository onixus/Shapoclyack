"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
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
import { useJobs, useStartScan } from "@/hooks/use-jobs";
import { type JobInfo } from "@/lib/api";
import { JOB_STATUS } from "@/lib/config/statuses";
import { runDetailHref } from "@/lib/run-data";
import { useAuthStore } from "@/lib/auth-store";

export default function JobsPage() {
  const { canOperate } = useAuthStore();
  const [mode, setMode] = useState("balanced");
  const [delta, setDelta] = useState(false);
  const [skipNse, setSkipNse] = useState(false);
  const [notify, setNotify] = useState(false);
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("");
  const [portsUdp, setPortsUdp] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);

  const { data = [], isLoading, error, isFetching } = useJobs(canOperate);
  const mutation = useStartScan();

  const columns = useMemo<ColumnDef<JobInfo>[]>(
    () => [
      {
        accessorKey: "job_id",
        header: "Job",
        cell: ({ getValue }) => <code className="text-xs">{String(getValue())}</code>,
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge value={row.original.status} map={JOB_STATUS} />,
      },
      {
        accessorKey: "mode",
        header: "Mode",
      },
      {
        accessorKey: "run_id",
        header: "Run",
        enableSorting: false,
        cell: ({ row }) => {
          const runId = row.original.run_id;
          if (!runId) return "—";
          return (
            <Link
              href={runDetailHref(runId)}
              className="font-medium text-sky-700 underline-offset-2 hover:underline"
              title="Open run report"
            >
              <code className="text-xs">{runId}</code>
            </Link>
          );
        },
      },
      {
        accessorKey: "execution",
        header: "Exec",
        cell: ({ getValue }) => String(getValue() || "local"),
      },
      {
        accessorKey: "started_at",
        header: "Started",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at
            ? format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm:ss")
            : "—",
      },
      {
        accessorKey: "requested_by",
        header: "By",
      },
    ],
    [],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Jobs</h1>
        <p className="text-sm text-muted-foreground">
          Operator or admin role required to view and start scan jobs.
        </p>
      </div>
    );
  }

  const noTargets = !ranges.trim() && !domains.trim();

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    setConfirmOpen(true);
  }

  function startConfirmed() {
    mutation.mutate({
      mode,
      delta,
      skip_nse: skipNse,
      notify,
      ranges: ranges.trim() || undefined,
      domains: domains.trim() || undefined,
      ports: ports.trim() || undefined,
      ports_udp: portsUdp.trim() || undefined,
    });
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Jobs</h1>
        <p className="text-sm text-muted-foreground">
          Live orchestration from <code className="text-xs">GET/POST /api/jobs</code>
          {isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      <form onSubmit={onSubmit} className="space-y-4 rounded-lg border bg-white p-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="scan-mode">Mode</Label>
            <Select value={mode} onValueChange={setMode}>
              <SelectTrigger id="scan-mode">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="safe">safe</SelectItem>
                <SelectItem value="balanced">balanced</SelectItem>
                <SelectItem value="fast">fast</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="flex flex-wrap items-end gap-4 text-sm">
            <Label className="flex items-center gap-2 font-normal">
              <Checkbox checked={delta} onCheckedChange={(checked) => setDelta(checked === true)} />
              Delta
            </Label>
            <Label className="flex items-center gap-2 font-normal">
              <Checkbox
                checked={skipNse}
                onCheckedChange={(checked) => setSkipNse(checked === true)}
              />
              Skip NSE
            </Label>
            <Label className="flex items-center gap-2 font-normal">
              <Checkbox
                checked={notify}
                onCheckedChange={(checked) => setNotify(checked === true)}
              />
              Notify
            </Label>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="scan-ranges">Ranges (optional)</Label>
            <Textarea
              id="scan-ranges"
              className="min-h-[96px]"
              value={ranges}
              onChange={(e) => setRanges(e.target.value)}
              placeholder={"10.0.0.0/24"}
              spellCheck={false}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="scan-domains">Domains (optional)</Label>
            <Textarea
              id="scan-domains"
              className="min-h-[96px]"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder={"example.com"}
              spellCheck={false}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="scan-ports">TCP ports (optional)</Label>
            <Textarea
              id="scan-ports"
              className="min-h-[72px]"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder={"22,80,443\n8000-8010"}
              spellCheck={false}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="scan-ports-udp">UDP ports (optional)</Label>
            <Textarea
              id="scan-ports-udp"
              className="min-h-[72px]"
              value={portsUdp}
              onChange={(e) => setPortsUdp(e.target.value)}
              placeholder={"53,123,161\n500-510"}
              spellCheck={false}
            />
          </div>
        </div>
        <p className="text-xs text-muted-foreground">
          Empty fields use server default input files. UDP list applies when{" "}
          <code>ports.protocol</code> is <code>udp</code> or <code>tcp_udp</code>.
        </p>
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Starting…" : "Start scan"}
        </Button>
      </form>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Start a {mode} scan?</AlertDialogTitle>
            <AlertDialogDescription>
              {noTargets
                ? "No targets specified — the server default input files will be scanned. Active scanning will begin immediately after confirmation."
                : "Active scanning of the specified targets will begin immediately after confirmation."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={startConfirmed}>Start scan</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Filter jobs…"
        loadingMessage="Loading jobs…"
        emptyMessage="No jobs yet."
      />
    </div>
  );
}
