"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Play, Terminal, ArrowUpRight, Cpu } from "lucide-react";
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
        header: "Job ID",
        cell: ({ getValue }) => <code className="font-mono text-xs text-sky-400 font-semibold">{String(getValue())}</code>,
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge value={row.original.status} map={JOB_STATUS} showPulse={row.original.status === "running"} />,
      },
      {
        accessorKey: "mode",
        header: "Profile Mode",
        cell: ({ getValue }) => <span className="uppercase text-[11px] font-bold tracking-wider text-slate-300">{String(getValue())}</span>,
      },
      {
        accessorKey: "run_id",
        header: "Associated Run",
        enableSorting: false,
        cell: ({ row }) => {
          const runId = row.original.run_id;
          if (!runId) return <span className="text-slate-500">—</span>;
          return (
            <Link
              href={runDetailHref(runId)}
              className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-sky-400 hover:text-sky-300 hover:underline"
              title="Open run report"
            >
              <span>{runId}</span>
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          );
        },
      },
      {
        accessorKey: "execution",
        header: "Execution",
        cell: ({ getValue }) => (
          <span className="inline-flex items-center gap-1 text-xs text-slate-300 font-medium">
            <Cpu className="h-3 w-3 text-slate-400" />
            {String(getValue() || "local")}
          </span>
        ),
      },
      {
        accessorKey: "started_at",
        header: "Started At",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at
            ? <span className="text-xs text-slate-400 font-mono">{format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm:ss")}</span>
            : "—",
      },
      {
        accessorKey: "requested_by",
        header: "Operator",
        cell: ({ getValue }) => <span className="text-xs font-semibold text-slate-200">{String(getValue())}</span>,
      },
    ],
    [],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Scan Job Orchestration</h1>
        <p className="text-xs text-slate-400">
          Operator or admin role privileges required to launch and monitor scan jobs.
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
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Terminal className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Scan Jobs Orchestrator</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Control center for launching network discovery and vulnerability scan jobs.
            {isFetching ? " · Refreshing job queue…" : ""}
          </p>
        </div>
      </div>

      <form onSubmit={onSubmit} className="space-y-5 rounded-xl border border-slate-800/80 bg-slate-900/80 p-6 shadow-xl backdrop-blur">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">Launch New Recon Job</h3>
          <span className="text-xs text-sky-400 font-semibold">Step 1 of 2: Configure Targets</span>
        </div>

        <div className="grid gap-5 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="scan-mode" className="text-slate-300 font-semibold">Scan Profile Mode</Label>
            <Select value={mode} onValueChange={setMode}>
              <SelectTrigger id="scan-mode" className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value="safe">safe (500 pps · low load)</SelectItem>
                <SelectItem value="balanced">balanced (2,000 pps · standard)</SelectItem>
                <SelectItem value="fast">fast (5,000 pps · aggressive)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex flex-wrap items-end gap-5 text-xs text-slate-300">
            <Label className="flex items-center gap-2 font-semibold cursor-pointer">
              <Checkbox checked={delta} onCheckedChange={(checked) => setDelta(checked === true)} className="border-slate-700" />
              Delta Mode (Incremental)
            </Label>
            <Label className="flex items-center gap-2 font-semibold cursor-pointer">
              <Checkbox
                checked={skipNse}
                onCheckedChange={(checked) => setSkipNse(checked === true)}
                className="border-slate-700"
              />
              Skip NSE Scripts
            </Label>
            <Label className="flex items-center gap-2 font-semibold cursor-pointer">
              <Checkbox
                checked={notify}
                onCheckedChange={(checked) => setNotify(checked === true)}
                className="border-slate-700"
              />
              Alert Notifications
            </Label>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="scan-ranges" className="text-slate-300 font-semibold">Target CIDR Ranges (Optional)</Label>
            <Textarea
              id="scan-ranges"
              className="min-h-[96px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
              value={ranges}
              onChange={(e) => setRanges(e.target.value)}
              placeholder={"10.0.0.0/24\n192.168.1.0/28"}
              spellCheck={false}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="scan-domains" className="text-slate-300 font-semibold">Target Domains / FQDNs (Optional)</Label>
            <Textarea
              id="scan-domains"
              className="min-h-[96px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder={"api.example.com\nportal.internal"}
              spellCheck={false}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="scan-ports" className="text-slate-300 font-semibold">TCP Ports Override (Optional)</Label>
            <Textarea
              id="scan-ports"
              className="min-h-[72px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder={"22,80,443\n8000-8080"}
              spellCheck={false}
            />
          </div>

          <div className="grid gap-2">
            <Label htmlFor="scan-ports-udp" className="text-slate-300 font-semibold">UDP Ports Override (Optional)</Label>
            <Textarea
              id="scan-ports-udp"
              className="min-h-[72px] bg-slate-950 border-slate-800 font-mono text-xs text-slate-100 placeholder:text-slate-600"
              value={portsUdp}
              onChange={(e) => setPortsUdp(e.target.value)}
              placeholder={"53,123,161"}
              spellCheck={false}
            />
          </div>
        </div>

        <div className="flex items-center justify-between pt-3 border-t border-slate-800">
          <p className="text-xs text-slate-400">
            Empty fields will automatically use server default targets from inputs configuration.
          </p>
          <Button type="submit" disabled={mutation.isPending} className="gap-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold">
            <Play className="h-3.5 w-3.5 fill-current" />
            {mutation.isPending ? "Starting Scan Job…" : "Start Scan Job"}
          </Button>
        </div>
      </form>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent className="bg-slate-900 border-slate-800 text-slate-100">
          <AlertDialogHeader>
            <AlertDialogTitle className="text-slate-100">Start {mode.toUpperCase()} scan job?</AlertDialogTitle>
            <AlertDialogDescription className="text-slate-400 text-xs">
              {noTargets
                ? "No custom targets specified — scanner will proceed using configured server target inputs."
                : "Reconnaissance execution will start immediately on specified target ranges."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800">Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={startConfirmed} className="bg-sky-600 text-white hover:bg-sky-500">Confirm & Launch</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Search jobs by ID or operator…"
        loadingMessage="Retrieving scan jobs stream…"
        emptyMessage="No scan jobs recorded."
      />
    </div>
  );
}

