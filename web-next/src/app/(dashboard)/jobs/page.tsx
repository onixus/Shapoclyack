"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Play, Terminal, ArrowUpRight, Cpu, Timer, TriangleAlert } from "lucide-react";
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
import { useWordlists } from "@/hooks/use-wordlists";
import { usePagination } from "@/hooks/use-pagination";
import { useSystemStatus } from "@/hooks/use-system";
import { type JobInfo, type ScanIntent } from "@/lib/api";
import { JOB_STATUS } from "@/lib/config/statuses";
import { runDetailHref } from "@/lib/run-data";
import { useAuthStore } from "@/lib/auth-store";

const NO_INTENT = "__none__";

export default function JobsPage() {
  const t = useT();
  const { canOperate } = useAuthStore();
  const [mode, setMode] = useState("balanced");
  const [intent, setIntent] = useState<ScanIntent | "">("inventory");
  const [delta, setDelta] = useState(false);
  const [skipNse, setSkipNse] = useState(false);
  const [notify, setNotify] = useState(false);
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("");
  const [portsUdp, setPortsUdp] = useState("");
  const [wordlistId, setWordlistId] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const NO_WORDLIST = "__none__";

  // Server-side paging/search/sort (ROADMAP P3.3): the job list is unbounded.
  const pagination = usePagination({ sort: "started_at", order: "desc" });
  const { data, isLoading, error, isFetching } = useJobs(canOperate, pagination.params);
  const jobs = data?.items ?? [];
  const mutation = useStartScan();
  const { data: systemStatus } = useSystemStatus();
  const serviceBackend = systemStatus?.scan_config.service_backend;
  const { data: wordlists } = useWordlists(canOperate);

  const columns = useMemo<ColumnDef<JobInfo>[]>(
    () => [
      {
        accessorKey: "job_id",
        header: t("col.jobId"),
        cell: ({ getValue }) => <code className="font-mono text-xs text-sky-400 font-semibold">{String(getValue())}</code>,
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1.5">
            <StatusBadge
              value={row.original.status}
              map={JOB_STATUS}
              showPulse={row.original.status === "running" || row.original.status === "claimed"}
            />
            {/* A succeeded scan whose asset upsert failed looks entirely clean
                here; without this the empty asset list has no explanation. */}
            {row.original.asset_upsert_error ? (
              <span
                role="img"
                aria-label="Assets were not updated for this job"
                title={`Assets were not updated: ${row.original.asset_upsert_error}`}
              >
                <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-amber-400" />
              </span>
            ) : null}
          </span>
        ),
      },
      {
        accessorKey: "mode",
        header: t("col.profile"),
        cell: ({ row }) => {
          const intentVal = row.original.scan_options?.intent;
          return (
            <span className="flex flex-col gap-0.5">
              <span className="uppercase text-[11px] font-bold tracking-wider text-slate-300">
                {row.original.mode}
              </span>
              {typeof intentVal === "string" && intentVal ? (
                <span className="text-[10px] font-semibold uppercase tracking-wide text-sky-400/90">
                  {intentVal}
                </span>
              ) : null}
            </span>
          );
        },
      },
      {
        accessorKey: "run_id",
        header: t("col.run"),
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
        header: t("col.execution"),
        cell: ({ getValue }) => (
          <span className="inline-flex items-center gap-1 text-xs text-slate-300 font-medium">
            <Cpu className="h-3 w-3 text-slate-400" />
            {String(getValue() || "local")}
          </span>
        ),
      },
      {
        accessorKey: "started_at",
        header: t("col.started"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at
            ? <span className="text-xs text-slate-400 font-mono">{format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm:ss")}</span>
            : "—",
      },
      {
        accessorKey: "requested_by",
        header: t("col.operator"),
        cell: ({ getValue }) => <span className="text-xs font-semibold text-slate-200">{String(getValue())}</span>,
      },
    ],
    [t],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-slate-800 bg-slate-900/80 p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">{t("page.jobs.orchestration")}</h1>
        <p className="text-xs text-slate-400">
          {t("page.jobs.denied")}
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
      intent: intent || null,
      // When intent is set, server owns skip_nse/nuclei; delta still applies for inventory/vuln/full.
      delta,
      skip_nse: intent ? false : skipNse,
      notify,
      ranges: ranges.trim() || undefined,
      domains: domains.trim() || undefined,
      ports: ports.trim() || undefined,
      ports_udp: portsUdp.trim() || undefined,
      wordlist_id: wordlistId || undefined,
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Terminal className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.jobs.title")}</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {t("page.jobs.subtitle")}
            {isFetching ? t("common.refreshing") : ""}
          </p>
        </div>
        <Link
          href="/schedules"
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-800 hover:text-slate-100"
        >
          <Timer className="h-3.5 w-3.5" />
          {t("common.manageSchedules")}
        </Link>
      </div>

      <form onSubmit={onSubmit} className="space-y-5 rounded-xl border border-slate-800/80 bg-slate-900/80 p-6 shadow-xl backdrop-blur">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">Launch New Recon Job</h3>
          <span className="text-xs text-sky-400 font-semibold">Step 1 of 2: Configure Targets</span>
        </div>

        <div className="grid gap-5 md:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="scan-intent" className="text-slate-300 font-semibold">
              Scan Intent
            </Label>
            <Select
              value={intent || NO_INTENT}
              onValueChange={(v) => setIntent(v === NO_INTENT ? "" : (v as ScanIntent))}
            >
              <SelectTrigger id="scan-intent" className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value="inventory">inventory — ports only, fast recheck</SelectItem>
                <SelectItem value="vuln">vuln — probe + nuclei critical/high</SelectItem>
                <SelectItem value="full">full — assessment-grade pipeline</SelectItem>
                <SelectItem value="delta">delta — full + incremental discovery</SelectItem>
                <SelectItem value={NO_INTENT}>legacy — manual flags only</SelectItem>
              </SelectContent>
            </Select>
            <p className="text-[11px] text-slate-500">
              Intent chooses stages (what to run). Profile mode chooses rate (how hard).
            </p>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="scan-mode" className="text-slate-300 font-semibold">Speed Profile</Label>
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

          <div className="flex flex-wrap items-end gap-5 text-xs text-slate-300 md:col-span-2">
            <Label className="flex items-center gap-2 font-semibold cursor-pointer">
              <Checkbox
                checked={intent === "delta" ? true : delta}
                disabled={intent === "delta"}
                onCheckedChange={(checked) => setDelta(checked === true)}
                className="border-slate-700"
              />
              Delta discovery (incremental)
            </Label>
            {!intent ? (
              <Label className="flex items-center gap-2 font-semibold cursor-pointer">
                <Checkbox
                  checked={skipNse}
                  onCheckedChange={(checked) => setSkipNse(checked === true)}
                  className="border-slate-700"
                />
                Ports only (no service/OS/CVE probe)
              </Label>
            ) : null}
            <Label className="flex items-center gap-2 font-semibold cursor-pointer">
              <Checkbox
                checked={notify}
                onCheckedChange={(checked) => setNotify(checked === true)}
                className="border-slate-700"
              />
              Alert Notifications
            </Label>
            {serviceBackend ? (
              <span className="inline-flex items-center gap-1.5 rounded-md border border-slate-800 bg-slate-950/60 px-2 py-1 text-[11px] font-mono text-slate-400">
                Full probe uses <span className="text-sky-400">{serviceBackend}</span> backend
              </span>
            ) : null}
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

          <div className="grid gap-2 md:col-span-2">
            <Label htmlFor="scan-wordlist" className="text-slate-300 font-semibold">
              Brute-force Wordlist (Optional)
            </Label>
            <Select
              value={wordlistId || NO_WORDLIST}
              onValueChange={(v) => setWordlistId(v === NO_WORDLIST ? "" : v)}
            >
              <SelectTrigger id="scan-wordlist" className="bg-slate-950 border-slate-800 text-slate-200">
                <SelectValue placeholder="None — no dictionary brute force" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={NO_WORDLIST}>None — no dictionary brute force</SelectItem>
                {(wordlists ?? []).map((wl) => (
                  <SelectItem key={wl.wordlist_id} value={wl.wordlist_id}>
                    {wl.name} · {wl.kind} · {wl.line_count.toLocaleString()} entries
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-slate-500">
              Selecting a list enables dictionary brute force for this scan (subdomain or bucket
              discovery). Manage lists on the{" "}
              <Link href="/wordlists" className="text-sky-400 hover:underline">
                Wordlists
              </Link>{" "}
              page. Local execution only — rejected in agent mode.
            </p>
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
            <AlertDialogTitle className="text-slate-100">
              Start {intent ? `${intent} / ${mode}` : mode.toUpperCase()} scan job?
            </AlertDialogTitle>
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
        data={jobs}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder={t("search.jobs")}
        loadingMessage="Retrieving scan jobs stream…"
        emptyMessage="No scan jobs recorded."
        meta={`${data?.total ?? 0} jobs`}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: data?.total ?? 0,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["started_at", "finished_at", "status", "job_id", "mode", "tenant_id"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}

