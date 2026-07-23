"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Download, FileText } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/data-table";
import { useRuns } from "@/hooks/use-runs";
import { downloadArtifact, type RunSummary } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";

export default function ReportsPage() {
  const { data = [], isLoading, error, isFetching } = useRuns();
  const [busyRun, setBusyRun] = useState<string | null>(null);

  async function downloadPdf(runId: string) {
    setBusyRun(runId);
    try {
      await downloadArtifact(runId, "summary.pdf");
    } catch {
      toast.error("No PDF report available for this run.");
    } finally {
      setBusyRun(null);
    }
  }

  const columns = useMemo<ColumnDef<RunSummary>[]>(
    () => [
      {
        accessorKey: "run_id",
        header: "Run ID",
        cell: ({ row }) => (
          <Link
            href={`${runDetailHref(row.original.run_id)}&tab=reports`}
            className="font-mono text-xs text-sky-400 hover:text-sky-300 underline-offset-2 hover:underline"
          >
            {row.original.run_id}
          </Link>
        ),
      },
      {
        accessorKey: "profile",
        header: "Profile",
        cell: ({ getValue }) => <Badge variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[11px]">{String(getValue() || "—")}</Badge>,
      },
      {
        accessorKey: "started_at",
        header: "Execution Date",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at ? (
            <span className="font-mono text-xs text-slate-300">
              {format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            "—"
          ),
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: "Vulnerabilities",
        cell: ({ getValue }) => {
          const val = Number(getValue() ?? 0);
          return (
            <span className={`font-mono text-xs font-bold ${val > 0 ? "text-rose-400" : "text-slate-400"}`}>
              {val.toLocaleString()}
            </span>
          );
        },
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex justify-end gap-2">
            {row.original.has_summary ? (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-sky-500/30 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20 text-xs font-semibold"
                onClick={() => downloadPdf(row.original.run_id)}
                disabled={busyRun === row.original.run_id}
              >
                <Download className="h-3.5 w-3.5" />
                {busyRun === row.original.run_id ? "Downloading…" : "Download PDF"}
              </Button>
            ) : (
              <Badge variant="outline" className="border-slate-800 text-slate-500 font-normal">no summary</Badge>
            )}
            <Button asChild variant="ghost" size="sm" className="text-slate-400 hover:text-slate-100 hover:bg-slate-800 text-xs">
              <Link href={`${runDetailHref(row.original.run_id)}&tab=reports`}>Artifacts</Link>
            </Button>
          </div>
        ),
      },
    ],
    [busyRun],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <FileText className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Executive Security Reports</h1>
            <p className="text-xs text-slate-400">
              Download business PDF reports or inspect raw scan artifact bundles.
              {isFetching ? " · Refreshing reports…" : ""}
            </p>
          </div>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Filter run IDs or profiles…"
        loadingMessage="Retrieving report catalog…"
        emptyMessage="No scan runs recorded yet."
      />
    </div>
  );
}

