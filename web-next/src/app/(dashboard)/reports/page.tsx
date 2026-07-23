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
            className="font-medium text-sky-700 underline-offset-2 hover:underline"
          >
            <code className="text-xs">{row.original.run_id}</code>
          </Link>
        ),
      },
      {
        accessorKey: "profile",
        header: "Profile",
        cell: ({ getValue }) => String(getValue() || "—"),
      },
      {
        accessorKey: "started_at",
        header: "Started",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at
            ? format(new Date(row.original.started_at), "dd-MM-yyyy HH:mm")
            : "—",
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: "Vulns",
        cell: ({ getValue }) => (
          <span className="tabular-nums">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
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
                onClick={() => downloadPdf(row.original.run_id)}
                disabled={busyRun === row.original.run_id}
              >
                <Download className="mr-1 h-3.5 w-3.5" />
                {busyRun === row.original.run_id ? "…" : "PDF"}
              </Button>
            ) : (
              <Badge variant="outline">no summary</Badge>
            )}
            <Button asChild variant="ghost" size="sm">
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
      <div className="flex items-center gap-3">
        <FileText className="h-6 w-6 text-slate-500" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Reports</h1>
          <p className="text-sm text-muted-foreground">
            Download the business PDF report or browse raw artifacts for any run.
            {isFetching ? " · refreshing…" : ""}
          </p>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Filter runs…"
        loadingMessage="Loading runs…"
        emptyMessage="No runs yet — reports appear here after a scan completes."
      />
    </div>
  );
}
