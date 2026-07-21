"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchJobs, startScan, type JobInfo } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";
import { useAuthStore } from "@/lib/auth-store";

function jobBadge(status: JobInfo["status"]) {
  if (status === "succeeded")
    return <Badge className="bg-emerald-600 hover:bg-emerald-600">succeeded</Badge>;
  if (status === "failed") return <Badge variant="destructive">failed</Badge>;
  if (status === "running")
    return <Badge className="bg-amber-600 hover:bg-amber-600">running</Badge>;
  return <Badge variant="secondary">queued</Badge>;
}

export default function JobsPage() {
  const { canOperate } = useAuthStore();
  const queryClient = useQueryClient();
  const [mode, setMode] = useState("balanced");
  const [delta, setDelta] = useState(false);
  const [skipNse, setSkipNse] = useState(false);
  const [notify, setNotify] = useState(false);
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("");
  const [portsUdp, setPortsUdp] = useState("");
  const [formError, setFormError] = useState<string | null>(null);

  const {
    data = [],
    isLoading,
    error,
    isFetching,
  } = useQuery({
    queryKey: ["jobs"],
    queryFn: fetchJobs,
    refetchInterval: 4_000,
    enabled: canOperate,
  });

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: async () => {
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["jobs"] });
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : "Failed to start scan");
    },
  });

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
        cell: ({ row }) => jobBadge(row.original.status),
      },
      {
        accessorKey: "mode",
        header: "Mode",
      },
      {
        accessorKey: "run_id",
        header: "Run",
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

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

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

  function onStart(event: FormEvent) {
    event.preventDefault();
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

      <form onSubmit={onStart} className="space-y-4 rounded-lg border bg-white p-4">
        <div className="grid gap-4 md:grid-cols-2">
          <label className="grid gap-2 text-sm font-medium">
            Mode
            <select
              className="flex h-10 rounded-md border border-input bg-background px-3 text-sm"
              value={mode}
              onChange={(e) => setMode(e.target.value)}
            >
              <option value="safe">safe</option>
              <option value="balanced">balanced</option>
              <option value="fast">fast</option>
            </select>
          </label>
          <div className="flex flex-wrap items-end gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={delta} onChange={(e) => setDelta(e.target.checked)} />
              Delta
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={skipNse}
                onChange={(e) => setSkipNse(e.target.checked)}
              />
              Skip NSE
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={notify}
                onChange={(e) => setNotify(e.target.checked)}
              />
              Notify
            </label>
          </div>
          <label className="grid gap-2 text-sm font-medium md:col-span-1">
            Ranges (optional)
            <textarea
              className="min-h-[96px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={ranges}
              onChange={(e) => setRanges(e.target.value)}
              placeholder={"10.0.0.0/24"}
              spellCheck={false}
            />
          </label>
          <label className="grid gap-2 text-sm font-medium">
            Domains (optional)
            <textarea
              className="min-h-[96px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              placeholder={"example.com"}
              spellCheck={false}
            />
          </label>
          <label className="grid gap-2 text-sm font-medium">
            TCP ports (optional)
            <textarea
              className="min-h-[72px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              placeholder={"22,80,443\n8000-8010"}
              spellCheck={false}
            />
          </label>
          <label className="grid gap-2 text-sm font-medium">
            UDP ports (optional)
            <textarea
              className="min-h-[72px] rounded-md border border-input bg-background px-3 py-2 text-sm"
              value={portsUdp}
              onChange={(e) => setPortsUdp(e.target.value)}
              placeholder={"53,123,161\n500-510"}
              spellCheck={false}
            />
          </label>
        </div>
        <p className="text-xs text-muted-foreground">
          Empty fields use server default input files. UDP list applies when{" "}
          <code>ports.protocol</code> is <code>udp</code> or <code>tcp_udp</code>.
        </p>
        {formError ? <p className="text-sm text-rose-600">{formError}</p> : null}
        <Button type="submit" disabled={mutation.isPending}>
          {mutation.isPending ? "Starting…" : "Start scan"}
        </Button>
      </form>

      {error ? (
        <p className="text-sm text-rose-600">
          {error instanceof Error ? error.message : "Failed to load jobs"}
        </p>
      ) : null}

      <div className="rounded-lg border bg-white">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  Loading jobs…
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  No jobs yet.
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
