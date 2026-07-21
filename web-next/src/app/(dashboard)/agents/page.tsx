"use client";

import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { format } from "date-fns";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchAgents, type AgentInfo } from "@/lib/api";

function statusBadge(agent: AgentInfo) {
  if (!agent.online) return <Badge variant="secondary">offline</Badge>;
  if (agent.status === "busy")
    return <Badge className="bg-amber-600 hover:bg-amber-600">busy</Badge>;
  if (agent.status === "error") return <Badge variant="destructive">error</Badge>;
  if (agent.status === "stale") return <Badge variant="outline">stale</Badge>;
  return <Badge className="bg-emerald-600 hover:bg-emerald-600">idle</Badge>;
}

export default function AgentsPage() {
  const {
    data = [],
    isLoading,
    error,
    isFetching,
  } = useQuery({
    queryKey: ["agents"],
    queryFn: fetchAgents,
    refetchInterval: 5_000,
  });

  const columns = useMemo<ColumnDef<AgentInfo>[]>(
    () => [
      {
        accessorKey: "hostname",
        header: "Agent",
        cell: ({ row }) => (
          <div>
            <p className="font-medium text-slate-900">{row.original.hostname || "—"}</p>
            <p className="text-xs text-muted-foreground">{row.original.agent_id}</p>
          </div>
        ),
      },
      {
        id: "status",
        header: "Status",
        cell: ({ row }) => statusBadge(row.original),
      },
      {
        accessorKey: "tenant_id",
        header: "Tenant",
        cell: ({ getValue }) => String(getValue() || "default"),
      },
      {
        accessorKey: "version",
        header: "Version",
      },
      {
        accessorKey: "current_job_id",
        header: "Job",
        cell: ({ getValue }) => {
          const value = getValue();
          return value ? <code className="text-xs">{String(value)}</code> : "—";
        },
      },
      {
        accessorKey: "last_seen_at",
        header: "Last seen",
        cell: ({ row }) =>
          row.original.last_seen_at
            ? format(new Date(row.original.last_seen_at), "yyyy-MM-dd HH:mm:ss")
            : "—",
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Agents</h1>
        <p className="text-sm text-muted-foreground">
          Remote agent fleet from <code className="text-xs">GET /api/agents</code>
          {isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      {error ? (
        <p className="text-sm text-rose-600">
          {error instanceof Error ? error.message : "Failed to load agents"}
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
                  Loading agents…
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  No agents registered.
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
