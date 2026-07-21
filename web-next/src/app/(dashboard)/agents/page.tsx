"use client";

import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useAgents } from "@/hooks/use-agents";
import { type AgentInfo } from "@/lib/api";
import { AGENT_STATUS, agentEffectiveStatus } from "@/lib/config/statuses";

export default function AgentsPage() {
  const { data = [], isLoading, error, isFetching } = useAgents();

  const columns = useMemo<ColumnDef<AgentInfo>[]>(
    () => [
      {
        id: "agent",
        accessorFn: (agent) => `${agent.hostname} ${agent.agent_id}`,
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
        accessorFn: (agent) => agentEffectiveStatus(agent),
        header: "Status",
        cell: ({ row }) => (
          <StatusBadge value={agentEffectiveStatus(row.original)} map={AGENT_STATUS} />
        ),
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
        enableSorting: false,
        cell: ({ getValue }) => {
          const value = getValue();
          return value ? <code className="text-xs">{String(value)}</code> : "—";
        },
      },
      {
        accessorKey: "last_seen_at",
        header: "Last seen",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.last_seen_at
            ? format(new Date(row.original.last_seen_at), "yyyy-MM-dd HH:mm:ss")
            : "—",
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Agents</h1>
        <p className="text-sm text-muted-foreground">
          Remote agent fleet from <code className="text-xs">GET /api/agents</code>
          {isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        searchPlaceholder="Filter agents…"
        loadingMessage="Loading agents…"
        emptyMessage="No agents registered."
      />
    </div>
  );
}
