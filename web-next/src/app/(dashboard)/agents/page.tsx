"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import {
  ArrowUpCircle,
  Cpu,
  Eye,
  Server,
} from "lucide-react";
import { AgentDetailsDrawer } from "@/components/agent/agent-details-drawer";
import { DeployAgentDialog } from "@/components/agent/deploy-agent-dialog";
import { DataTable } from "@/components/data-table";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { useAgents, useAgentSummary } from "@/hooks/use-agents";
import { usePagination } from "@/hooks/use-pagination";
import { type AgentInfo } from "@/lib/api";
import { AGENT_STATUS, agentEffectiveStatus } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";

export default function AgentsPage() {
  const t = useT();
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  // Server-side paging/search/sort (ROADMAP P3.3): the fleet list is unbounded.
  const pagination = usePagination({ sort: "hostname", order: "asc" });
  const { data, isLoading, error, isFetching } = useAgents(pagination.params);
  const { data: summary } = useAgentSummary();
  const agents = data?.items ?? [];

  const columns = useMemo<ColumnDef<AgentInfo>[]>(
    () => [
      {
        id: "hostname",
        accessorFn: (agent) => `${agent.hostname} ${agent.agent_id}`,
        header: t("col.agentHost"),
        cell: ({ row }) => (
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/80 text-sky-400">
              <Server className="h-4 w-4" />
            </div>
            <div>
              <p className="font-mono font-bold text-slate-100">{row.original.hostname || "—"}</p>
              <p className="font-mono text-[10px] text-slate-400">{row.original.agent_id}</p>
            </div>
          </div>
        ),
      },
      {
        id: "status",
        accessorFn: (agent) => agentEffectiveStatus(agent),
        header: t("col.status"),
        cell: ({ row }) => (
          <StatusBadge value={agentEffectiveStatus(row.original)} map={AGENT_STATUS} />
        ),
      },
      {
        accessorKey: "tenant_id",
        header: t("col.tenantId"),
        cell: ({ getValue }) => <span className="font-semibold text-slate-300">{String(getValue() || "default")}</span>,
      },
      {
        accessorKey: "version",
        header: t("col.version"),
        cell: ({ row }) => {
          const isOutdated = row.original.is_outdated;
          return (
            <div className="flex items-center gap-1.5">
              <code className="rounded bg-slate-950 px-2 py-0.5 font-mono text-xs text-sky-400 border border-slate-800">
                v{row.original.version || "—"}
              </code>
              {isOutdated && (
                <span title={`Update available: v${row.original.latest_version || "0.42.0"}`} className="flex items-center">
                  <ArrowUpCircle className="h-4 w-4 text-amber-400" />
                </span>
              )}
            </div>
          );
        },
      },
      {
        id: "telemetry",
        header: "CPU / Mem",
        enableSorting: false,
        cell: ({ row }) => {
          const m = row.original.metrics;
          if (!m || (m.cpu_percent === undefined && m.memory_percent === undefined)) {
            return <span className="text-slate-500 text-xs">—</span>;
          }
          return (
            <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300">
              {m.cpu_percent !== undefined && (
                <span className="rounded bg-slate-900 px-1.5 py-0.5 border border-slate-800">
                  <span className="text-slate-500">CPU:</span> {m.cpu_percent}%
                </span>
              )}
              {m.memory_used_mb !== undefined && (
                <span className="rounded bg-slate-900 px-1.5 py-0.5 border border-slate-800">
                  <span className="text-slate-500">RAM:</span> {m.memory_used_mb}M
                </span>
              )}
            </div>
          );
        },
      },
      {
        accessorKey: "current_job_id",
        header: t("col.activeJob"),
        enableSorting: false,
        cell: ({ getValue }) => {
          const value = getValue();
          return value ? <code className="rounded bg-slate-950 px-2 py-0.5 font-mono text-xs text-indigo-400 border border-slate-800">{String(value)}</code> : <span className="text-slate-500">—</span>;
        },
      },
      {
        accessorKey: "last_seen_at",
        header: t("col.lastHeartbeat"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.last_seen_at ? (
            <span className="font-mono text-xs text-slate-300">
              {format(new Date(row.original.last_seen_at), "yyyy-MM-dd HH:mm:ss")}
            </span>
          ) : (
            "—"
          ),
      },
      {
        id: "actions",
        header: "Actions",
        enableSorting: false,
        cell: ({ row }) => (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => setSelectedAgentId(row.original.agent_id)}
            className="h-8 gap-1.5 px-2.5 text-xs text-sky-400 hover:bg-sky-950/40 hover:text-sky-300"
          >
            <Eye className="h-3.5 w-3.5" />
            Inspect
          </Button>
        ),
      },
    ],
    [t],
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Cpu className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.agents.title")}</h1>
            <p className="text-xs text-slate-400">
              {t("page.agents.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>

        <DeployAgentDialog />
      </div>

      {/* Fleet KPIs Banner */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <KpiCard
          label="Total Agents"
          value={summary?.total_agents ?? data?.total ?? 0}
          hint="Registered scan nodes"
          decorationColor="sky"
        />
        <KpiCard
          label="Online / Active"
          value={summary?.online_agents ?? 0}
          hint="Sending heartbeats"
          decorationColor="emerald"
        />
        <KpiCard
          label="Scanning (Busy)"
          value={summary?.busy_agents ?? 0}
          hint="Executing scan tasks"
          decorationColor="blue"
        />
        <KpiCard
          label="Stale / Offline"
          value={summary?.stale_agents ?? 0}
          hint="Heartbeat timed out"
          decorationColor="rose"
        />
        <KpiCard
          label="Updates Available"
          value={summary?.outdated_agents ?? 0}
          hint={`Target: v${summary?.latest_version || "0.42.0"}`}
          decorationColor="amber"
        />
      </div>

      {/* Agents Table */}
      <DataTable
        columns={columns}
        data={agents}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("search.agents")}
        loadingMessage={t("loading.agents")}
        emptyMessage={t("empty.agents")}
        meta={`${data?.total ?? 0} agents`}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: data?.total ?? 0,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["hostname", "status", "tenant_id", "last_seen_at"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />

      {/* Agent Details Drawer */}
      <AgentDetailsDrawer
        agentId={selectedAgentId}
        open={Boolean(selectedAgentId)}
        onOpenChange={(open) => {
          if (!open) setSelectedAgentId(null);
        }}
      />
    </div>
  );
}

