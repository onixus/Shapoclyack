"use client";

import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Cpu } from "lucide-react";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useAgents } from "@/hooks/use-agents";
import { usePagination } from "@/hooks/use-pagination";
import { type AgentInfo } from "@/lib/api";
import { AGENT_STATUS, agentEffectiveStatus } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";

export default function AgentsPage() {
  const t = useT();
  // Server-side paging/search/sort (ROADMAP P3.3): the fleet list is unbounded.
  const pagination = usePagination({ sort: "hostname", order: "asc" });
  const { data, isLoading, error, isFetching } = useAgents(pagination.params);
  const agents = data?.items ?? [];

  const columns = useMemo<ColumnDef<AgentInfo>[]>(
    () => [
      {
        id: "hostname",
        accessorFn: (agent) => `${agent.hostname} ${agent.agent_id}`,
        header: t("col.agentHost"),
        cell: ({ row }) => (
          <div>
            <p className="font-mono font-bold text-slate-100">{row.original.hostname || "—"}</p>
            <p className="font-mono text-[10px] text-slate-400">{row.original.agent_id}</p>
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
        cell: ({ getValue }) => <code className="rounded bg-slate-950 px-2 py-0.5 font-mono text-xs text-sky-400 border border-slate-800">{String(getValue() || "—")}</code>,
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
    ],
    [t],
  );

  return (
    <div className="space-y-6">
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
      </div>

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
    </div>
  );
}

