"use client";

import { useState } from "react";
import Link from "next/link";
import { format } from "date-fns";
import {
  Activity,
  ArrowUpCircle,
  Cpu,
  Database,
  HardDrive,
  Layers,
  Loader2,
  Play,
  Server,
  Trash2,
} from "lucide-react";
import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useAgentDetail, useDeleteAgent, useUpgradeAgent } from "@/hooks/use-agents";
import { AGENT_STATUS, agentEffectiveStatus } from "@/lib/config/statuses";

export function AgentDetailsDrawer({
  agentId,
  open,
  onOpenChange,
}: {
  agentId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { data: agent, isLoading } = useAgentDetail(agentId);
  const upgradeMutation = useUpgradeAgent();
  const deleteMutation = useDeleteAgent();
  const [confirmDelete, setConfirmDelete] = useState(false);

  if (!open || !agentId) return null;

  const metrics = agent?.metrics || {};
  const isOutdated = Boolean(agent?.is_outdated);
  const cpuPercent = metrics.cpu_percent ?? 0;
  const memPercent = metrics.memory_percent ?? 0;
  const diskPercent = metrics.disk_percent ?? 0;

  const formatUptime = (seconds?: number) => {
    if (!seconds) return "—";
    const d = Math.floor(seconds / (3600 * 24));
    const h = Math.floor((seconds % (3600 * 24)) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m ${seconds % 60}s`;
  };

  const handleUpgrade = async () => {
    if (!agentId) return;
    await upgradeMutation.mutateAsync(agentId);
  };

  const handleDelete = async () => {
    if (!agentId) return;
    await deleteMutation.mutateAsync(agentId);
    setConfirmDelete(false);
    onOpenChange(false);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl border-slate-800 bg-slate-950 text-slate-100 shadow-2xl">
        <DialogHeader className="border-b border-slate-800/80 pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <DialogTitle className="font-mono text-lg font-bold text-slate-100">
                  {agent?.hostname || agentId}
                </DialogTitle>
                <DialogDescription className="font-mono text-xs text-slate-400">
                  {agentId} • Tenant: <span className="text-slate-300 font-semibold">{agent?.tenant_id || "default"}</span>
                </DialogDescription>
              </div>
            </div>
            {agent && (
              <StatusBadge value={agentEffectiveStatus(agent)} map={AGENT_STATUS} />
            )}
          </div>
        </DialogHeader>

        {isLoading ? (
          <div className="flex h-64 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-sky-400" />
          </div>
        ) : agent ? (
          <div className="space-y-5 pt-2">
            {/* Outdated Warning & Upgrade Trigger */}
            {isOutdated && (
              <div className="flex items-center justify-between rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                <div className="flex items-center gap-2">
                  <ArrowUpCircle className="h-4 w-4 text-amber-400" />
                  <span>
                    Update available: Current <strong>v{agent.version}</strong> &rarr; Latest <strong>v{agent.latest_version || "0.42.0"}</strong>
                  </span>
                </div>
                <Button
                  size="sm"
                  disabled={upgradeMutation.isPending || agent.upgrade_requested}
                  onClick={handleUpgrade}
                  className="h-7 bg-amber-600 px-3 text-xs font-semibold text-white hover:bg-amber-500"
                >
                  {upgradeMutation.isPending ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : agent.upgrade_requested ? (
                    "Upgrade Queued"
                  ) : (
                    "Upgrade Agent"
                  )}
                </Button>
              </div>
            )}

            {/* Live System Resource Telemetry */}
            <div>
              <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
                <Activity className="h-3.5 w-3.5 text-sky-400" />
                Live System Telemetry
              </h4>
              <div className="mt-3 grid grid-cols-3 gap-3">
                {/* CPU */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="flex items-center gap-1.5"><Cpu className="h-3.5 w-3.5 text-sky-400" /> CPU Load</span>
                    <span className="font-mono font-bold text-slate-200">{cpuPercent}%</span>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-full ${cpuPercent > 80 ? "bg-rose-500" : cpuPercent > 50 ? "bg-amber-500" : "bg-sky-500"}`}
                      style={{ width: `${Math.min(100, Math.max(0, cpuPercent))}%` }}
                    />
                  </div>
                </div>

                {/* Memory */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="flex items-center gap-1.5"><Database className="h-3.5 w-3.5 text-indigo-400" /> Memory</span>
                    <span className="font-mono font-bold text-slate-200">
                      {metrics.memory_used_mb ? `${metrics.memory_used_mb}MB` : `${memPercent}%`}
                    </span>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className={`h-full ${memPercent > 85 ? "bg-rose-500" : "bg-indigo-500"}`}
                      style={{ width: `${Math.min(100, Math.max(0, memPercent))}%` }}
                    />
                  </div>
                </div>

                {/* Disk */}
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-3.5">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="flex items-center gap-1.5"><HardDrive className="h-3.5 w-3.5 text-emerald-400" /> Disk Free</span>
                    <span className="font-mono font-bold text-slate-200">
                      {metrics.disk_free_gb ? `${metrics.disk_free_gb}GB` : "—"}
                    </span>
                  </div>
                  <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
                    <div
                      className="h-full bg-emerald-500"
                      style={{ width: `${Math.min(100, Math.max(0, 100 - diskPercent))}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* OS & Uptime Info */}
              <div className="mt-3 grid grid-cols-3 gap-2 rounded-lg border border-slate-800/70 bg-slate-900/30 p-2.5 font-mono text-[11px] text-slate-300">
                <div>
                  <span className="text-slate-500">OS:</span> {metrics.os || "Linux"} {metrics.arch ? `(${metrics.arch})` : ""}
                </div>
                <div>
                  <span className="text-slate-500">Uptime:</span> {formatUptime(metrics.uptime_seconds)}
                </div>
                <div>
                  <span className="text-slate-500">Last Seen:</span>{" "}
                  {agent.last_seen_at ? format(new Date(agent.last_seen_at), "HH:mm:ss") : "—"}
                </div>
              </div>
            </div>

            {/* Active Job Details */}
            {agent.current_job_id ? (
              <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/10 p-3.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Play className="h-4 w-4 animate-pulse text-indigo-400" />
                    <span className="text-xs font-semibold text-indigo-300">Executing Job:</span>
                    <code className="rounded bg-indigo-950 px-2 py-0.5 font-mono text-xs text-indigo-200 border border-indigo-800">
                      {agent.current_job_id}
                    </code>
                  </div>
                  <Link
                    href={`/runs/view?id=${agent.current_job_id}`}
                    className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 hover:underline"
                  >
                    View Scan &rarr;
                  </Link>
                </div>
                {agent.detail && (
                  <p className="mt-2 font-mono text-xs text-slate-300">
                    {agent.detail}
                  </p>
                )}
              </div>
            ) : null}

            {/* Labels & Capabilities */}
            <div className="space-y-2">
              <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
                <Layers className="h-3.5 w-3.5 text-sky-400" />
                Metadata & Labels
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {Object.entries(agent.labels || {}).map(([k, v]) => (
                  <span
                    key={k}
                    className="rounded-md border border-slate-800 bg-slate-900 px-2 py-0.5 font-mono text-xs text-slate-300"
                  >
                    <span className="text-slate-500">{k}:</span> {v}
                  </span>
                ))}
                {agent.capabilities?.map((cap) => (
                  <span
                    key={cap}
                    className="rounded-md border border-sky-900/60 bg-sky-950/40 px-2 py-0.5 font-mono text-xs text-sky-300"
                  >
                    {cap}
                  </span>
                ))}
                {Object.keys(agent.labels || {}).length === 0 && (!agent.capabilities || agent.capabilities.length === 0) && (
                  <span className="text-xs text-slate-500">No custom labels configured</span>
                )}
              </div>
            </div>

            {/* Danger Zone: Deregister */}
            <div className="border-t border-slate-800/80 pt-4">
              {!confirmDelete ? (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setConfirmDelete(true)}
                  className="gap-1.5 border-rose-900/60 text-xs text-rose-400 hover:bg-rose-950/40 hover:text-rose-300"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Deregister Agent
                </Button>
              ) : (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-rose-400 font-semibold">Confirm removal of {agentId}?</span>
                  <Button
                    size="sm"
                    disabled={deleteMutation.isPending}
                    onClick={handleDelete}
                    className="h-7 bg-rose-600 px-2.5 text-xs text-white hover:bg-rose-500"
                  >
                    {deleteMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Yes, Delete"}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setConfirmDelete(false)}
                    className="h-7 px-2 text-xs text-slate-400 hover:text-slate-200"
                  >
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}
