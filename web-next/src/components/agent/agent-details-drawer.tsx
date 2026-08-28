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
      <DialogContent className="flex max-h-[90vh] w-full max-w-2xl flex-col overflow-hidden p-0 bg-card text-card-foreground border-border shadow-2xl">
        <DialogHeader className="border-b border-border/80 px-6 pt-6 pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-500 border border-sky-500/20 shadow-sm">
                <Server className="h-5 w-5" />
              </div>
              <div>
                <DialogTitle className="font-mono text-lg font-bold text-foreground">
                  {agent?.hostname || agentId}
                </DialogTitle>
                <DialogDescription className="font-mono text-xs text-muted-foreground">
                  {agentId} • Tenant: <span className="text-foreground font-semibold">{agent?.tenant_id || "default"}</span>
                </DialogDescription>
              </div>
            </div>
            {agent && (
              <StatusBadge value={agentEffectiveStatus(agent)} map={AGENT_STATUS} />
            )}
          </div>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto custom-scrollbar px-6 py-4">
          {isLoading ? (
            <div className="flex h-64 items-center justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-primary" />
            </div>
          ) : agent ? (
            <div className="space-y-5">
              {/* Outdated Warning & Upgrade Trigger */}
              {isOutdated && (
                <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
                  <div className="flex items-center gap-2">
                    <ArrowUpCircle className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span>
                      Update available: Current <strong>v{agent.version}</strong> &rarr; Latest <strong>v{agent.latest_version || "0.42.0"}</strong>
                      <span className="block opacity-80">
                        Marking records the intent for operators. The upgrade itself runs on the
                        host — the agent receives no command from here.
                      </span>
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
                      "Marked for upgrade"
                    ) : (
                      "Mark for upgrade"
                    )}
                  </Button>
                </div>
              )}

              {/* Live System Resource Telemetry */}
              <div>
                <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  <Activity className="h-3.5 w-3.5 text-sky-500" />
                  Live System Telemetry
                </h4>
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3">
                  {/* CPU */}
                  <div className="rounded-xl border border-border bg-card p-3.5 shadow-sm">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-medium"><Cpu className="h-3.5 w-3.5 text-sky-500" /> CPU Load</span>
                      <span className="font-mono font-bold text-foreground">{cpuPercent}%</span>
                    </div>
                    <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div
                        className={`h-full transition-all duration-300 ${cpuPercent > 80 ? "bg-rose-500" : cpuPercent > 50 ? "bg-amber-500" : "bg-sky-500"}`}
                        style={{ width: `${Math.min(100, Math.max(0, cpuPercent))}%` }}
                      />
                    </div>
                  </div>

                  {/* Memory */}
                  <div className="rounded-xl border border-border bg-card p-3.5 shadow-sm">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-medium"><Database className="h-3.5 w-3.5 text-indigo-500" /> Memory</span>
                      <span className="font-mono font-bold text-foreground">
                        {metrics.memory_used_mb ? `${metrics.memory_used_mb}MB` : `${memPercent}%`}
                      </span>
                    </div>
                    <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div
                        className={`h-full transition-all duration-300 ${memPercent > 85 ? "bg-rose-500" : "bg-indigo-500"}`}
                        style={{ width: `${Math.min(100, Math.max(0, memPercent))}%` }}
                      />
                    </div>
                  </div>

                  {/* Disk */}
                  <div className="rounded-xl border border-border bg-card p-3.5 shadow-sm">
                    <div className="flex items-center justify-between text-xs text-muted-foreground">
                      <span className="flex items-center gap-1.5 font-medium"><HardDrive className="h-3.5 w-3.5 text-emerald-500" /> Disk Free</span>
                      <span className="font-mono font-bold text-foreground">
                        {metrics.disk_free_gb ? `${metrics.disk_free_gb}GB` : "—"}
                      </span>
                    </div>
                    <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-secondary">
                      <div
                        className="h-full bg-emerald-500 transition-all duration-300"
                        style={{ width: `${Math.min(100, Math.max(0, 100 - diskPercent))}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* OS & Uptime Info */}
                <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2 rounded-lg border border-border bg-muted/50 p-2.5 font-mono text-xs text-foreground">
                  <div>
                    <span className="text-muted-foreground">OS:</span> {metrics.os || "Linux"} {metrics.arch ? `(${metrics.arch})` : ""}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Uptime:</span> {formatUptime(metrics.uptime_seconds)}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Last Seen:</span>{" "}
                    {agent.last_seen_at ? format(new Date(agent.last_seen_at), "HH:mm:ss") : "—"}
                  </div>
                </div>
              </div>

              {/* Active Job Details */}
              {agent.current_job_id ? (
                <div className="rounded-xl border border-indigo-500/30 bg-indigo-500/10 p-3.5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Play className="h-4 w-4 animate-pulse text-indigo-500 shrink-0" />
                      <span className="text-xs font-semibold text-indigo-950 dark:text-indigo-200">Executing Job:</span>
                      <code className="rounded bg-background px-2 py-0.5 font-mono text-xs text-indigo-600 dark:text-indigo-300 border border-indigo-500/30">
                        {agent.current_job_id}
                      </code>
                    </div>
                    <Link
                      href={`/runs/view?id=${agent.current_job_id}`}
                      className="text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:underline"
                    >
                      View Scan &rarr;
                    </Link>
                  </div>
                  {agent.detail && (
                    <p className="mt-2 font-mono text-xs text-muted-foreground">
                      {agent.detail}
                    </p>
                  )}
                </div>
              ) : null}

              {/* Labels & Capabilities */}
              <div className="space-y-2">
                <h4 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground">
                  <Layers className="h-3.5 w-3.5 text-sky-500" />
                  Metadata & Labels
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(agent.labels || {}).map(([k, v]) => (
                    <span
                      key={k}
                      className="rounded-md border border-border bg-muted px-2 py-0.5 font-mono text-xs text-foreground"
                    >
                      <span className="text-muted-foreground">{k}:</span> {v}
                    </span>
                  ))}
                  {agent.capabilities?.map((cap) => (
                    <span
                      key={cap}
                      className="rounded-md border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-xs text-sky-700 dark:text-sky-300"
                    >
                      {cap}
                    </span>
                  ))}
                  {Object.keys(agent.labels || {}).length === 0 && (!agent.capabilities || agent.capabilities.length === 0) && (
                    <span className="text-xs text-muted-foreground">No custom labels configured</span>
                  )}
                </div>
              </div>

              {/* Danger Zone: Deregister */}
              <div className="border-t border-border/80 pt-4">
                {!confirmDelete ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setConfirmDelete(true)}
                    className="gap-1.5 border-rose-500/40 text-xs text-rose-600 dark:text-rose-400 hover:bg-rose-500/10 hover:text-rose-700 dark:hover:text-rose-300"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Deregister Agent
                  </Button>
                ) : (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-rose-600 dark:text-rose-400 font-semibold">Confirm removal of {agentId}?</span>
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
                      className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                    >
                      Cancel
                    </Button>
                  </div>
                )}
              </div>
            </div>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  );
}
