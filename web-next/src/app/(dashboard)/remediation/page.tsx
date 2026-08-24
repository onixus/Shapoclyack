"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertCircle,
  Calendar,
  CheckCircle2,
  ExternalLink,
  Flame,
  History,
  Kanban,
  MoreVertical,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  User,
  Wrench,
  X,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { VulnerabilityTimeline } from "@/components/vulnerability/timeline";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import {
  useAssignVulnerability,
  useCommentOnVulnerability,
  useClearVulnerabilityTicket,
  useSetVulnerabilityTicket,
  useTrackedVulnerabilities,
  useTransitionVulnerability,
  useVulnerabilityActivity,
  useVulnerabilityEvents,
} from "@/hooks/use-vulnerabilities";
import {
  transitionVulnerability,
  type TicketSystem,
  type TrackedVulnerability,
  type VulnLifecycleState,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { SEVERITY_STATUS, VULN_LIFECYCLE_STATUS } from "@/lib/config/statuses";
import { normalizeSeverity } from "@/lib/run-data";
import {
  BOARD_CLOSED_LIMIT,
  BOARD_OPEN_LIMIT,
  TICKET_SYSTEMS,
  canDropOn,
  groupByState,
} from "@/lib/remediation";
import {
  findingLabel,
  legalTransitions,
  VULN_STATES,
  VULN_TRANSITION_LABEL,
  vulnDetailHref,
} from "@/lib/vuln-lifecycle";
import { cn } from "@/lib/utils";

const DRAG_TYPE = "application/x-shapoclyack-vuln";

const STAGE_META: Record<
  VulnLifecycleState,
  {
    title: string;
    description: string;
    accentColor: string;
    topBorder: string;
    badgeBg: string;
    badgeText: string;
    icon: React.ComponentType<{ className?: string }>;
  }
> = {
  OPEN: {
    title: "Open",
    description: "New findings requiring triage",
    accentColor: "sky",
    topBorder: "border-t-sky-500",
    badgeBg: "bg-sky-500/10 dark:bg-sky-500/20",
    badgeText: "text-sky-700 dark:text-sky-300",
    icon: AlertCircle,
  },
  ACKNOWLEDGED: {
    title: "Acknowledged",
    description: "Confirmed & scoped findings",
    accentColor: "amber",
    topBorder: "border-t-amber-500",
    badgeBg: "bg-amber-500/10 dark:bg-amber-500/20",
    badgeText: "text-amber-800 dark:text-amber-300",
    icon: CheckCircle2,
  },
  PLANNED: {
    title: "Planned",
    description: "Scheduled for remediation sprint",
    accentColor: "indigo",
    topBorder: "border-t-indigo-500",
    badgeBg: "bg-indigo-500/10 dark:bg-indigo-500/20",
    badgeText: "text-indigo-800 dark:text-indigo-300",
    icon: Calendar,
  },
  FIXING: {
    title: "Fixing",
    description: "Patch or config in development",
    accentColor: "orange",
    topBorder: "border-t-orange-500",
    badgeBg: "bg-orange-500/10 dark:bg-orange-500/20",
    badgeText: "text-orange-800 dark:text-orange-300",
    icon: Wrench,
  },
  VERIFYING: {
    title: "Verifying",
    description: "Testing fix & rescan validation",
    accentColor: "violet",
    topBorder: "border-t-violet-500",
    badgeBg: "bg-violet-500/10 dark:bg-violet-500/20",
    badgeText: "text-violet-800 dark:text-violet-300",
    icon: ShieldCheck,
  },
  CLOSED: {
    title: "Closed",
    description: "Verified remediated or exception",
    accentColor: "emerald",
    topBorder: "border-t-emerald-500",
    badgeBg: "bg-emerald-500/10 dark:bg-emerald-500/20",
    badgeText: "text-emerald-800 dark:text-emerald-300",
    icon: Shield,
  },
};

export default function RemediationPage() {
  const t = useT();
  const queryClient = useQueryClient();
  const { user } = useAuthStore();

  // Queries
  const openQuery = useTrackedVulnerabilities(
    { open_only: true },
    { limit: BOARD_OPEN_LIMIT, sort: "contextual_score", order: "desc" },
  );
  const closedQuery = useTrackedVulnerabilities(
    { state: "CLOSED" },
    { limit: BOARD_CLOSED_LIMIT, sort: "closed_at", order: "desc" },
  );
  const activityQuery = useVulnerabilityActivity({ limit: 30 });

  // Local Filter & UI State
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedSla, setSelectedSla] = useState<string>("all");
  const [selectedAssignee, setSelectedAssignee] = useState<string>("all");
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);
  const [isActivitySheetOpen, setIsActivitySheetOpen] = useState(false);
  const [dropTarget, setDropTarget] = useState<VulnLifecycleState | null>(null);

  const dropMutation = useMutation({
    mutationFn: ({ vulnId, state }: { vulnId: string; state: VulnLifecycleState }) =>
      transitionVulnerability(vulnId, { state }),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.vulnerability(updated.vuln_id), updated);
      void queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
      toast.success(`Vulnerability moved to ${updated.state}`);
    },
    onError: (err) => {
      toast.error("Transition failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });

  const rawItems = useMemo(
    () => [...(openQuery.data?.items ?? []), ...(closedQuery.data?.items ?? [])],
    [openQuery.data, closedQuery.data],
  );

  const byId = useMemo(() => new Map(rawItems.map((row) => [row.vuln_id, row])), [rawItems]);

  // Filtered Items
  const filteredItems = useMemo(() => {
    return rawItems.filter((item) => {
      // Search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchesTitle = (item.title || "").toLowerCase().includes(q);
        const matchesCve = (item.cve || "").toLowerCase().includes(q);
        const matchesAsset = (item.asset_id || "").toLowerCase().includes(q);
        const matchesAssignee = (item.assignee || "").toLowerCase().includes(q);
        const matchesTicket = (item.ticket_key || "").toLowerCase().includes(q);
        const matchesId = item.vuln_id.toLowerCase().includes(q);
        if (!matchesTitle && !matchesCve && !matchesAsset && !matchesAssignee && !matchesTicket && !matchesId) {
          return false;
        }
      }

      // Severity
      if (selectedSeverity !== "all") {
        const norm = normalizeSeverity(item.severity);
        if (norm !== selectedSeverity) return false;
      }

      // SLA State
      if (selectedSla !== "all") {
        if (item.sla_state !== selectedSla) return false;
      }

      // Assignee
      if (selectedAssignee === "unassigned") {
        if (item.assignee) return false;
      } else if (selectedAssignee === "mine") {
        if (!user?.username || item.assignee !== user.username) return false;
      } else if (selectedAssignee !== "all") {
        if (item.assignee !== selectedAssignee) return false;
      }

      return true;
    });
  }, [rawItems, searchQuery, selectedSeverity, selectedSla, selectedAssignee, user?.username]);

  const grouped = useMemo(() => groupByState(filteredItems), [filteredItems]);
  const selected = rawItems.find((row) => row.vuln_id === selectedVulnId) ?? null;

  // Aggregate stats
  const totalFindings = rawItems.length;
  const criticalCount = rawItems.filter((i) => normalizeSeverity(i.severity) === "critical").length;
  const highCount = rawItems.filter((i) => normalizeSeverity(i.severity) === "high").length;
  const breachedCount = rawItems.filter((i) => i.sla_state === "breached").length;
  const dueSoonCount = rawItems.filter((i) => i.sla_state === "due_soon").length;

  function handleDrop(vulnId: string, from: VulnLifecycleState, to: VulnLifecycleState) {
    const row = byId.get(vulnId);
    if (!row) return;
    if (!canDropOn(from, to)) {
      toast.error(`Invalid transition: ${row.state} cannot move directly to ${to}`);
      return;
    }
    dropMutation.mutate({ vulnId, state: to });
  }

  const truncated =
    (openQuery.data?.has_more ?? false) || (closedQuery.data?.has_more ?? false);
  const error = (openQuery.error || closedQuery.error) as Error | null;
  const loading = openQuery.isLoading || closedQuery.isLoading;

  return (
    <div className="space-y-4">
      {/* Header & Global Stats */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500/20 to-indigo-500/20 text-sky-500 border border-sky-500/30 shadow-sm">
            <Kanban className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
                {t("page.remediation.title")}
              </h1>
              <span className="rounded-full bg-primary/10 px-2.5 py-0.5 font-mono text-xs font-bold text-primary border border-primary/20">
                {filteredItems.length} findings
              </span>
            </div>
            <p className="mt-0.5 text-xs text-muted-foreground">{t("page.remediation.subtitle")}</p>
          </div>
        </div>

        {/* Quick Actions */}
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setIsActivitySheetOpen(true)}
            className="gap-1.5 border-border bg-card text-xs font-semibold shadow-sm"
          >
            <History className="h-3.5 w-3.5 text-sky-500" />
            Audit Trail
          </Button>

          <Link href="/vulnerabilities">
            <Button size="sm" variant="ghost" className="gap-1 text-xs text-muted-foreground hover:text-foreground">
              Vulnerability Center
              <ExternalLink className="h-3 w-3" />
            </Button>
          </Link>
        </div>
      </div>

      {/* KPI / Risk Strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
        <div className="flex items-center gap-3 rounded-xl border border-border bg-card p-3 shadow-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/10 text-sky-500 font-bold text-xs">
            {totalFindings}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-muted-foreground font-semibold">Total Tracked</p>
            <p className="text-sm font-bold text-foreground">{rawItems.length} items</p>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-xl border border-rose-500/20 bg-rose-500/5 p-3 shadow-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/20 text-rose-600 dark:text-rose-400 font-bold text-xs">
            {criticalCount}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-rose-700 dark:text-rose-300 font-semibold">Critical Risk</p>
            <p className="text-sm font-bold text-rose-900 dark:text-rose-200">{criticalCount} critical</p>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-xl border border-orange-500/20 bg-orange-500/5 p-3 shadow-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-500/20 text-orange-600 dark:text-orange-400 font-bold text-xs">
            {highCount}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-orange-700 dark:text-orange-300 font-semibold">High Risk</p>
            <p className="text-sm font-bold text-orange-900 dark:text-orange-200">{highCount} high</p>
          </div>
        </div>

        <div className="flex items-center gap-3 rounded-xl border border-rose-500/20 bg-rose-500/5 p-3 shadow-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/20 text-rose-600 dark:text-rose-400 font-bold text-xs">
            {breachedCount}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-rose-700 dark:text-rose-300 font-semibold">SLA Breached</p>
            <p className="text-sm font-bold text-rose-900 dark:text-rose-200">{breachedCount} overdue</p>
          </div>
        </div>

        <div className="hidden lg:flex items-center gap-3 rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 shadow-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-amber-500/20 text-amber-600 dark:text-amber-400 font-bold text-xs">
            {dueSoonCount}
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-amber-700 dark:text-amber-300 font-semibold">SLA Due Soon</p>
            <p className="text-sm font-bold text-amber-900 dark:text-amber-200">{dueSoonCount} approaching</p>
          </div>
        </div>
      </div>

      {/* Kanban Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card p-3 shadow-sm">
        <div className="flex flex-1 flex-wrap items-center gap-2.5">
          {/* Search Box */}
          <div className="relative min-w-[220px] max-w-xs flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Filter by CVE, title, asset, owner..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 h-9 text-xs"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2.5 top-2.5 text-muted-foreground hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>

          {/* Severity Filter */}
          <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
            <SelectTrigger className="h-9 w-[130px] text-xs">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>

          {/* SLA Filter */}
          <Select value={selectedSla} onValueChange={setSelectedSla}>
            <SelectTrigger className="h-9 w-[130px] text-xs">
              <SelectValue placeholder="SLA Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All SLAs</SelectItem>
              <SelectItem value="breached">🚨 Breached</SelectItem>
              <SelectItem value="due_soon">⚠️ Due Soon</SelectItem>
              <SelectItem value="on_track">✅ On Track</SelectItem>
            </SelectContent>
          </Select>

          {/* Assignee Filter */}
          <Select value={selectedAssignee} onValueChange={setSelectedAssignee}>
            <SelectTrigger className="h-9 w-[140px] text-xs">
              <SelectValue placeholder="Assignee" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Assignees</SelectItem>
              <SelectItem value="mine">Assigned to Me</SelectItem>
              <SelectItem value="unassigned">Unassigned</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Reset Filter Button */}
        {(searchQuery || selectedSeverity !== "all" || selectedSla !== "all" || selectedAssignee !== "all") && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              setSearchQuery("");
              setSelectedSeverity("all");
              setSelectedSla("all");
              setSelectedAssignee("all");
            }}
            className="h-8 text-xs text-muted-foreground hover:text-foreground"
          >
            Reset Filters
          </Button>
        )}
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}

      {truncated ? (
        <Alert className="border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200">
          <AlertDescription className="text-xs">
            Showing top {BOARD_OPEN_LIMIT} open and {BOARD_CLOSED_LIMIT} closed findings on Kanban. Open{" "}
            <Link href="/vulnerabilities" className="font-semibold text-primary underline">
              Vulnerability Center
            </Link>{" "}
            for complete queryable catalog.
          </AlertDescription>
        </Alert>
      ) : null}

      {/* Main Kanban Columns Grid */}
      {loading ? (
        <div className="flex h-96 items-center justify-center rounded-xl border border-border bg-card">
          <div className="flex items-center gap-3 text-muted-foreground font-medium text-sm">
            <RefreshCw className="h-5 w-5 animate-spin text-primary" />
            Loading Remediation Kanban Board…
          </div>
        </div>
      ) : (
        <div className="flex min-w-0 gap-4 overflow-x-auto custom-scrollbar-x pb-5 pt-1">
          {VULN_STATES.map((state) => (
            <KanbanColumn
              key={state}
              state={state}
              items={grouped[state]}
              selectedId={selectedVulnId}
              isDropTarget={dropTarget === state}
              onSelect={setSelectedVulnId}
              onDragEnter={() => setDropTarget(state)}
              onDragLeave={() => setDropTarget((current) => (current === state ? null : current))}
              onDropped={(vulnId, from) => {
                setDropTarget(null);
                handleDrop(vulnId, from, state);
              }}
              onQuickMove={(vulnId, targetState) => {
                const item = byId.get(vulnId);
                if (item) handleDrop(vulnId, item.state, targetState);
              }}
            />
          ))}
        </div>
      )}

      {/* Slide-Over Finding Detail Drawer */}
      <VulnerabilityDrawer
        vuln={selected}
        open={Boolean(selectedVulnId)}
        onOpenChange={(open) => {
          if (!open) setSelectedVulnId(null);
        }}
      />

      {/* Global Activity Timeline Sheet */}
      <Sheet open={isActivitySheetOpen} onOpenChange={setIsActivitySheetOpen}>
        <SheetContent side="right" className="flex flex-col p-0 overflow-hidden bg-card">
          <SheetHeader className="border-b border-border/80 p-6 pb-4">
            <SheetTitle className="flex items-center gap-2 text-lg font-bold">
              <History className="h-5 w-5 text-sky-500" />
              Remediation Audit Trail
            </SheetTitle>
            <SheetDescription>
              Chronological log of all state transitions, comments, assignments, and ticket links.
            </SheetDescription>
          </SheetHeader>

          <div className="flex-1 overflow-y-auto custom-scrollbar p-6">
            {activityQuery.isLoading ? (
              <p className="text-xs text-muted-foreground">Loading audit trail…</p>
            ) : (
              <VulnerabilityTimeline
                events={activityQuery.data?.items ?? []}
                emptyMessage="No remediation activity yet."
              />
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

// ----------------------------------------------------------------------------
// KANBAN COLUMN COMPONENT
// ----------------------------------------------------------------------------
function KanbanColumn({
  state,
  items,
  selectedId,
  isDropTarget,
  onSelect,
  onDragEnter,
  onDragLeave,
  onDropped,
  onQuickMove,
}: {
  state: VulnLifecycleState;
  items: TrackedVulnerability[];
  selectedId: string | null;
  isDropTarget: boolean;
  onSelect: (id: string) => void;
  onDragEnter: () => void;
  onDragLeave: () => void;
  onDropped: (vulnId: string, from: VulnLifecycleState) => void;
  onQuickMove: (vulnId: string, targetState: VulnLifecycleState) => void;
}) {
  const meta = STAGE_META[state];
  const Icon = meta.icon;

  return (
    <div
      className={cn(
        "flex w-80 sm:w-84 shrink-0 flex-col rounded-2xl border bg-muted/40 text-card-foreground shadow-sm transition-all duration-200",
        meta.topBorder,
        isDropTarget
          ? "border-primary ring-2 ring-primary/30 bg-primary/5 shadow-md"
          : "border-border/80",
      )}
      onDragOver={(e) => {
        e.preventDefault();
        onDragEnter();
      }}
      onDragLeave={onDragLeave}
      onDrop={(e) => {
        e.preventDefault();
        const raw = e.dataTransfer.getData(DRAG_TYPE);
        if (!raw) return;
        try {
          const payload = JSON.parse(raw) as { vulnId: string; from: VulnLifecycleState };
          onDropped(payload.vulnId, payload.from);
        } catch {
          // invalid payload
        }
      }}
    >
      {/* Column Sticky Header */}
      <div className="flex items-center justify-between border-b border-border/70 px-4 py-3 bg-card/70 backdrop-blur-sm rounded-t-xl">
        <div className="flex items-center gap-2">
          <div className={cn("flex h-6 w-6 items-center justify-center rounded-md", meta.badgeBg, meta.badgeText)}>
            <Icon className="h-3.5 w-3.5" />
          </div>
          <div>
            <h3 className="font-bold text-sm text-foreground">{meta.title}</h3>
          </div>
        </div>

        <span className={cn("rounded-full px-2 py-0.5 font-mono text-xs font-bold border border-border", meta.badgeBg, meta.badgeText)}>
          {items.length}
        </span>
      </div>

      {/* Column Cards List */}
      <div className="flex flex-1 flex-col gap-2.5 overflow-y-auto custom-scrollbar p-3 max-h-[calc(100vh-17rem)] min-h-[220px]">
        {items.length === 0 ? (
          <div className={cn(
            "flex flex-1 flex-col items-center justify-center rounded-xl border border-dashed p-6 text-center transition-colors",
            isDropTarget ? "border-primary bg-primary/10 text-primary" : "border-border/70 text-muted-foreground"
          )}>
            <Icon className="h-6 w-6 opacity-40 mb-1" />
            <p className="text-xs font-semibold">{isDropTarget ? "Drop to transition" : "No findings"}</p>
            <p className="text-[10px] text-muted-foreground mt-0.5">{meta.description}</p>
          </div>
        ) : (
          items.map((row) => (
            <KanbanCard
              key={row.vuln_id}
              vuln={row}
              selected={row.vuln_id === selectedId}
              onSelect={() => onSelect(row.vuln_id)}
              onQuickMove={(target) => onQuickMove(row.vuln_id, target)}
            />
          ))
        )}
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// KANBAN CARD COMPONENT
// ----------------------------------------------------------------------------
function KanbanCard({
  vuln,
  selected,
  onSelect,
  onQuickMove,
}: {
  vuln: TrackedVulnerability;
  selected: boolean;
  onSelect: () => void;
  onQuickMove: (target: VulnLifecycleState) => void;
}) {
  const normSev = normalizeSeverity(vuln.severity);
  const possibleTransitions = legalTransitions(vuln.state);

  const sevBorderColor =
    normSev === "critical"
      ? "border-l-rose-500"
      : normSev === "high"
      ? "border-l-orange-500"
      : normSev === "medium"
      ? "border-l-amber-500"
      : "border-l-sky-500";

  return (
    <div
      draggable
      onDragStart={(e) => {
        e.dataTransfer.setData(
          DRAG_TYPE,
          JSON.stringify({ vulnId: vuln.vuln_id, from: vuln.state }),
        );
        e.dataTransfer.effectAllowed = "move";
      }}
      onClick={onSelect}
      className={cn(
        "group relative flex cursor-grab flex-col gap-2 rounded-xl border border-l-4 bg-card p-3.5 shadow-sm transition-all duration-150 active:cursor-grabbing hover:-translate-y-0.5 hover:shadow-md",
        sevBorderColor,
        selected
          ? "ring-2 ring-primary border-primary bg-primary/5 shadow-md"
          : "border-border hover:border-primary/40",
      )}
    >
      {/* Top Bar: Title / CVE + KEV / Score */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex-1">
          <p className="font-mono text-xs font-bold text-foreground leading-snug line-clamp-2">
            {findingLabel(vuln)}
          </p>
          {vuln.title && vuln.cve && (
            <p className="mt-0.5 text-[11px] text-muted-foreground line-clamp-1">
              {vuln.title}
            </p>
          )}
        </div>

        <div className="flex items-center gap-1 shrink-0">
          {vuln.in_kev && (
            <span
              title="Known Exploited Vulnerability (CISA KEV)"
              className="flex items-center gap-0.5 rounded bg-rose-500/15 px-1.5 py-0.5 font-mono text-[10px] font-bold text-rose-700 dark:text-rose-400 border border-rose-500/30"
            >
              <Flame className="h-3 w-3 text-rose-500" />
              KEV
            </span>
          )}
          {vuln.contextual_score !== null && vuln.contextual_score !== undefined && (
            <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] font-bold text-foreground border border-border">
              {vuln.contextual_score.toFixed(1)}
            </span>
          )}
        </div>
      </div>

      {/* Asset & Port Info */}
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground font-mono">
        <Server className="h-3 w-3 shrink-0 text-muted-foreground" />
        <span className="truncate max-w-[170px]" title={vuln.asset_id}>
          {vuln.asset_id}
        </span>
        {vuln.port ? (
          <span className="rounded bg-muted px-1 py-0.2 text-[10px] text-foreground border border-border">
            :{vuln.port}
          </span>
        ) : null}
      </div>

      {/* Badges Row: Severity + SLA */}
      <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
        <StatusBadge value={normSev} map={SEVERITY_STATUS} />
        <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} showDue={false} />
      </div>

      {/* Card Footer: Assignee + Ticket + Quick Move */}
      <div className="flex items-center justify-between border-t border-border/60 pt-2 text-[11px] text-muted-foreground">
        {/* Assignee */}
        <div className="flex items-center gap-1 truncate max-w-[130px]">
          <div className="flex h-4 w-4 items-center justify-center rounded-full bg-muted text-muted-foreground">
            <User className="h-2.5 w-2.5" />
          </div>
          <span className={vuln.assignee ? "font-medium text-foreground truncate" : "text-muted-foreground/80 italic"}>
            {vuln.assignee ? `@${vuln.assignee}` : "Unassigned"}
          </span>
        </div>

        {/* Ticket & Menu */}
        <div className="flex items-center gap-1.5">
          {vuln.ticket_key && (
            <span className="rounded bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-primary border border-primary/20">
              {vuln.ticket_key}
            </span>
          )}

          {/* Quick Transition Dropdown */}
          {possibleTransitions.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground"
                >
                  <MoreVertical className="h-3.5 w-3.5" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel className="text-xs">Quick Move</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {possibleTransitions.map((target) => (
                  <DropdownMenuItem
                    key={target}
                    onClick={(e) => {
                      e.stopPropagation();
                      onQuickMove(target);
                    }}
                    className="text-xs cursor-pointer"
                  >
                    &rarr; {VULN_TRANSITION_LABEL[target]}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// SLIDE-OVER FINDING DETAIL DRAWER
// ----------------------------------------------------------------------------
function VulnerabilityDrawer({
  vuln,
  open,
  onOpenChange,
}: {
  vuln: TrackedVulnerability | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { canOperate } = useAuthStore();
  const eventsQuery = useVulnerabilityEvents(vuln?.vuln_id ?? "", { limit: 20 });

  if (!vuln) return null;

  const normSev = normalizeSeverity(vuln.severity);

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col p-0 overflow-hidden bg-card w-full sm:max-w-xl">
        {/* Header */}
        <SheetHeader className="border-b border-border/80 p-6 pb-4">
          <div className="flex items-center gap-2">
            <StatusBadge value={vuln.state} map={VULN_LIFECYCLE_STATUS} />
            <StatusBadge value={normSev} map={SEVERITY_STATUS} />
            {vuln.in_kev && (
              <span className="flex items-center gap-1 rounded bg-rose-500/20 px-2 py-0.5 font-mono text-xs font-bold text-rose-600 dark:text-rose-400">
                <Flame className="h-3.5 w-3.5 text-rose-500" />
                CISA KEV
              </span>
            )}
          </div>
          <SheetTitle className="font-mono text-lg font-bold text-foreground mt-2 leading-tight">
            {findingLabel(vuln)}
          </SheetTitle>
          <SheetDescription className="text-xs text-muted-foreground font-mono">
            ID: {vuln.vuln_id}
          </SheetDescription>
        </SheetHeader>

        {/* Body Content */}
        <div className="flex-1 overflow-y-auto custom-scrollbar p-6 space-y-6">
          {/* Key Attributes Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-border bg-card p-3 shadow-sm">
              <p className="text-[10px] uppercase font-bold text-muted-foreground">Contextual Score</p>
              <p className="text-xl font-extrabold text-foreground mt-1">
                {vuln.contextual_score !== null ? vuln.contextual_score.toFixed(1) : "—"}
              </p>
            </div>

            <div className="rounded-xl border border-border bg-card p-3 shadow-sm">
              <p className="text-[10px] uppercase font-bold text-muted-foreground">Base CVSS</p>
              <p className="text-xl font-extrabold text-foreground mt-1">
                {vuln.cvss !== null ? vuln.cvss.toFixed(1) : "—"}
              </p>
            </div>

            <div className="rounded-xl border border-border bg-card p-3 shadow-sm">
              <p className="text-[10px] uppercase font-bold text-muted-foreground">SLA State</p>
              <div className="mt-1.5">
                <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} />
              </div>
            </div>
          </div>

          {/* Affected Target / Asset Information */}
          <div className="rounded-xl border border-border bg-muted/40 p-4 space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <Server className="h-3.5 w-3.5 text-sky-500" />
              Target Host & Service
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <div>
                <span className="text-muted-foreground">Asset:</span>{" "}
                <span className="font-bold text-foreground">{vuln.asset_id}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Port:</span>{" "}
                <span className="font-bold text-foreground">{vuln.port || "None / Host-level"}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Tenant:</span>{" "}
                <span className="text-foreground">{vuln.tenant_id}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Exposure:</span>{" "}
                <span className="text-foreground">{vuln.network_exposure || "internal"}</span>
              </div>
            </div>
          </div>

          {/* Operations Panel */}
          {canOperate ? (
            <div className="space-y-4 rounded-xl border border-border bg-card p-4 shadow-sm">
              <h4 className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-1.5">
                <Wrench className="h-3.5 w-3.5 text-primary" />
                Remediation Actions
              </h4>

              <Tabs defaultValue="move" className="w-full">
                <TabsList className="grid grid-cols-4 gap-1 bg-muted/80 p-1 border border-border rounded-lg">
                  <TabsTrigger value="move" className="text-xs">Move</TabsTrigger>
                  <TabsTrigger value="assign" className="text-xs">Assign</TabsTrigger>
                  <TabsTrigger value="comment" className="text-xs">Note</TabsTrigger>
                  <TabsTrigger value="ticket" className="text-xs">Ticket</TabsTrigger>
                </TabsList>

                <TabsContent value="move" className="mt-3">
                  <MoveForm vuln={vuln} />
                </TabsContent>
                <TabsContent value="assign" className="mt-3">
                  <AssignForm vuln={vuln} />
                </TabsContent>
                <TabsContent value="comment" className="mt-3">
                  <CommentForm vulnId={vuln.vuln_id} />
                </TabsContent>
                <TabsContent value="ticket" className="mt-3">
                  <TicketForm vuln={vuln} />
                </TabsContent>
              </Tabs>
            </div>
          ) : (
            <div className="rounded-xl border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
              Viewer mode: Workflow transitions and assignments require Operator permissions.
            </div>
          )}

          {/* Audit History Timeline */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
              <History className="h-3.5 w-3.5 text-sky-500" />
              Audit Trail
            </h4>
            <div className="rounded-xl border border-border bg-card p-4 shadow-sm">
              <VulnerabilityTimeline
                events={eventsQuery.data?.items ?? []}
                emptyMessage="No audit trail events recorded yet."
              />
            </div>
          </div>

          {/* Direct Finding Link */}
          <div className="pt-2">
            <Link
              href={vulnDetailHref(vuln.vuln_id, vuln.tenant_id)}
              className="inline-flex items-center gap-1.5 text-xs font-bold text-primary hover:underline"
            >
              Open Full Finding Dossier &rarr;
            </Link>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ----------------------------------------------------------------------------
// REMEDIATION FORMS
// ----------------------------------------------------------------------------
function MoveForm({ vuln }: { vuln: TrackedVulnerability }) {
  const mutation = useTransitionVulnerability(vuln.vuln_id);
  const options = legalTransitions(vuln.state);
  const [target, setTarget] = useState<VulnLifecycleState>(options[0] ?? vuln.state);
  const [note, setNote] = useState("");

  if (options.length === 0) {
    return <p className="text-xs text-muted-foreground">No further lifecycle transitions available.</p>;
  }

  return (
    <form
      className="space-y-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        mutation.mutate({ state: target, note: note.trim() || null });
      }}
    >
      <div className="space-y-1">
        <Label className="text-xs font-medium text-foreground">Target Stage</Label>
        <Select value={target} onValueChange={(val) => setTarget(val as VulnLifecycleState)}>
          <SelectTrigger className="h-9 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {options.map((st) => (
              <SelectItem key={st} value={st} className="text-xs">
                {VULN_TRANSITION_LABEL[st]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1">
        <Label className="text-xs font-medium text-foreground">Resolution Note / Context</Label>
        <Textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={2}
          placeholder="Details on the patch, workaround, or justification..."
          className="text-xs"
        />
      </div>

      <Button type="submit" size="sm" disabled={mutation.isPending} className="font-semibold text-xs">
        {mutation.isPending ? "Transitioning…" : `Move to ${VULN_TRANSITION_LABEL[target]}`}
      </Button>
    </form>
  );
}

function AssignForm({ vuln }: { vuln: TrackedVulnerability }) {
  const mutation = useAssignVulnerability(vuln.vuln_id);
  const [assignee, setAssignee] = useState(vuln.assignee ?? "");

  return (
    <form
      className="space-y-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        mutation.mutate({ assignee: assignee.trim() || null });
      }}
    >
      <div className="space-y-1">
        <Label className="text-xs font-medium text-foreground">Assignee Username</Label>
        <Input
          value={assignee}
          onChange={(e) => setAssignee(e.target.value)}
          placeholder="security-engineer or dev-lead"
          className="h-9 text-xs font-mono"
        />
      </div>
      <Button
        type="submit"
        size="sm"
        disabled={mutation.isPending}
        className="font-semibold text-xs"
      >
        {mutation.isPending ? "Saving…" : "Update Owner"}
      </Button>
    </form>
  );
}

function CommentForm({ vulnId }: { vulnId: string }) {
  const mutation = useCommentOnVulnerability(vulnId);
  const [note, setNote] = useState("");

  return (
    <form
      className="space-y-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        if (!note.trim()) return;
        mutation.mutate(note.trim(), { onSuccess: () => setNote("") });
      }}
    >
      <div className="space-y-1">
        <Label className="text-xs font-medium text-foreground">Audit Note</Label>
        <Textarea
          value={note}
          onChange={(e) => setNote(e.target.value)}
          rows={3}
          placeholder="Add findings note, reproduction steps, or verify status..."
          className="text-xs"
        />
      </div>
      <Button
        type="submit"
        size="sm"
        disabled={mutation.isPending}
        className="font-semibold text-xs"
      >
        {mutation.isPending ? "Posting…" : "Post Comment"}
      </Button>
    </form>
  );
}

function TicketForm({ vuln }: { vuln: TrackedVulnerability }) {
  const setMutation = useSetVulnerabilityTicket(vuln.vuln_id);
  const clearMutation = useClearVulnerabilityTicket(vuln.vuln_id);
  const [system, setSystem] = useState<TicketSystem>((vuln.ticket_system as TicketSystem) || "jira");
  const [key, setKey] = useState(vuln.ticket_key ?? "");
  const [url, setUrl] = useState(vuln.ticket_url ?? "");

  return (
    <form
      className="space-y-3"
      onSubmit={(e: FormEvent) => {
        e.preventDefault();
        setMutation.mutate({ system, key: key.trim() || null, url: url.trim() || null });
      }}
    >
      <div className="space-y-1">
        <Label className="text-xs font-medium text-foreground">Ticket Tracker</Label>
        <Select value={system} onValueChange={(val) => setSystem(val as TicketSystem)}>
          <SelectTrigger className="h-9 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {TICKET_SYSTEMS.map((sys) => (
              <SelectItem key={sys.value} value={sys.value} className="text-xs">
                {sys.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <div className="space-y-1">
          <Label className="text-xs font-medium text-foreground">Ticket Key</Label>
          <Input
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder="SEC-2041"
            className="h-9 text-xs font-mono"
          />
        </div>
        <div className="space-y-1">
          <Label className="text-xs font-medium text-foreground">Ticket URL</Label>
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://jira.corp/..."
            className="h-9 text-xs font-mono"
          />
        </div>
      </div>

      <div className="flex items-center gap-2 pt-1">
        <Button type="submit" size="sm" disabled={setMutation.isPending} className="font-semibold text-xs">
          {setMutation.isPending ? "Saving…" : "Save Linked Ticket"}
        </Button>
        {vuln.ticket_key || vuln.ticket_url ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={clearMutation.isPending}
            onClick={() => clearMutation.mutate()}
            className="text-xs"
          >
            Unlink
          </Button>
        ) : null}
      </div>
    </form>
  );
}
