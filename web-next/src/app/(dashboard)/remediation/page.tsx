"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Columns3, ExternalLink } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { VulnerabilityTimeline } from "@/components/vulnerability/timeline";
import { useAuthStore } from "@/lib/auth-store";
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

export default function RemediationPage() {
  const queryClient = useQueryClient();
  const openQuery = useTrackedVulnerabilities(
    { open_only: true },
    { limit: BOARD_OPEN_LIMIT, sort: "contextual_score", order: "desc" },
  );
  const closedQuery = useTrackedVulnerabilities(
    { state: "CLOSED" },
    { limit: BOARD_CLOSED_LIMIT, sort: "closed_at", order: "desc" },
  );
  const activityQuery = useVulnerabilityActivity({ limit: 20 });
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [dropTarget, setDropTarget] = useState<VulnLifecycleState | null>(null);
  const dropMutation = useMutation({
    mutationFn: ({ vulnId, state }: { vulnId: string; state: VulnLifecycleState }) =>
      transitionVulnerability(vulnId, { state }),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.vulnerability(updated.vuln_id), updated);
      void queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities });
      toast.success(`Moved to ${updated.state}`);
    },
    onError: (err) => {
      toast.error("Transition failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });

  const items = useMemo(
    () => [...(openQuery.data?.items ?? []), ...(closedQuery.data?.items ?? [])],
    [openQuery.data, closedQuery.data],
  );
  const byId = useMemo(() => new Map(items.map((row) => [row.vuln_id, row])), [items]);
  const grouped = useMemo(() => groupByState(items), [items]);
  const selected = items.find((row) => row.vuln_id === selectedId) ?? null;

  function handleDrop(vulnId: string, from: VulnLifecycleState, to: VulnLifecycleState) {
    const row = byId.get(vulnId);
    if (!row) return;
    if (!canDropOn(from, to)) {
      toast.error(`${row.state} cannot move to ${to}`);
      return;
    }
    dropMutation.mutate({ vulnId, state: to });
  }
  const truncated =
    (openQuery.data?.has_more ?? false) || (closedQuery.data?.has_more ?? false);
  const error = (openQuery.error || closedQuery.error) as Error | null;
  const loading = openQuery.isLoading || closedQuery.isLoading;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Columns3 className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">
              Remediation Board
            </h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Move a finding from detection to verified closure. Columns are the
            lifecycle states; accepted risk is a badge, not a seventh column.
            Tickets are links to Jira/ServiceNow/SMAX/DefectDojo — the platform
            does not open them (that is the 10.3 delivery queue).
          </p>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}
      {truncated ? (
        <Alert className="border-amber-500/30 bg-amber-950/30 text-amber-100">
          <AlertDescription className="text-xs">
            Showing {BOARD_OPEN_LIMIT} open and {BOARD_CLOSED_LIMIT} closed findings —{" "}
            <Link href="/vulnerabilities" className="font-semibold text-sky-300 underline">
              the full list
            </Link>{" "}
            is in Vulnerability Center.
          </AlertDescription>
        </Alert>
      ) : null}

      {loading ? (
        <p className="text-sm text-slate-400">Loading remediation board…</p>
      ) : (
        <div className="grid gap-4 xl:grid-cols-[1fr_20rem]">
          <div className="flex min-w-0 gap-3 overflow-x-auto pb-2">
            {VULN_STATES.map((state) => (
              <Column
                key={state}
                state={state}
                items={grouped[state]}
                selectedId={selectedId}
                isDropTarget={dropTarget === state}
                onSelect={setSelectedId}
                onDragEnter={() => setDropTarget(state)}
                onDragLeave={() => setDropTarget((current) => (current === state ? null : current))}
                onDropped={(vulnId, from) => {
                  setDropTarget(null);
                  handleDrop(vulnId, from, state);
                }}
              />
            ))}
          </div>
          <aside className="space-y-4">
            {selected ? (
              <CardPanel vuln={selected} onClose={() => setSelectedId(null)} />
            ) : (
              <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-4">
                <h2 className="text-sm font-semibold text-slate-100">Activity</h2>
                <div className="mt-3">
                  {activityQuery.isLoading ? (
                    <p className="text-xs text-slate-500">Loading…</p>
                  ) : (
                    <VulnerabilityTimeline
                      events={activityQuery.data?.items ?? []}
                      emptyMessage="No remediation activity yet."
                    />
                  )}
                </div>
              </section>
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

function Column({
  state,
  items,
  selectedId,
  isDropTarget,
  onSelect,
  onDragEnter,
  onDragLeave,
  onDropped,
}: {
  state: VulnLifecycleState;
  items: TrackedVulnerability[];
  selectedId: string | null;
  isDropTarget: boolean;
  onSelect: (id: string) => void;
  onDragEnter: () => void;
  onDragLeave: () => void;
  onDropped: (vulnId: string, from: VulnLifecycleState) => void;
}) {
  return (
    <section
      className={cn(
        "flex w-64 shrink-0 flex-col rounded-xl border bg-slate-950/60",
        isDropTarget ? "border-sky-500/60" : "border-slate-800/80",
      )}
      onDragOver={(event) => {
        event.preventDefault();
        onDragEnter();
      }}
      onDragLeave={onDragLeave}
      onDrop={(event) => {
        event.preventDefault();
        const raw = event.dataTransfer.getData(DRAG_TYPE);
        if (!raw) return;
        const payload = JSON.parse(raw) as { vulnId: string; from: VulnLifecycleState };
        onDropped(payload.vulnId, payload.from);
      }}
    >
      <header className="flex items-center justify-between border-b border-slate-800 px-3 py-2">
        <StatusBadge value={state} map={VULN_LIFECYCLE_STATUS} />
        <span className="font-mono text-[11px] text-slate-500">{items.length}</span>
      </header>
      <ul className="flex max-h-[70vh] flex-col gap-2 overflow-y-auto p-2">
        {items.length === 0 ? (
          <li className="px-1 py-6 text-center text-[11px] text-slate-600">Empty</li>
        ) : (
          items.map((row) => (
            <BoardCard
              key={row.vuln_id}
              vuln={row}
              selected={row.vuln_id === selectedId}
              onSelect={() => onSelect(row.vuln_id)}
            />
          ))
        )}
      </ul>
    </section>
  );
}

function BoardCard({
  vuln,
  selected,
  onSelect,
}: {
  vuln: TrackedVulnerability;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <li>
      <button
        type="button"
        draggable
        onDragStart={(event) => {
          event.dataTransfer.setData(
            DRAG_TYPE,
            JSON.stringify({ vulnId: vuln.vuln_id, from: vuln.state }),
          );
          event.dataTransfer.effectAllowed = "move";
        }}
        onClick={onSelect}
        className={cn(
          "w-full rounded-lg border p-2.5 text-left transition-colors",
          selected
            ? "border-sky-500/50 bg-slate-800/80"
            : "border-slate-800 bg-slate-900/80 hover:border-slate-700",
        )}
      >
        <p className="font-mono text-xs font-semibold text-sky-300">{findingLabel(vuln)}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <StatusBadge value={normalizeSeverity(vuln.severity)} map={SEVERITY_STATUS} />
          <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} showDue={false} />
        </div>
        <p className="mt-1.5 truncate text-[11px] text-slate-400">
          {vuln.assignee || "Unassigned"}
          {vuln.ticket_key ? ` · ${vuln.ticket_key}` : ""}
        </p>
      </button>
    </li>
  );
}

function CardPanel({ vuln, onClose }: { vuln: TrackedVulnerability; onClose: () => void }) {
  const { canOperate } = useAuthStore();
  const eventsQuery = useVulnerabilityEvents(vuln.vuln_id, { limit: 15 });

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-4 shadow-lg">
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="font-mono text-sm font-bold text-slate-100">{findingLabel(vuln)}</p>
          <p className="mt-0.5 font-mono text-[11px] text-slate-500">{vuln.vuln_id}</p>
        </div>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          className="h-7 px-2 text-slate-400"
          onClick={onClose}
        >
          Close
        </Button>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        <StatusBadge value={vuln.state} map={VULN_LIFECYCLE_STATUS} />
        <StatusBadge value={normalizeSeverity(vuln.severity)} map={SEVERITY_STATUS} />
        <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} />
      </div>
      <p className="mt-2 text-xs text-slate-400">
        Owner: {vuln.assignee || "unassigned"}
        {vuln.owner_team ? ` · ${vuln.owner_team}` : ""}
      </p>
      {vuln.last_seen_run_id ? (
        <p className="mt-1 text-[11px] text-slate-500">
          Evidence: last observing run{" "}
          <span className="font-mono text-slate-300">{vuln.last_seen_run_id}</span>
        </p>
      ) : null}
      <Link
        href={vulnDetailHref(vuln.vuln_id, vuln.tenant_id)}
        className="mt-2 inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
      >
        Full finding card
      </Link>

      {canOperate ? (
        <div className="mt-4 space-y-4 border-t border-slate-800 pt-4">
          <MoveForm vuln={vuln} />
          <AssignForm vuln={vuln} />
          <CommentForm vulnId={vuln.vuln_id} />
          <TicketForm vuln={vuln} />
        </div>
      ) : (
        <p className="mt-3 text-xs text-slate-500">Viewer role: moves and comments are hidden.</p>
      )}

      <div className="mt-4 border-t border-slate-800 pt-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Trail</h3>
        <div className="mt-2">
          <VulnerabilityTimeline events={eventsQuery.data?.items ?? []} />
        </div>
      </div>
    </section>
  );
}

function MoveForm({ vuln }: { vuln: TrackedVulnerability }) {
  const mutation = useTransitionVulnerability(vuln.vuln_id);
  const options = legalTransitions(vuln.state);
  const [target, setTarget] = useState<VulnLifecycleState>(options[0] ?? vuln.state);
  const [note, setNote] = useState("");

  if (options.length === 0) return null;

  return (
    <form
      className="space-y-2"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        mutation.mutate({ state: target, note: note.trim() || null });
      }}
    >
      <Label className="text-xs text-slate-400">Move to</Label>
      <Select value={target} onValueChange={(value) => setTarget(value as VulnLifecycleState)}>
        <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
          <SelectValue />
        </SelectTrigger>
        <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
          {options.map((state) => (
            <SelectItem key={state} value={state}>
              {VULN_TRANSITION_LABEL[state]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Textarea
        value={note}
        onChange={(event) => setNote(event.target.value)}
        rows={2}
        placeholder="Note (required when closing)"
        className="bg-slate-950 border-slate-800 text-slate-200"
      />
      <Button type="submit" size="sm" disabled={mutation.isPending} className="bg-sky-600 hover:bg-sky-500">
        {mutation.isPending ? "Moving…" : VULN_TRANSITION_LABEL[target]}
      </Button>
    </form>
  );
}

function AssignForm({ vuln }: { vuln: TrackedVulnerability }) {
  const mutation = useAssignVulnerability(vuln.vuln_id);
  const [assignee, setAssignee] = useState(vuln.assignee ?? "");
  return (
    <form
      className="space-y-2"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        mutation.mutate({ assignee: assignee.trim() || null });
      }}
    >
      <Label className="text-xs text-slate-400">Assignee</Label>
      <Input
        value={assignee}
        onChange={(event) => setAssignee(event.target.value)}
        className="bg-slate-950 border-slate-800 text-slate-200"
        placeholder="username"
      />
      <Button
        type="submit"
        size="sm"
        variant="outline"
        disabled={mutation.isPending}
        className="border-slate-700 bg-slate-950 text-slate-200"
      >
        {mutation.isPending ? "Saving…" : "Save owner"}
      </Button>
    </form>
  );
}

function CommentForm({ vulnId }: { vulnId: string }) {
  const mutation = useCommentOnVulnerability(vulnId);
  const [note, setNote] = useState("");
  return (
    <form
      className="space-y-2"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        if (!note.trim()) return;
        mutation.mutate(note.trim(), { onSuccess: () => setNote("") });
      }}
    >
      <Label className="text-xs text-slate-400">Comment</Label>
      <Textarea
        value={note}
        onChange={(event) => setNote(event.target.value)}
        rows={2}
        className="bg-slate-950 border-slate-800 text-slate-200"
      />
      <Button type="submit" size="sm" disabled={mutation.isPending} className="bg-indigo-600 hover:bg-indigo-500">
        {mutation.isPending ? "Posting…" : "Add comment"}
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
      className="space-y-2"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        setMutation.mutate({ system, key: key.trim() || null, url: url.trim() || null });
      }}
    >
      <Label className="text-xs text-slate-400">Linked ticket</Label>
      {vuln.ticket_url || vuln.ticket_key ? (
        <p className="text-xs text-slate-300">
          {vuln.ticket_url ? (
            <a
              href={vuln.ticket_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-sky-400 hover:underline"
            >
              {vuln.ticket_key || vuln.ticket_url}
              <ExternalLink className="h-3 w-3" />
            </a>
          ) : (
            <span className="font-mono">{vuln.ticket_key}</span>
          )}
        </p>
      ) : (
        <p className="text-[11px] text-slate-500">No ticket linked. Paste a key or URL — this does not create one.</p>
      )}
      <Select value={system} onValueChange={(value) => setSystem(value as TicketSystem)}>
        <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
          <SelectValue />
        </SelectTrigger>
        <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
          {TICKET_SYSTEMS.map((item) => (
            <SelectItem key={item.value} value={item.value}>
              {item.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Input
        value={key}
        onChange={(event) => setKey(event.target.value)}
        placeholder="SEC-123"
        className="bg-slate-950 border-slate-800 text-slate-200"
      />
      <Input
        value={url}
        onChange={(event) => setUrl(event.target.value)}
        placeholder="https://…"
        className="bg-slate-950 border-slate-800 text-slate-200"
      />
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={setMutation.isPending} className="bg-sky-600 hover:bg-sky-500">
          {setMutation.isPending ? "Saving…" : "Link ticket"}
        </Button>
        {vuln.ticket_key || vuln.ticket_url ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={clearMutation.isPending}
            onClick={() => clearMutation.mutate()}
            className="border-slate-700 bg-slate-950 text-slate-200"
          >
            Unlink
          </Button>
        ) : null}
      </div>
    </form>
  );
}
