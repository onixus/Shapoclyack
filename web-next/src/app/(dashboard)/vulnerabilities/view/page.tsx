"use client";

import Link from "next/link";
import { FormEvent, Suspense, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "next/navigation";
import { format, isValid, parseISO } from "date-fns";
import { ArrowLeft, EyeOff, RefreshCw, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
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
import { LifecycleStepper } from "@/components/vulnerability/lifecycle-stepper";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { VulnerabilityTimeline } from "@/components/vulnerability/timeline";
import { useAssetDetail } from "@/hooks/use-assets";
import { useRunVulns } from "@/hooks/use-runs";
import {
  useAssignVulnerability,
  useClearVulnerabilityException,
  useClearVulnerabilityFalsePositive,
  useClearVulnerabilityTicket,
  useCommentOnVulnerability,
  useDecideVulnerabilityException,
  useSetVulnerabilityException,
  useSetVulnerabilityFalsePositive,
  useSetVulnerabilityTicket,
  useSyncVulnTicket,
  useTrackedVulnerability,
  useTransitionVulnerability,
  useTriggerVulnVerification,
  useVulnerabilityEvents,
} from "@/hooks/use-vulnerabilities";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import type {
  TicketSystem,
  TrackedVulnerability,
  VulnLifecycleState,
  Vulnerability,
} from "@/lib/api";
import { TICKET_SYSTEMS } from "@/lib/remediation";
import { SEVERITY_STATUS, VULN_LIFECYCLE_STATUS } from "@/lib/config/statuses";
import { normalizeSeverity, runDetailHref } from "@/lib/run-data";
import { useT } from "@/lib/i18n";
import {
  assetDetailHref,
  findingLabel,
  legalTransitions,
  VULN_PRIMARY_NEXT,
  VULN_TRANSITION_LABEL,
} from "@/lib/vuln-lifecycle";

function formatWhen(value: string | null | undefined): string {
  if (!value) return "—";
  const parsed = parseISO(value);
  return isValid(parsed) ? format(parsed, "yyyy-MM-dd HH:mm") : value;
}

function matchRunFinding(
  tracked: TrackedVulnerability,
  items: Vulnerability[],
): Vulnerability | null {
  return (
    items.find((item) => {
      const portOk = !tracked.port || item.port === tracked.port;
      if (tracked.cve) return item.cve === tracked.cve && portOk;
      if (tracked.script_id) return item.script_id === tracked.script_id && portOk;
      return false;
    }) ?? null
  );
}

function BackToVulnerabilities() {
  return (
    <Button
      asChild
      variant="ghost"
      size="sm"
      className="gap-2 px-0 text-slate-400 hover:text-slate-100 hover:bg-transparent"
    >
      <Link href="/vulnerabilities">
        <ArrowLeft className="h-4 w-4 text-sky-400" />
        Back to Vulnerability Center
      </Link>
    </Button>
  );
}

export default function VulnerabilityDetailPage() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading vulnerability…</p>}>
      <VulnerabilityDetailInner />
    </Suspense>
  );
}

/** Render a stored ``closure_reason`` in the viewer's language.
 *
 * Unknown values pass through: the column is a plain string, so a reason a
 * future release adds should read as itself rather than as a missing key. */
function closureReasonLabel(t: ReturnType<typeof useT>, reason: string): string {
  switch (reason) {
    case "verified_remediated":
      return t("vuln.reason.verifiedRemediated");
    case "manual":
      return t("vuln.reason.manual");
    case "ticket_resolved":
      return t("vuln.reason.ticketResolved");
    case "patched":
      return t("vuln.reason.patched");
    case "false_positive":
      return t("vuln.reason.falsePositive");
    default:
      return reason;
  }
}

function VulnerabilityDetailInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const vulnId = (searchParams.get("vulnId") || "").trim();
  const tenantId = searchParams.get("tenantId") || "default";
  const { canOperate, user } = useAuthStore();
  const isAdmin = user?.role === "admin";
  // Accepted risk is two permissions held by two different people (#348), and
  // neither of them is the *global* role: `risk-approver` is a membership of
  // this tenant and is a plain `viewer` globally, so gating the panel on
  // `isAdmin` showed it to the one person the API refuses (the tenant admin
  // who filed the request) and hid it from the only person who can answer.
  // The fallbacks keep the old behaviour on an API that predates #318.
  const canApproveException = holdsPermission(
    user,
    "vulnerability.exception.approve",
    isAdmin,
  );
  const canRequestException = (user?.tenant_role ?? user?.role) === "admin";

  const detailQuery = useTrackedVulnerability(vulnId || null);
  const eventsQuery = useVulnerabilityEvents(vulnId || null, { limit: 50 });
  const vuln = detailQuery.data;

  const assetQuery = useAssetDetail(vuln?.asset_id ?? null, tenantId);
  const asset = assetQuery.data;
  const ip =
    asset?.identifiers.find((item) => item.identifier_type === "ip")?.identifier_value ?? null;
  const runVulnsQuery = useRunVulns(vuln?.last_seen_run_id ?? "", {
    host: ip,
    port: vuln?.port,
  });
  const observation = useMemo(
    () => (vuln ? matchRunFinding(vuln, runVulnsQuery.data ?? []) : null),
    [vuln, runVulnsQuery.data],
  );

  if (!vulnId) {
    return (
      <div className="space-y-4">
        <BackToVulnerabilities />
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>Missing vulnId query parameter.</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (detailQuery.isLoading || !vuln) {
    if (detailQuery.error) {
      return (
        <div className="space-y-4">
          <BackToVulnerabilities />
          <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
            <AlertDescription>{(detailQuery.error as Error).message}</AlertDescription>
          </Alert>
        </div>
      );
    }
    return <p className="text-sm text-slate-400">Loading tracked finding…</p>;
  }

  const assetName =
    asset?.identifiers.find((item) => item.identifier_type === "ip")?.identifier_value ||
    asset?.identifiers[0]?.identifier_value ||
    vuln.asset_id;

  return (
    <div className="space-y-6">
      <div className="space-y-3 border-b border-slate-800/80 pb-5">
        <BackToVulnerabilities />
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-extrabold font-mono tracking-tight text-slate-100">
                {findingLabel(vuln)}
              </h1>
              <StatusBadge value={normalizeSeverity(vuln.severity)} map={SEVERITY_STATUS} />
              <StatusBadge value={vuln.state} map={VULN_LIFECYCLE_STATUS} />
              <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} />
              {vuln.machine_verified ? (
                <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 flex items-center gap-1 text-xs">
                  <ShieldCheck className="h-3 w-3" /> {t("vuln.machineVerified")}
                </Badge>
              ) : null}
              {vuln.closure_reason ? (
                <Badge variant="outline" className="border-slate-700 text-slate-300 text-xs">
                  {t("vuln.closureReason")}: {closureReasonLabel(t, vuln.closure_reason)}
                </Badge>
              ) : null}
              {/* The suppression, not the verdict: a lapsed verdict leaves the
                  closure reason in place but stops holding the finding down, and
                  the difference is the whole point of the expiry. */}
              {vuln.fp_suppressed ? (
                <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/40 flex items-center gap-1 text-xs">
                  <EyeOff className="h-3 w-3" />
                  {t("vuln.fp.suppressedUntil", { when: formatWhen(vuln.fp_suppress_until) })}
                </Badge>
              ) : null}
            </div>
            {vuln.title && vuln.title !== findingLabel(vuln) ? (
              <p className="text-sm text-slate-300">{vuln.title}</p>
            ) : null}
            <p className="font-mono text-xs text-slate-400">
              {vuln.vuln_id}
              {vuln.port ? ` · port ${vuln.port}` : ""}
            </p>
          </div>
        </div>
        <LifecycleStepper state={vuln.state} />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          {canOperate ? <TransitionCard key={vuln.state} vuln={vuln} /> : null}
          {canOperate ? (
            <AssignCard key={`${vuln.assignee}:${vuln.owner_team}`} vuln={vuln} />
          ) : null}
          {canOperate ? <CommentCard vulnId={vuln.vuln_id} /> : null}
          {canOperate ? <TicketCard vuln={vuln} /> : null}
          {canRequestException || canApproveException ? (
            <ExceptionCard
              vuln={vuln}
              canRequest={canRequestException}
              canApprove={canApproveException}
              username={user?.username ?? null}
            />
          ) : null}
          {isAdmin ? <FalsePositiveCard vuln={vuln} /> : null}
          {!canOperate && !isAdmin && !canApproveException ? (
            <p className="text-xs text-slate-500">
              Viewer role: lifecycle, assignment and risk-acceptance actions are hidden.
            </p>
          ) : null}
        </div>

        <div className="lg:col-span-2 space-y-6">
          <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
            <h2 className="text-sm font-semibold text-slate-100">Finding</h2>
            <dl className="mt-4 grid gap-4 sm:grid-cols-2 text-xs">
              <Field label="CVE" value={vuln.cve || "—"} mono />
              <Field
                label="CWE"
                value={vuln.cwe?.length ? vuln.cwe.join(", ") : "—"}
                hint={
                  vuln.cwe?.length
                    ? "From NVD (cvss4 overlay) or nuclei classification on the last observation"
                    : "NVD/nuclei did not name a CWE; not inferred from the CVE id"
                }
              />
              <Field label="Detection source" value={vuln.script_id || "—"} mono />
              <Field
                label={t("vuln.source")}
                value={
                  vuln.source === "endpoint_software"
                    ? t("vuln.source.endpointSoftware")
                    : t("vuln.source.scan")
                }
                hint={
                  vuln.source === "endpoint_software"
                    ? t("vuln.software.noVerify")
                    : undefined
                }
              />
              {/* A software finding has no port by construction — its locator
                  is the endpoint and the package named in the title. */}
              {vuln.source === "endpoint_software" ? (
                <Field label={t("vuln.software.device")} value={vuln.device_id || "—"} mono />
              ) : (
                <Field label="Port" value={vuln.port || "—"} mono />
              )}
              <Field label="CVSS" value={vuln.cvss != null ? String(vuln.cvss) : "—"} />
              <Field
                label="EPSS"
                value={observation?.epss != null ? `${Math.round(observation.epss * 100)}%` : "—"}
                hint={observation ? undefined : "From the last observing run, when present"}
              />
              <Field label="KEV" value={observation ? (observation.in_kev ? "Yes" : "No") : "—"} />
              <Field label="Risk level" value={vuln.risk_level || "—"} />
              <Field
                label="Contextual score"
                value={vuln.contextual_score != null ? vuln.contextual_score.toFixed(1) : "—"}
              />
              <Field
                label="Asset"
                value={
                  <Link
                    href={assetDetailHref(vuln.asset_id, vuln.tenant_id)}
                    className="font-mono text-sky-400 hover:underline"
                  >
                    {assetName}
                  </Link>
                }
              />
              <Field label="Owner" value={vuln.assignee || "Unassigned"} />
              <Field label="Team" value={vuln.owner_team || "—"} />
              <Field
                label="Ticket"
                value={
                  vuln.ticket_url ? (
                    <a
                      href={vuln.ticket_url}
                      target="_blank"
                      rel="noreferrer"
                      className="font-mono text-sky-400 hover:underline"
                    >
                      {vuln.ticket_key || vuln.ticket_url}
                    </a>
                  ) : (
                    vuln.ticket_key || "—"
                  )
                }
              />
              <Field label="First seen" value={formatWhen(vuln.first_seen_at)} />
              <Field label="Last seen" value={formatWhen(vuln.last_seen_at)} />
              <Field label="Observations" value={String(vuln.observation_count)} />
              <Field label="Reopens" value={String(vuln.reopen_count)} />
              <Field label="Machine verified" value={vuln.machine_verified ? "Yes (Re-scan confirmed)" : "No"} />
              {vuln.closure_reason ? <Field label="Closure reason" value={vuln.closure_reason} /> : null}
              {vuln.last_verified_at ? <Field label="Last verified" value={formatWhen(vuln.last_verified_at)} /> : null}
              <Field
                label="SLA"
                value={`${vuln.sla_days ?? "—"} days${vuln.sla_source ? ` · ${vuln.sla_source}` : ""}`}
              />
              <Field label="Due" value={formatWhen(vuln.due_at)} />
              <Field
                label="First run"
                value={
                  vuln.first_seen_run_id ? (
                    <Link
                      href={runDetailHref(vuln.first_seen_run_id)}
                      className="font-mono text-sky-400 hover:underline"
                    >
                      {vuln.first_seen_run_id}
                    </Link>
                  ) : (
                    "—"
                  )
                }
              />
              <Field
                label="Last run"
                value={
                  vuln.last_seen_run_id ? (
                    <Link
                      href={runDetailHref(vuln.last_seen_run_id)}
                      className="font-mono text-sky-400 hover:underline"
                    >
                      {vuln.last_seen_run_id}
                    </Link>
                  ) : (
                    "—"
                  )
                }
              />
            </dl>
          </section>

          <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
            <h2 className="text-sm font-semibold text-slate-100">Evidence</h2>
            {observation?.risk_explanation ? (
              <p className="mt-3 text-sm text-slate-200">{observation.risk_explanation}</p>
            ) : (
              <p className="mt-3 text-xs text-slate-500">
                No risk explanation on the last observation
                {vuln.last_seen_run_id ? (
                  <>
                    . Open the{" "}
                    <Link
                      href={runDetailHref(vuln.last_seen_run_id)}
                      className="text-sky-400 hover:underline"
                    >
                      last seeing run
                    </Link>{" "}
                    for the raw finding.
                  </>
                ) : (
                  "."
                )}
              </p>
            )}
            {observation?.cisa_decision ? (
              <p className="mt-2 text-xs text-slate-400">
                CISA decision:{" "}
                <span className="font-semibold text-slate-200">{observation.cisa_decision}</span>
              </p>
            ) : null}
          </section>

          <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
            <h2 className="text-sm font-semibold text-slate-100">Audit trail</h2>
            <div className="mt-4">
              {eventsQuery.isLoading ? (
                <p className="text-xs text-slate-500">Loading events…</p>
              ) : eventsQuery.error ? (
                <p className="text-xs text-rose-300">{(eventsQuery.error as Error).message}</p>
              ) : (
                <VulnerabilityTimeline events={eventsQuery.data?.items ?? []} />
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  value,
  mono,
  hint,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  hint?: string;
}) {
  return (
    <div>
      <dt className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={mono ? "mt-1 font-mono text-slate-200" : "mt-1 text-slate-200"} title={hint}>
        {value}
      </dd>
    </div>
  );
}

function TransitionCard({ vuln }: { vuln: TrackedVulnerability }) {
  const t = useT();
  const mutation = useTransitionVulnerability(vuln.vuln_id);
  const verifyMutation = useTriggerVulnVerification(vuln.vuln_id);
  const options = legalTransitions(vuln.state);
  const primary = VULN_PRIMARY_NEXT[vuln.state];
  const [target, setTarget] = useState<VulnLifecycleState>(
    options.includes(primary) ? primary : options[0],
  );
  const [note, setNote] = useState("");

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    mutation.mutate({ state: target, note: note.trim() || null });
  }

  if (options.length === 0) return null;

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-slate-100">Move lifecycle</h2>
        <form onSubmit={onSubmit} className="mt-3 space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="vuln-next-state" className="text-xs text-slate-400">
              Next state
            </Label>
            <Select value={target} onValueChange={(value) => setTarget(value as VulnLifecycleState)}>
              <SelectTrigger
                id="vuln-next-state"
                className="bg-slate-950 border-slate-800 text-slate-200"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                {options.map((state) => (
                  <SelectItem key={state} value={state}>
                    {VULN_TRANSITION_LABEL[state]} ({state})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="vuln-note" className="text-xs text-slate-400">
              Note {target === "CLOSED" ? "(recommended)" : "(optional)"}
            </Label>
            <Textarea
              id="vuln-note"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              rows={3}
              className="bg-slate-950 border-slate-800 text-slate-200"
              placeholder={
                target === "CLOSED"
                  ? "Why this is closed — false positive, fixed, decommissioned…"
                  : "Optional context for the audit trail"
              }
            />
          </div>
          <Button
            type="submit"
            size="sm"
            disabled={mutation.isPending}
            className="bg-sky-600 hover:bg-sky-500"
          >
            {mutation.isPending ? "Moving…" : VULN_TRANSITION_LABEL[target]}
          </Button>
        </form>
      </div>

      {/* A software finding is verified by its endpoint's next inventory
          snapshot: a re-scan does not observe an installed package, and the API
          refuses the dispatch with a 409 for exactly that reason. Offering a
          button that cannot work is worse than offering none. */}
      {vuln.source === "endpoint_software" ? (
        <div className="border-t border-slate-800/80 pt-3 space-y-1">
          <h3 className="text-xs font-semibold text-slate-300">Automated verification</h3>
          <p className="text-[11px] text-slate-400">{t("vuln.software.noVerify")}</p>
          <p className="text-[11px] text-slate-500">
            {t("vuln.software.lastSnapshot")}: {formatWhen(vuln.last_seen_at)}
          </p>
        </div>
      ) : (vuln.state === "FIXING" || vuln.state === "VERIFYING") ? (
        <div className="border-t border-slate-800/80 pt-3 space-y-2">
          <h3 className="text-xs font-semibold text-slate-300">Automated verification</h3>
          <p className="text-[11px] text-slate-400">
            Dispatch a targeted re-scan against this asset to verify remediation.
          </p>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={verifyMutation.isPending}
            onClick={() => verifyMutation.mutate()}
            className="w-full border-sky-500/40 bg-sky-950/30 text-sky-300 hover:bg-sky-900/40 gap-1.5"
          >
            <ShieldCheck className="h-4 w-4" />
            {verifyMutation.isPending
              ? t("vuln.verifyingInProgress")
              : t("vuln.verifyBtn")}
          </Button>
        </div>
      ) : null}
    </section>
  );
}

function AssignCard({ vuln }: { vuln: TrackedVulnerability }) {
  const mutation = useAssignVulnerability(vuln.vuln_id);
  const [assignee, setAssignee] = useState(vuln.assignee ?? "");
  const [ownerTeam, setOwnerTeam] = useState(vuln.owner_team ?? "");

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    mutation.mutate({
      assignee: assignee.trim() || null,
      owner_team: ownerTeam.trim() || null,
    });
  }

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg">
      <h2 className="text-sm font-semibold text-slate-100">Ownership</h2>
      <form onSubmit={onSubmit} className="mt-3 space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="vuln-assignee" className="text-xs text-slate-400">
            Assignee
          </Label>
          <Input
            id="vuln-assignee"
            value={assignee}
            onChange={(event) => setAssignee(event.target.value)}
            className="bg-slate-950 border-slate-800 text-slate-200"
            placeholder="username or email"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vuln-team" className="text-xs text-slate-400">
            Owner team
          </Label>
          <Input
            id="vuln-team"
            value={ownerTeam}
            onChange={(event) => setOwnerTeam(event.target.value)}
            className="bg-slate-950 border-slate-800 text-slate-200"
            placeholder="queue or team name"
          />
        </div>
        <Button
          type="submit"
          size="sm"
          variant="outline"
          disabled={mutation.isPending}
          className="border-slate-700 bg-slate-950 text-slate-200 hover:bg-slate-800"
        >
          {mutation.isPending ? "Saving…" : "Save owner"}
        </Button>
      </form>
    </section>
  );
}

function CommentCard({ vulnId }: { vulnId: string }) {
  const mutation = useCommentOnVulnerability(vulnId);
  const [note, setNote] = useState("");
  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!note.trim()) return;
    mutation.mutate(note.trim(), { onSuccess: () => setNote("") });
  }
  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg">
      <h2 className="text-sm font-semibold text-slate-100">Comment</h2>
      <form onSubmit={onSubmit} className="mt-3 space-y-3">
        <Textarea
          value={note}
          onChange={(event) => setNote(event.target.value)}
          rows={3}
          className="bg-slate-950 border-slate-800 text-slate-200"
          required
        />
        <Button type="submit" size="sm" disabled={mutation.isPending} className="bg-indigo-600 hover:bg-indigo-500">
          {mutation.isPending ? "Posting…" : "Add comment"}
        </Button>
      </form>
    </section>
  );
}

function TicketCard({ vuln }: { vuln: TrackedVulnerability }) {
  const t = useT();
  const setMutation = useSetVulnerabilityTicket(vuln.vuln_id);
  const clearMutation = useClearVulnerabilityTicket(vuln.vuln_id);
  const syncMutation = useSyncVulnTicket(vuln.vuln_id);
  const [system, setSystem] = useState<TicketSystem>((vuln.ticket_system as TicketSystem) || "jira");
  const [key, setKey] = useState(vuln.ticket_key ?? "");
  const [url, setUrl] = useState(vuln.ticket_url ?? "");
  function onSubmit(event: FormEvent) {
    event.preventDefault();
    setMutation.mutate({ system, key: key.trim() || null, url: url.trim() || null });
  }
  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-100">Ticket link</h2>
        {vuln.ticket_key ? (
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={syncMutation.isPending}
            onClick={() => syncMutation.mutate()}
            className="text-xs text-sky-400 hover:text-sky-300 gap-1 h-7 px-2"
          >
            <RefreshCw className={`h-3 w-3 ${syncMutation.isPending ? "animate-spin" : ""}`} />
            {t("vuln.syncTicketBtn")}
          </Button>
        ) : null}
      </div>
      <p className="mt-1 text-[11px] text-slate-500">
        Records where the work lives. Transitions are pushed to the ticket immediately; the
        ticket&apos;s own status is read back on a cadence, and Sync reads it now.
      </p>
      {vuln.ticket_sync_error ? (
        // A link that has stopped working — a renamed key, a revoked token —
        // is otherwise only in the worker's log, which is where "why is this
        // finding not updating?" goes unanswered.
        <p className="mt-2 rounded-md border border-amber-900/60 bg-amber-950/40 px-2 py-1 text-[11px] text-amber-300">
          Last read failed: {vuln.ticket_sync_error}
        </p>
      ) : null}
      <form onSubmit={onSubmit} className="mt-3 space-y-3">
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
    </section>
  );
}

/** Accepted risk, which since #348 is two decisions by two people: this card
 * asks, and whoever holds `vulnerability.exception.approve` answers. The panel
 * has to say which of the two states the finding is in — a request that looked
 * like an acceptance would tell an operator their SLA had stopped when it is
 * still running.
 *
 * `canRequest` and `canApprove` are separate props because the two halves are
 * for different people and only rarely for the same one: the approver may not
 * ask, the requester may not sign, and neither is told anything useful by a
 * button the API will answer with 403. */
function ExceptionCard({
  vuln,
  canRequest,
  canApprove,
  username,
}: {
  vuln: TrackedVulnerability;
  canRequest: boolean;
  canApprove: boolean;
  username: string | null;
}) {
  const setMutation = useSetVulnerabilityException(vuln.vuln_id);
  const clearMutation = useClearVulnerabilityException(vuln.vuln_id);
  const decideMutation = useDecideVulnerabilityException(vuln.vuln_id);
  const [until, setUntil] = useState("");
  const [reason, setReason] = useState(
    vuln.exception_requested_reason ?? vuln.exception_reason ?? "",
  );
  const pending = vuln.exception_state === "exception_requested";
  // Whose request it is decides who may answer it, and the API compares the
  // names case-insensitively — so does this, or the requester keeps a button
  // that only ever returns "cannot approve".
  const ownRequest =
    !!username &&
    (vuln.exception_requested_by ?? "").trim().toLowerCase() === username.trim().toLowerCase();
  const canDecide = canApprove && pending && !ownRequest;
  // The window against the clock, not against the workflow state: the sweep
  // that writes `exception_expired` runs on the worker's tick, and until it
  // does an acceptance that ran out an hour ago still reads `exception_approved`.
  const lapsed =
    !!vuln.exception_until && new Date(vuln.exception_until).getTime() <= Date.now();
  const inForce = !!vuln.exception_until && !lapsed;

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!until || !reason.trim()) return;
    const iso = new Date(until).toISOString();
    setMutation.mutate({ until: iso, reason: reason.trim() });
  }

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg">
      <h2 className="text-sm font-semibold text-slate-100">Accepted risk</h2>
      {inForce ? (
        <p className="mt-2 text-xs text-slate-400">
          In force until <span className="text-slate-200">{formatWhen(vuln.exception_until)}</span>
          {vuln.exception_by ? (
            <>
              {" "}
              · by <span className="font-mono text-slate-300">{vuln.exception_by}</span>
            </>
          ) : null}
        </p>
      ) : lapsed ? (
        <p className="mt-2 text-xs text-amber-300">
          The acceptance lapsed on {formatWhen(vuln.exception_until)} and the finding is back
          under its deadline.
        </p>
      ) : vuln.exception_state === "exception_rejected" ? (
        <p className="mt-2 text-xs text-amber-300">
          Last request rejected
          {vuln.exception_decided_by ? (
            <>
              {" "}
              by <span className="font-mono text-slate-300">{vuln.exception_decided_by}</span>
            </>
          ) : null}
          . The deadline never moved.
        </p>
      ) : (
        <p className="mt-2 text-xs text-slate-500">
          No exception. Both expiry and reason are required, and a second person has to approve.
        </p>
      )}
      {pending ? (
        <p className="mt-2 text-xs text-sky-300">
          Requested by <span className="font-mono">{vuln.exception_requested_by ?? "—"}</span>{" "}
          until {formatWhen(vuln.exception_requested_until)} · waiting for approval. The SLA
          clock is still running.
        </p>
      ) : null}
      {vuln.exception_reason ? (
        <p className="mt-2 text-xs text-slate-300">{vuln.exception_reason}</p>
      ) : null}
      {/* What is being asked for now, kept apart from the justification that
          was approved — they are different texts while an extension waits. */}
      {pending && vuln.exception_requested_reason ? (
        <p className="mt-2 text-xs text-slate-400">{vuln.exception_requested_reason}</p>
      ) : null}
      {pending && !canDecide ? (
        <p className="mt-2 text-xs text-slate-500">
          {ownRequest
            ? "Your own request: it needs a second pair of eyes, so somebody holding vulnerability.exception.approve has to answer it."
            : "Waiting for somebody holding vulnerability.exception.approve."}
        </p>
      ) : null}
      {canDecide ? (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            disabled={decideMutation.isPending}
            onClick={() => decideMutation.mutate({ decision: "approve" })}
            className="bg-emerald-600 hover:bg-emerald-500"
          >
            Approve
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={decideMutation.isPending}
            onClick={() => decideMutation.mutate({ decision: "reject" })}
            className="border-slate-700 bg-slate-950 text-slate-200 hover:bg-slate-800"
          >
            Reject
          </Button>
        </div>
      ) : null}
      {canRequest ? (
      <form onSubmit={onSubmit} className="mt-3 space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="vuln-until" className="text-xs text-slate-400">
            Until
          </Label>
          <Input
            id="vuln-until"
            type="datetime-local"
            value={until}
            onChange={(event) => setUntil(event.target.value)}
            className="bg-slate-950 border-slate-800 text-slate-200"
            required
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vuln-reason" className="text-xs text-slate-400">
            Reason
          </Label>
          <Textarea
            id="vuln-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            rows={3}
            className="bg-slate-950 border-slate-800 text-slate-200"
            required
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            size="sm"
            disabled={setMutation.isPending}
            className="bg-indigo-600 hover:bg-indigo-500"
          >
            {setMutation.isPending ? "Saving…" : "Request acceptance"}
          </Button>
          {vuln.exception_until || pending ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={clearMutation.isPending}
              onClick={() => clearMutation.mutate()}
              className="border-slate-700 bg-slate-950 text-slate-200 hover:bg-slate-800"
            >
              {clearMutation.isPending ? "Withdrawing…" : "Withdraw"}
            </Button>
          ) : null}
        </div>
      </form>
      ) : null}
    </section>
  );
}

/** Setting a verdict is ``admin``; withdrawing one is ``operator``, and the
 * card is rendered under ``isAdmin`` only because withdrawing is reachable from
 * the lifecycle actions an operator already has. The asymmetry is the API's:
 * a suppression can hide a real finding, releasing one only adds work back. */
function FalsePositiveCard({ vuln }: { vuln: TrackedVulnerability }) {
  const t = useT();
  const setMutation = useSetVulnerabilityFalsePositive(vuln.vuln_id);
  const clearMutation = useClearVulnerabilityFalsePositive(vuln.vuln_id);
  const [reason, setReason] = useState(vuln.fp_reason ?? "");
  const [days, setDays] = useState("90");
  // The closure, not the leftover columns. `fp_reason` is dropped when a
  // finding is re-opened, but reading it was how an *open* finding came to
  // render "Suppressed until 2027" with a Withdraw button behind it — and the
  // API answered that button with a 200 that changed nothing. A lapsed verdict
  // is still a verdict on a closed finding, so the expiry is deliberately not
  // part of this test; `fp_suppressed` says whether it is still holding.
  const marked = vuln.state === "CLOSED" && vuln.closure_reason === "false_positive";

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    const suppressDays = Number(days);
    if (!reason.trim() || !Number.isFinite(suppressDays)) return;
    setMutation.mutate({ reason: reason.trim(), suppress_days: suppressDays });
  }

  return (
    <section className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg">
      <h2 className="text-sm font-semibold text-slate-100">{t("vuln.fp.title")}</h2>
      {marked ? (
        <p className="mt-2 text-xs text-slate-400">
          {vuln.fp_suppressed
            ? t("vuln.fp.suppressedUntil", { when: formatWhen(vuln.fp_suppress_until) })
            : t("vuln.fp.lapsed")}
          {vuln.fp_marked_by ? (
            <>
              {" "}
              · <span className="font-mono text-slate-300">{vuln.fp_marked_by}</span>
            </>
          ) : null}
          {vuln.fp_observations ? (
            <> · {t("vuln.fp.observations", { count: vuln.fp_observations })}</>
          ) : null}
        </p>
      ) : (
        <p className="mt-2 text-xs text-slate-500">{t("vuln.fp.hint")}</p>
      )}
      {marked && vuln.fp_reason ? (
        <p className="mt-2 text-xs text-slate-300">{vuln.fp_reason}</p>
      ) : null}
      <form onSubmit={onSubmit} className="mt-3 space-y-3">
        <div className="space-y-1.5">
          <Label htmlFor="vuln-fp-reason" className="text-xs text-slate-400">
            {t("vuln.fp.reason")}
          </Label>
          <Textarea
            id="vuln-fp-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            rows={3}
            className="bg-slate-950 border-slate-800 text-slate-200"
            required
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="vuln-fp-days" className="text-xs text-slate-400">
            {t("vuln.fp.suppressDays")}
          </Label>
          <Input
            id="vuln-fp-days"
            type="number"
            min={1}
            max={365}
            value={days}
            onChange={(event) => setDays(event.target.value)}
            className="bg-slate-950 border-slate-800 text-slate-200"
            required
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button
            type="submit"
            size="sm"
            disabled={setMutation.isPending}
            className="bg-amber-600 hover:bg-amber-500"
          >
            {setMutation.isPending ? t("vuln.fp.saving") : t("vuln.fp.markBtn")}
          </Button>
          {marked ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={clearMutation.isPending}
              onClick={() => clearMutation.mutate()}
              className="border-slate-700 bg-slate-950 text-slate-200 hover:bg-slate-800"
            >
              {clearMutation.isPending ? t("vuln.fp.saving") : t("vuln.fp.clearBtn")}
            </Button>
          ) : null}
        </div>
      </form>
    </section>
  );
}
