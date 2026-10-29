"use client";
import { scanIntentLabel, scanModeLabel } from "@/lib/scan-labels";
import { ScanTechnicalDetails } from "@/components/scans/scan-technical-details";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Globe2, Layers, Play, ShieldCheck, TriangleAlert } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { CheckboxOption, Field, FieldGrid, fieldHintId } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { useAgentGroups } from "@/hooks/use-agent-groups";
import { useStartScan } from "@/hooks/use-jobs";
import { useSystemStatus } from "@/hooks/use-system";
import { useWordlists } from "@/hooks/use-wordlists";
import {
  fetchScopeTargets,
  type JobInfo,
  type ScanIntent,
  type ScopeTargetSkipped,
  type ScopeTargets,
  type StartScanBody,
} from "@/lib/api";
import { useT } from "@/lib/i18n";
import { queryKeys } from "@/lib/query-keys";
import { classifyTargets, splitTargetLines, type ScanSurface } from "@/lib/scan-surface";
import { cn } from "@/lib/utils";

const NO_INTENT = "__none__";
const NO_WORDLIST = "__none__";
// "Let the server decide" — either any agent of the tenant, or the one group
// the approved scope permits for these targets (#361).
const ANY_AGENT_GROUP = "__any__";

const INTENTS_BY_SURFACE: Record<"external" | "internal" | "all", Array<ScanIntent | "">> = {
  external: ["inventory", "vuln", "full", "delta", "org_profile", ""],
  internal: ["inventory", "vuln", "full", "delta", ""],
  all: ["inventory", "vuln", "full", "delta", "org_profile", ""],
};

/** What a "fill from scope" button fills: both fields, or one of them. */
export type ScopeFillSlot = "all" | "domains" | "ranges";

/**
 * Which of the approved scope's targets one fill button puts where, on a
 * launcher of `family`. A field left `undefined` is not touched.
 *
 * Ranges follow the page: the server tags each with the surface a scan of it
 * faces, and a private range typed into the external launcher is exactly the
 * mismatch the form warns about. A name is always external evidence there
 * (api/services/scan_surface.py), so "everything" on the internal page is its
 * private ranges — the domains button still fills names on purpose, for an
 * operator whose internal estate has them.
 */
export function scopeFill(
  found: ScopeTargets,
  slot: ScopeFillSlot,
  family: "external" | "internal" | "all",
): {
  domains?: string[];
  ranges?: string[];
  /** Ranges in scope that belong on the other surface's page. */
  otherSurface: number;
  skipped: ScopeTargetSkipped[];
} {
  const wantsDomains = slot === "domains" || (slot === "all" && family !== "internal");
  const wantsRanges = slot === "ranges" || slot === "all";
  const cidrs = found.targets.filter((target) => target.kind === "cidr");
  const ranges = cidrs
    .filter((target) => family === "all" || target.surface === family)
    .map((target) => target.value);
  return {
    domains: wantsDomains
      ? found.targets.filter((target) => target.kind === "domain").map((target) => target.value)
      : undefined,
    ranges: wantsRanges ? ranges : undefined,
    otherSurface: wantsRanges ? cidrs.length - ranges.length : 0,
    skipped: found.skipped.filter((entry) =>
      entry.kind === "domain" ? wantsDomains : wantsRanges,
    ),
  };
}

type FillNote =
  | {
      kind: "filled" | "nothing" | "notApproved";
      domains: number;
      ranges: number;
      otherSurface: number;
      skipped: ScopeTargetSkipped[];
    }
  | { kind: "failed"; error: string };

function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto)
    return `console:${crypto.randomUUID()}`;
  return `console:${Date.now().toString(36)}:${Math.random().toString(36).slice(2)}`;
}

/**
 * The scan form, shaped by the surface it lives on. An external launcher
 * leads with domains and offers org-profile and wordlists; an internal one
 * leads with private ranges and hides what only makes sense from the
 * internet. On a surfaced page the choice is sent explicitly (the server
 * honours it); the unpinned launcher lets the server derive it.
 */
export function ScanLauncher({
  surface,
  onStarted,
  className,
}: {
  surface: ScanSurface | null;
  onStarted?: (job: JobInfo) => void;
  className?: string;
}) {
  const t = useT();
  const family = surface === "external" || surface === "internal" ? surface : "all";
  const [mode, setMode] = useState("balanced");
  const [intent, setIntent] = useState<ScanIntent | "">("inventory");
  const [delta, setDelta] = useState(false);
  const [skipNse, setSkipNse] = useState(false);
  const [notify, setNotify] = useState(false);
  const [exportDefectDojo, setExportDefectDojo] = useState(false);
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("");
  const [portsUdp, setPortsUdp] = useState("");
  const [wordlistId, setWordlistId] = useState("");
  const [agentGroup, setAgentGroup] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [filling, setFilling] = useState<ScopeFillSlot | null>(null);
  const [fillNote, setFillNote] = useState<FillNote | null>(null);
  const queryClient = useQueryClient();
  // One key per *form content*: a retry of the same form after a timeout
  // replays the same request instead of queueing a second scan, while any
  // edit rotates the key — otherwise a corrected target list would silently
  // replay the earlier job (the server matches the key, not the body).
  const [idempotencyKey, setIdempotencyKey] = useState(newIdempotencyKey);
  const formFingerprint = JSON.stringify([
    mode,
    intent,
    delta,
    skipNse,
    notify,
    exportDefectDojo,
    ranges,
    domains,
    ports,
    portsUdp,
    wordlistId,
    agentGroup,
    surface,
  ]);
  const [lastFingerprint, setLastFingerprint] = useState(formFingerprint);
  if (formFingerprint !== lastFingerprint) {
    setLastFingerprint(formFingerprint);
    setIdempotencyKey(newIdempotencyKey());
  }

  const mutation = useStartScan();
  const { data: systemStatus } = useSystemStatus();
  const agentMode = systemStatus?.runtime.job_execution_mode === "agent";
  const serviceBackend = systemStatus?.scan_config.service_backend;
  const wantsWordlists = family !== "internal" && !agentMode;
  const { data: wordlists } = useWordlists(wantsWordlists);
  // Only in agent mode: a local scan runs in the API container, which is in no
  // group, and the server refuses a selector there rather than ignoring it.
  const { data: agentGroups } = useAgentGroups(agentMode);
  const selectedGroup = (agentGroups ?? []).find((group) => group.name === agentGroup);

  useEffect(() => {
    // org_profile is an internet-facing intent; if the operator switches to
    // the internal launcher with it selected, fall back to inventory.
    if (!INTENTS_BY_SURFACE[family].includes(intent)) setIntent("inventory");
  }, [family, intent]);

  const detected = useMemo(() => classifyTargets(ranges, domains), [ranges, domains]);
  const domainCount = splitTargetLines(domains).length;
  const rangeCount = splitTargetLines(ranges).length;
  const noTargets = domainCount === 0 && rangeCount === 0;
  const mismatch = surface !== null && detected !== null && detected !== surface;

  async function fillFromScope(slot: ScopeFillSlot) {
    setFilling(slot);
    try {
      // Read at the click, never from cache: the scope is an admin's to change
      // between two visits, and a stale fill is a scan that comes back 403.
      const found = await queryClient.fetchQuery({
        queryKey: queryKeys.scopeTargets,
        queryFn: fetchScopeTargets,
        staleTime: 0,
      });
      const fill = scopeFill(found, slot, family);
      const domainTotal = fill.domains?.length ?? 0;
      const rangeTotal = fill.ranges?.length ?? 0;
      // Nothing to put in is not a reason to empty what the operator typed.
      if (domainTotal + rangeTotal > 0) {
        if (fill.domains) setDomains(fill.domains.join("\n"));
        if (fill.ranges) setRanges(fill.ranges.join("\n"));
      }
      setFillNote({
        kind: !found.approved
          ? "notApproved"
          : domainTotal + rangeTotal === 0
            ? "nothing"
            : "filled",
        domains: domainTotal,
        ranges: rangeTotal,
        otherSurface: fill.otherSurface,
        skipped: fill.skipped,
      });
    } catch (error) {
      setFillNote({
        kind: "failed",
        error: error instanceof Error ? error.message : String(error),
      });
    } finally {
      setFilling(null);
    }
  }

  function fillButton(slot: "domains" | "ranges") {
    const label = slot === "domains" ? t("launcher.fillDomains") : t("launcher.fillRanges");
    return (
      <Button
        type="button"
        variant="ghost"
        className="h-5 gap-1 px-1 text-xs font-semibold text-primary [&_svg]:size-3.5"
        disabled={filling !== null}
        onClick={() => void fillFromScope(slot)}
        title={label}
        aria-label={label}
      >
        <ShieldCheck />
        {filling === slot ? t("launcher.filling") : t("launcher.fillField")}
      </Button>
    );
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    setConfirmOpen(true);
  }

  function startConfirmed() {
    const body: StartScanBody = {
      mode,
      intent: intent || null,
      // When intent is set, the server owns skip_nse/nuclei; delta still applies.
      delta,
      skip_nse: intent ? false : skipNse,
      notify,
      export_defectdojo: exportDefectDojo,
      surface: surface ?? undefined,
      ranges: ranges.trim() || undefined,
      domains: domains.trim() || undefined,
      ports: ports.trim() || undefined,
      ports_udp: portsUdp.trim() || undefined,
      wordlist_id: wantsWordlists && wordlistId ? wordlistId : undefined,
      agent_group: agentMode && agentGroup ? agentGroup : undefined,
    };
    mutation.mutate(
      { body, idempotencyKey },
      {
        onSuccess: (job) => {
          setIdempotencyKey(newIdempotencyKey());
          onStarted?.(job);
        },
        // A 409 means the server saw this key with a different body (its
        // normalisation and ours disagreed); a fresh key lets the next attempt
        // be judged on its own.
        onError: () => setIdempotencyKey(newIdempotencyKey()),
      },
    );
  }

  const surfaceLabel = surface ? t(`surface.${surface}`) : t("surface.all");
  const Icon = family === "external" ? Globe2 : family === "internal" ? Layers : Play;

  const domainsField = (
    <Field
      label={t("launcher.domains")}
      htmlFor="scan-domains"
      optional={t("launcher.optional")}
      action={fillButton("domains")}
      hint={t("launcher.domainsHint")}
    >
      <Textarea
        id="scan-domains"
        aria-describedby={fieldHintId("scan-domains")}
        className="min-h-[8.5rem] font-mono text-body-sm"
        value={domains}
        onChange={(e) => setDomains(e.target.value)}
        placeholder={
          family === "internal"
            ? "portal.corp.internal\nwiki.corp.internal"
            : "api.example.com\nportal.example.com"
        }
        spellCheck={false}
      />
    </Field>
  );

  const rangesField = (
    <Field
      label={t("launcher.ranges")}
      htmlFor="scan-ranges"
      optional={t("launcher.optional")}
      action={fillButton("ranges")}
      hint={family === "external" ? t("launcher.rangesPublicHint") : t("launcher.rangesHint")}
    >
      <Textarea
        id="scan-ranges"
        aria-describedby={fieldHintId("scan-ranges")}
        className="min-h-[8.5rem] font-mono text-body-sm"
        value={ranges}
        onChange={(e) => setRanges(e.target.value)}
        placeholder={
          family === "external" ? "203.0.113.0/24\n198.51.100.12" : "10.0.0.0/24\n192.168.1.0/28"
        }
        spellCheck={false}
      />
    </Field>
  );

  const showAgentGroup = agentMode && (agentGroups ?? []).length > 0;
  const chosenOptions = [
    intent === "delta" || delta ? t("launcher.delta") : null,
    !intent && skipNse ? t("launcher.portsOnly") : null,
    notify ? t("launcher.notify") : null,
    exportDefectDojo ? t("launcher.defectdojo") : null,
  ].filter((item): item is string => item !== null);

  return (
    <form
      onSubmit={onSubmit}
      className={cn("rounded-xl border border-border bg-card", className)}
      data-testid="scan-launcher"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-6 py-4">
        <h3 className="flex items-center gap-2 text-lg font-semibold text-foreground">
          <Icon className="h-5 w-5 text-primary" aria-hidden />
          {t(`launcher.title.${family}`)}
        </h3>
        <div className="flex flex-wrap items-center gap-3 text-body-sm text-muted-foreground">
          <span>
            {detected
              ? t("launcher.detected", { surface: t(`surface.${detected}`) })
              : t("launcher.detectedNone")}
          </span>
          <SurfaceBadge surface={detected} />
          <Button
            type="button"
            variant="outline"
            disabled={filling !== null}
            onClick={() => void fillFromScope("all")}
            title={t("launcher.fillAllHint")}
          >
            <ShieldCheck aria-hidden />
            {filling === "all" ? t("launcher.filling") : t("launcher.fillAll")}
          </Button>
        </div>
      </div>

      <div className="grid gap-6 p-6 lg:grid-cols-[minmax(0,1fr)_18rem]">
        <div className="min-w-0 space-y-8">
          {mismatch && detected ? (
            <div
              role="status"
              className="flex items-start gap-2 rounded-lg border border-warning/30 bg-warning/10 px-3 py-2 text-body-sm text-warning"
            >
              <TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              <span>
                {t("launcher.mismatch", {
                  detected: t(`surface.${detected}`),
                  chosen: surfaceLabel,
                })}
              </span>
            </div>
          ) : null}

          <section aria-labelledby="launcher-targets" className="space-y-4">
            <h4 id="launcher-targets" className="text-h3 font-semibold text-foreground">
              {t("launcher.section.targets")}
            </h4>
            <FieldGrid cols={2}>
              {family === "internal" ? rangesField : domainsField}
              {family === "internal" ? domainsField : rangesField}
            </FieldGrid>
            {fillNote ? (
              <div
                aria-live="polite"
                data-testid="scope-fill-note"
                className={cn(
                  "space-y-1 rounded-lg border px-3 py-2 text-body-sm",
                  fillNote.kind === "filled"
                    ? "border-success/30 bg-success/10 text-success"
                    : "border-warning/30 bg-warning/10 text-warning",
                )}
              >
                {fillNote.kind === "failed" ? (
                  <p>{t("launcher.fillFailed", { error: fillNote.error })}</p>
                ) : (
                  <>
                    <p>
                      {fillNote.kind === "filled"
                        ? t("launcher.filled", {
                            domains: fillNote.domains,
                            ranges: fillNote.ranges,
                          })
                        : fillNote.kind === "notApproved"
                          ? t("launcher.fillNotApproved")
                          : t("launcher.fillNothing")}
                    </p>
                    {fillNote.otherSurface > 0 && family !== "all" ? (
                      <p>
                        {t("launcher.fillOtherSurface", {
                          count: fillNote.otherSurface,
                          page: t(
                            `page.scans.${family === "external" ? "internal" : "external"}.title`,
                          ),
                        })}
                      </p>
                    ) : null}
                    {fillNote.skipped.length > 0 ? (
                      <p>
                        {t("launcher.fillSkipped", {
                          items: fillNote.skipped
                            .map(
                              (entry) =>
                                `${entry.value} (${t(`launcher.fillReason.${entry.reason}`)})`,
                            )
                            .join(", "),
                        })}
                      </p>
                    ) : null}
                  </>
                )}
              </div>
            ) : null}
          </section>

          <section aria-labelledby="launcher-params" className="space-y-4">
            <h4 id="launcher-params" className="text-h3 font-semibold text-foreground">
              {t("launcher.section.params")}
            </h4>
            <FieldGrid cols={2}>
              <Field
                label={t("launcher.intent")}
                htmlFor="scan-intent"
                hint={t("launcher.intentHint")}
              >
                <Select
                  value={intent || NO_INTENT}
                  onValueChange={(v) => setIntent(v === NO_INTENT ? "" : (v as ScanIntent))}
                >
                  <SelectTrigger id="scan-intent" aria-describedby={fieldHintId("scan-intent")}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {INTENTS_BY_SURFACE[family].map((value) => (
                      <SelectItem key={value || NO_INTENT} value={value || NO_INTENT}>
                        {value ? t(`launcher.intent.${value}`) : t("launcher.intent.legacy")}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>

              <Field
                label={t("launcher.mode")}
                htmlFor="scan-mode"
                hint={serviceBackend ? t("scanCopy.backendHint") : null}
              >
                <Select value={mode} onValueChange={setMode}>
                  <SelectTrigger id="scan-mode">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="safe">{t("launcher.mode.safe")}</SelectItem>
                    <SelectItem value="balanced">{t("launcher.mode.balanced")}</SelectItem>
                    <SelectItem value="fast">{t("launcher.mode.fast")}</SelectItem>
                  </SelectContent>
                </Select>
              </Field>

              {showAgentGroup ? (
                <Field
                  label={t("launcher.agentGroup")}
                  htmlFor="scan-agent-group"
                  hintTone={selectedGroup && selectedGroup.agent_count === 0 ? "warning" : "muted"}
                  hint={
                    selectedGroup && selectedGroup.agent_count === 0
                      ? t("launcher.agentGroupEmpty", { group: selectedGroup.name })
                      : t("launcher.agentGroupHint")
                  }
                >
                  <Select
                    value={agentGroup || ANY_AGENT_GROUP}
                    onValueChange={(v) => setAgentGroup(v === ANY_AGENT_GROUP ? "" : v)}
                  >
                    <SelectTrigger
                      id="scan-agent-group"
                      aria-describedby={fieldHintId("scan-agent-group")}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={ANY_AGENT_GROUP}>
                        {t("launcher.agentGroup.any")}
                      </SelectItem>
                      {(agentGroups ?? []).map((group) => (
                        <SelectItem key={group.group_id} value={group.name}>
                          {group.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
              ) : null}

              <Field
                label={t("launcher.ports")}
                htmlFor="scan-ports"
                optional={t("launcher.optional")}
                hint={t("launcher.portsHint")}
              >
                <Input
                  id="scan-ports"
                  aria-describedby={fieldHintId("scan-ports")}
                  className="font-mono text-body-sm"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  placeholder="22,80,443,8000-8080"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>

              <Field
                label={t("launcher.portsUdp")}
                htmlFor="scan-ports-udp"
                optional={t("launcher.optional")}
                hint={t("launcher.portsUdpHint")}
              >
                <Input
                  id="scan-ports-udp"
                  aria-describedby={fieldHintId("scan-ports-udp")}
                  className="font-mono text-body-sm"
                  value={portsUdp}
                  onChange={(e) => setPortsUdp(e.target.value)}
                  placeholder="53,123,161"
                  spellCheck={false}
                  autoComplete="off"
                />
              </Field>

              {wantsWordlists ? (
                <Field
                  label={t("launcher.wordlist")}
                  htmlFor="scan-wordlist"
                  hint={
                    <>
                      {t("launcher.wordlistHint")}{" "}
                      <Link href="/wordlists" className="text-primary hover:underline">
                        {t("launcher.manageWordlists")}
                      </Link>
                    </>
                  }
                >
                  <Select
                    value={wordlistId || NO_WORDLIST}
                    onValueChange={(v) => setWordlistId(v === NO_WORDLIST ? "" : v)}
                  >
                    <SelectTrigger
                      id="scan-wordlist"
                      aria-describedby={fieldHintId("scan-wordlist")}
                    >
                      <SelectValue placeholder={t("launcher.wordlistNone")} />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NO_WORDLIST}>{t("launcher.wordlistNone")}</SelectItem>
                      {(wordlists ?? []).map((wl) => (
                        <SelectItem key={wl.wordlist_id} value={wl.wordlist_id}>
                          {wl.name} · {wl.kind} · {wl.line_count.toLocaleString()}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
              ) : null}
            </FieldGrid>
          </section>

          <section aria-labelledby="launcher-options" className="space-y-4">
            <h4 id="launcher-options" className="text-h3 font-semibold text-foreground">
              {t("launcher.section.options")}
            </h4>
            <div className="grid grid-cols-1 items-stretch gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <CheckboxOption
                label={t("launcher.delta")}
                description={t("launcher.deltaHint")}
                checked={intent === "delta" ? true : delta}
                disabled={intent === "delta"}
                onCheckedChange={setDelta}
              />
              {!intent ? (
                <CheckboxOption
                  label={t("launcher.portsOnly")}
                  description={t("launcher.portsOnlyHint")}
                  checked={skipNse}
                  onCheckedChange={setSkipNse}
                />
              ) : null}
              <CheckboxOption
                label={t("launcher.notify")}
                description={t("launcher.notifyHint")}
                checked={notify}
                onCheckedChange={setNotify}
              />
              <CheckboxOption
                label={t("launcher.defectdojo")}
                description={t("launcher.defectdojoHint")}
                checked={exportDefectDojo}
                onCheckedChange={setExportDefectDojo}
              />
            </div>
          </section>
        </div>

        <aside
          aria-labelledby="launcher-summary"
          className="flex flex-col gap-4 self-start rounded-lg border border-border bg-muted/30 p-5"
        >
          <h4 id="launcher-summary" className="text-h3 font-semibold text-foreground">
            {t("launcher.summary")}
          </h4>
          <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-3 text-body-sm">
            <dt className="text-muted-foreground">{t("launcher.summary.surface")}</dt>
            <dd className="text-foreground">{surfaceLabel}</dd>
            <dt className="text-muted-foreground">{t("launcher.summary.targets")}</dt>
            <dd className="tabular-nums text-foreground">
              {t("launcher.summary.targetsValue", { domains: domainCount, ranges: rangeCount })}
            </dd>
            <dt className="text-muted-foreground">{t("launcher.summary.intent")}</dt>
            <dd className="font-mono text-foreground">{scanIntentLabel(t.locale, intent)}</dd>
            <dt className="text-muted-foreground">{t("launcher.summary.mode")}</dt>
            <dd className="font-mono text-foreground">{scanModeLabel(t.locale, mode)}</dd>
            {showAgentGroup ? (
              <>
                <dt className="text-muted-foreground">{t("launcher.summary.agents")}</dt>
                <dd className="break-words text-foreground">
                  {agentGroup || t("launcher.agentGroup.any")}
                </dd>
              </>
            ) : null}
            <dt className="text-muted-foreground">{t("launcher.summary.options")}</dt>
            <dd className="text-foreground">
              {chosenOptions.length > 0 ? chosenOptions.join(", ") : t("launcher.summary.none")}
            </dd>
          </dl>
          <ScanTechnicalDetails intent={intent} mode={mode} backend={serviceBackend} />
          <div className="h-px bg-border" />
          <Button type="submit" disabled={mutation.isPending} className="w-full font-semibold">
            <Play className="fill-current" aria-hidden />
            {mutation.isPending ? t("launcher.starting") : t("launcher.start")}
          </Button>
          <p className="text-xs text-muted-foreground">{t("launcher.defaultsHint")}</p>
        </aside>
      </div>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {surface
                ? t("launcher.confirmTitle", {
                    surface: surfaceLabel.toLowerCase(),
                    intent: scanIntentLabel(t.locale, intent),
                    mode: scanModeLabel(t.locale, mode),
                  })
                : t("launcher.confirmTitleAny", {
                    intent: scanIntentLabel(t.locale, intent),
                    mode: scanModeLabel(t.locale, mode),
                  })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {noTargets
                ? t("launcher.confirmNoTargets")
                : t("launcher.confirmTargets", { domains: domainCount, ranges: rangeCount })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={startConfirmed}>{t("launcher.confirm")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </form>
  );
}
