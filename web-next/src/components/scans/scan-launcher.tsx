"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Globe2, Layers, Play, TriangleAlert } from "lucide-react";
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
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { useStartScan } from "@/hooks/use-jobs";
import { useSystemStatus } from "@/hooks/use-system";
import { useWordlists } from "@/hooks/use-wordlists";
import { type JobInfo, type ScanIntent, type StartScanBody } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { classifyTargets, splitTargetLines, type ScanSurface } from "@/lib/scan-surface";
import { cn } from "@/lib/utils";

const NO_INTENT = "__none__";
const NO_WORDLIST = "__none__";

const INTENTS_BY_SURFACE: Record<"external" | "internal" | "all", Array<ScanIntent | "">> = {
  external: ["inventory", "vuln", "full", "delta", "org_profile", ""],
  internal: ["inventory", "vuln", "full", "delta", ""],
  all: ["inventory", "vuln", "full", "delta", "org_profile", ""],
};

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
  const [confirmOpen, setConfirmOpen] = useState(false);
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
    <div className="grid gap-2">
      <Label
        htmlFor="scan-domains"
        className="flex items-center justify-between font-semibold text-foreground"
      >
        <span>{t("launcher.domains")}</span>
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          {t("launcher.optional")}
        </span>
      </Label>
      <Textarea
        id="scan-domains"
        className="min-h-[96px] font-mono text-xs"
        value={domains}
        onChange={(e) => setDomains(e.target.value)}
        placeholder={
          family === "internal"
            ? "portal.corp.internal\nwiki.corp.internal"
            : "api.example.com\nportal.example.com"
        }
        spellCheck={false}
      />
      <p className="text-[11px] text-muted-foreground">{t("launcher.domainsHint")}</p>
    </div>
  );

  const rangesField = (
    <div className="grid gap-2">
      <Label
        htmlFor="scan-ranges"
        className="flex items-center justify-between font-semibold text-foreground"
      >
        <span>{t("launcher.ranges")}</span>
        <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
          {t("launcher.optional")}
        </span>
      </Label>
      <Textarea
        id="scan-ranges"
        className="min-h-[96px] font-mono text-xs"
        value={ranges}
        onChange={(e) => setRanges(e.target.value)}
        placeholder={
          family === "external" ? "203.0.113.0/24\n198.51.100.12" : "10.0.0.0/24\n192.168.1.0/28"
        }
        spellCheck={false}
      />
      <p className="text-[11px] text-muted-foreground">
        {family === "external" ? t("launcher.rangesPublicHint") : t("launcher.rangesHint")}
      </p>
    </div>
  );

  return (
    <form
      onSubmit={onSubmit}
      className={cn("space-y-5 rounded-xl border border-border bg-card p-6 shadow-sm", className)}
      data-testid="scan-launcher"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
        <h3 className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider text-foreground">
          <Icon className="h-4 w-4 text-primary" />
          {t(`launcher.title.${family}`)}
        </h3>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <span>
            {detected
              ? t("launcher.detected", { surface: t(`surface.${detected}`) })
              : t("launcher.detectedNone")}
          </span>
          <SurfaceBadge surface={detected} />
        </div>
      </div>

      {mismatch && detected ? (
        <div
          role="status"
          className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200"
        >
          <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span>
            {t("launcher.mismatch", { detected: t(`surface.${detected}`), chosen: surfaceLabel })}
          </span>
        </div>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2">
        {family === "internal" ? rangesField : domainsField}
        {family === "internal" ? domainsField : rangesField}

        <div className="grid gap-2">
          <Label htmlFor="scan-intent" className="font-semibold text-foreground">
            {t("launcher.intent")}
          </Label>
          <Select
            value={intent || NO_INTENT}
            onValueChange={(v) => setIntent(v === NO_INTENT ? "" : (v as ScanIntent))}
          >
            <SelectTrigger id="scan-intent">
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
          <p className="text-[11px] text-muted-foreground">{t("launcher.intentHint")}</p>
        </div>

        <div className="grid gap-2">
          <Label htmlFor="scan-mode" className="font-semibold text-foreground">
            {t("launcher.mode")}
          </Label>
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
          {serviceBackend ? (
            <p className="text-[11px] text-muted-foreground">
              {t("launcher.backend", { backend: serviceBackend })}
            </p>
          ) : null}
        </div>

        <div className="grid gap-2">
          <Label
            htmlFor="scan-ports"
            className="flex items-center justify-between font-semibold text-foreground"
          >
            <span>{t("launcher.ports")}</span>
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {t("launcher.optional")}
            </span>
          </Label>
          <Textarea
            id="scan-ports"
            className="min-h-[56px] font-mono text-xs"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            placeholder={"22,80,443\n8000-8080"}
            spellCheck={false}
          />
        </div>

        <div className="grid gap-2">
          <Label
            htmlFor="scan-ports-udp"
            className="flex items-center justify-between font-semibold text-foreground"
          >
            <span>{t("launcher.portsUdp")}</span>
            <span className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              {t("launcher.optional")}
            </span>
          </Label>
          <Textarea
            id="scan-ports-udp"
            className="min-h-[56px] font-mono text-xs"
            value={portsUdp}
            onChange={(e) => setPortsUdp(e.target.value)}
            placeholder="53,123,161"
            spellCheck={false}
          />
        </div>

        {wantsWordlists ? (
          <div className="grid gap-2 md:col-span-2">
            <Label htmlFor="scan-wordlist" className="font-semibold text-foreground">
              {t("launcher.wordlist")}
            </Label>
            <Select
              value={wordlistId || NO_WORDLIST}
              onValueChange={(v) => setWordlistId(v === NO_WORDLIST ? "" : v)}
            >
              <SelectTrigger id="scan-wordlist">
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
            <p className="text-[11px] text-muted-foreground">
              {t("launcher.wordlistHint")}{" "}
              <Link href="/wordlists" className="text-primary hover:underline">
                {t("launcher.manageWordlists")}
              </Link>
            </p>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-5 text-xs text-foreground md:col-span-2">
          <Label className="flex cursor-pointer items-center gap-2 font-semibold">
            <Checkbox
              checked={intent === "delta" ? true : delta}
              disabled={intent === "delta"}
              onCheckedChange={(checked) => setDelta(checked === true)}
            />
            {t("launcher.delta")}
          </Label>
          {!intent ? (
            <Label className="flex cursor-pointer items-center gap-2 font-semibold">
              <Checkbox
                checked={skipNse}
                onCheckedChange={(checked) => setSkipNse(checked === true)}
              />
              {t("launcher.portsOnly")}
            </Label>
          ) : null}
          <Label className="flex cursor-pointer items-center gap-2 font-semibold">
            <Checkbox checked={notify} onCheckedChange={(checked) => setNotify(checked === true)} />
            {t("launcher.notify")}
          </Label>
          <Label className="flex cursor-pointer items-center gap-2 font-semibold">
            <Checkbox
              checked={exportDefectDojo}
              onCheckedChange={(checked) => setExportDefectDojo(checked === true)}
            />
            {t("launcher.defectdojo")}
          </Label>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border pt-3">
        <p className="text-xs text-muted-foreground">{t("launcher.defaultsHint")}</p>
        <Button type="submit" disabled={mutation.isPending} className="gap-2 font-semibold">
          <Play className="h-3.5 w-3.5 fill-current" />
          {mutation.isPending ? t("launcher.starting") : t("launcher.start")}
        </Button>
      </div>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {surface
                ? t("launcher.confirmTitle", {
                    surface: surfaceLabel.toLowerCase(),
                    intent: intent || "legacy",
                    mode,
                  })
                : t("launcher.confirmTitleAny", { intent: intent || "legacy", mode })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs">
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
