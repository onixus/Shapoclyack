"use client";

import { useState } from "react";
import { useT } from "@/lib/i18n";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Building2,
  Globe,
  CheckCircle2,
  HelpCircle,
  ChevronDown,
  ChevronRight,
  PlusCircle,
  MinusCircle,
  AlertCircle,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  fetchOrgProfile,
  promoteRelatedDomain,
  withdrawPromotedDomain,
  type OrgProfileDetail,
  type RelatedDomainCandidate,
} from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { canOperate as canOperateIn } from "@/lib/authz";

type DomainOwnership = {
  org_name?: string | null;
  registrant_organization?: string | null;
  registrar?: string | null;
  dnssec?: boolean | null;
  nameservers?: string[] | null;
};

function CandidateRow({
  candidate,
  isPromoted,
  onPromote,
  onWithdraw,
  isPromoting,
  canOperate,
}: {
  candidate: RelatedDomainCandidate;
  isPromoted: boolean;
  onPromote: (domain: string) => void;
  onWithdraw: (domain: string) => void;
  isPromoting: boolean;
  canOperate: boolean;
}) {
  const t = useT();
  const [expanded, setExpanded] = useState(false);
  const isConfirmed = candidate.status === "confirmed";

  return (
    <div className="border-b border-border last:border-0 hover:bg-card transition-colors">
      <div
        className="flex flex-col sm:flex-row sm:items-center justify-between p-4 gap-3 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start sm:items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground shrink-0 mt-0.5 sm:mt-0"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
          >
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>

          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-foreground text-sm font-mono">{candidate.domain}</span>
              {isConfirmed ? (
                <Badge className="bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/40 gap-1 font-mono text-[11px]">
                  <CheckCircle2 className="h-3 w-3" />
                  CONFIRMED
                </Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground border-border bg-muted gap-1 font-mono text-[11px]">
                  <HelpCircle className="h-3 w-3" />
                  CANDIDATE
                </Badge>
              )}
              <Badge variant="outline" className="text-[11px] border-border text-sky-600 dark:text-sky-400 font-mono">
                {Math.round(candidate.confidence * 100)}% confidence
              </Badge>
              {isPromoted && (
                <Badge className="bg-purple-500/20 text-purple-600 dark:text-purple-300 border-purple-500/40 text-[11px] font-mono">
                  PROMOTED
                </Badge>
              )}
            </div>

            <div className="flex items-center gap-1.5 mt-1.5 flex-wrap">
              <span className="text-muted-foreground text-xs">Sources:</span>
              {candidate.sources.map((s) => (
                <span
                  key={s}
                  className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-foreground border border-border"
                >
                  {s}
                </span>
              ))}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 ml-9 sm:ml-0">
          {canOperate && (
            <Button
              size="sm"
              variant={isPromoted ? "secondary" : "outline"}
              disabled={isPromoting}
              title={
                isPromoted
                  ? "Every scan of this tenant carries this domain; withdraw to stop that"
                  : "Add to the targets of every later scan of this tenant (starts nothing)"
              }
              className={`h-7 text-xs font-mono gap-1.5 ${
                isPromoted ? "hover:border-rose-500 hover:text-rose-600 dark:text-rose-300" : "hover:border-sky-500 hover:text-sky-600 dark:text-sky-300"
              }`}
              onClick={(e) => {
                e.stopPropagation();
                if (isPromoted) onWithdraw(candidate.domain);
                else onPromote(candidate.domain);
              }}
            >
              {isPromoted ? (
                <>
                  <MinusCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
                  {t("prose.withdrawFromScope")}
                </>
              ) : (
                <>
                  <PlusCircle className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  Promote to Scope
                </>
              )}
            </Button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="px-6 pb-4 pt-2 bg-muted space-y-2.5 text-xs border-t border-border">
          <span className="font-semibold text-foreground block">Attribution Evidence Trail:</span>
          <div className="space-y-1.5">
            {candidate.evidence?.map((ev, i) => (
              <div
                key={i}
                className="flex items-start gap-2 bg-card p-2 rounded border border-border font-mono text-xs"
              >
                <Badge variant="outline" className="text-[10px] uppercase border-border py-0 px-1 shrink-0 text-foreground">
                  {ev.source}
                </Badge>
                <span className="text-foreground grow">{ev.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function RelatedDomainsPanel({ runId }: { runId: string }) {
  const t = useT();
  const user = useAuthStore((s) => s.user);
  // Promoting a related domain is a tenant-scoped write, so the rank that
  // decides is the one held in this tenant, not the account's (#318).
  const canOperate = canOperateIn(user);
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<"all" | "confirmed" | "candidates">("all");

  const { data, isLoading, error } = useQuery<OrgProfileDetail>({
    queryKey: ["org-profile", runId],
    queryFn: () => fetchOrgProfile(runId),
  });

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["org-profile", runId] });
    queryClient.invalidateQueries({ queryKey: ["run", runId] });
  };
  // One mutation for both directions, so the error state belongs to the
  // *latest* action: a 403 from promoting one domain must not stay pinned
  // over a later successful withdraw of another. (Two mutations would each
  // keep their own error until they themselves ran again.)
  const scopeMutation = useMutation({
    mutationFn: ({ action, domain }: { action: "promote" | "withdraw"; domain: string }) =>
      action === "promote" ? promoteRelatedDomain(runId, domain) : withdrawPromotedDomain(domain),
    onSuccess: invalidate,
  });
  // A 403 here is the approved scan scope refusing the domain — the operator
  // decides attribution, an admin decides authorization — and it must be
  // read, not swallowed into a button that silently did nothing.
  const actionError = scopeMutation.error?.message || null;
  const promote = (domain: string) => scopeMutation.mutate({ action: "promote", domain });
  const withdraw = (domain: string) => scopeMutation.mutate({ action: "withdraw", domain });

  if (isLoading) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="py-8 text-center text-muted-foreground text-xs">
          {t("prose.loadingOrganizationProfileAndRelated")}
        </CardContent>
      </Card>
    );
  }

  if (error || !data) {
    return (
      <Card className="border-border bg-card">
        <CardContent className="py-8 text-center text-muted-foreground text-xs">
          <HelpCircle className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          {t("prose.organizationProfileTelemetryIsNot")}
        </CardContent>
      </Card>
    );
  }

  const ownership = (data.ownership?.domains || {}) as Record<string, DomainOwnership>;
  const firstDomain = Object.keys(ownership)[0];
  const primaryOwner = firstDomain ? ownership[firstDomain] : null;

  const related = data.related_domains;
  const candidates = related?.candidates || [];
  // The tenant's whole promoted list — what every scan of this tenant carries —
  // not just what this run proposed: a promoted domain is a seed on the next
  // run and is never proposed again, so this is the only place it stays visible
  // and withdrawable.
  const promoted = data.promoted_domains || [];
  const promotedSet = new Set(promoted);

  const filteredCandidates = candidates.filter((c) => {
    if (filter === "confirmed") return c.status === "confirmed";
    if (filter === "candidates") return c.status === "candidate";
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Registrant / Ownership Overview Card */}
      <div className="rounded-xl border border-border bg-card p-5 shadow-lg backdrop-blur space-y-4">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Building2 className="h-5 w-5 text-sky-600 dark:text-sky-400" />
              <h2 className="text-base font-bold text-foreground">
                {primaryOwner?.org_name || primaryOwner?.registrant_organization || "Organization Profile"}
              </h2>
            </div>
            <p className="text-xs text-muted-foreground font-mono">
              Seed Scope: {data.seed_domains?.join(", ") || "No seed domains recorded"}
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {primaryOwner?.registrar && (
              <Badge variant="outline" className="border-border text-foreground text-xs">
                Registrar: {primaryOwner.registrar}
              </Badge>
            )}
            {primaryOwner?.dnssec != null && (
              <Badge
                className={
                  primaryOwner.dnssec
                    ? "bg-emerald-500/20 text-emerald-600 dark:text-emerald-300 border-emerald-500/40"
                    : "bg-muted text-muted-foreground border-border"
                }
              >
                DNSSEC: {primaryOwner.dnssec ? "Signed" : "Unsigned"}
              </Badge>
            )}
          </div>
        </div>

        {primaryOwner?.nameservers && primaryOwner.nameservers.length > 0 && (
          <div className="pt-2 border-t border-border flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
            <span className="text-muted-foreground font-semibold">Authoritative NS:</span>
            <span className="font-mono text-foreground">{primaryOwner.nameservers.join(", ")}</span>
          </div>
        )}
      </div>

      {/* Promoted scope: tenant-wide, survives the run that proposed each domain */}
      <Card className="border-border bg-card shadow-md">
        <CardHeader className="py-3.5 px-4 border-b border-border">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground flex items-center gap-2">
            <PlusCircle className="h-4 w-4 text-purple-600 dark:text-purple-400" />
            Promoted Scope ({promoted.length})
          </CardTitle>
          <p className="text-[11px] text-muted-foreground mt-1">
            {t("prose.everyOrdinaryScanOfThis")}
          </p>
        </CardHeader>
        <CardContent className="p-0">
          {promoted.length > 0 ? (
            <ul className="divide-y divide-border" data-testid="promoted-scope">
              {promoted.map((domain) => (
                <li key={domain} className="flex items-center justify-between px-4 py-2.5 gap-3">
                  <span className="font-mono text-sm text-foreground">{domain}</span>
                  {canOperate && (
                    <Button
                      size="sm"
                      variant="secondary"
                      disabled={scopeMutation.isPending}
                      className="h-7 text-xs font-mono gap-1.5 hover:border-rose-500 hover:text-rose-600 dark:text-rose-300"
                      onClick={() => withdraw(domain)}
                    >
                      <MinusCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
                      {t("prose.withdrawFromScope")}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <div className="py-5 text-center text-muted-foreground text-xs">
              {t("prose.nothingPromotedYetPromoteA")}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Related Domains Card */}
      <Card className="border-border bg-card shadow-md">
        <CardHeader className="py-3.5 px-4 border-b border-border flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <CardTitle className="text-xs font-bold uppercase tracking-wider text-foreground">
              Discovered Co-Owned Domains ({candidates.length})
            </CardTitle>
          </div>

          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant={filter === "all" ? "secondary" : "ghost"}
              className="h-6 text-xs px-2"
              onClick={() => setFilter("all")}
            >
              All ({candidates.length})
            </Button>
            <Button
              size="sm"
              variant={filter === "confirmed" ? "secondary" : "ghost"}
              className="h-6 text-xs px-2"
              onClick={() => setFilter("confirmed")}
            >
              Confirmed ({related?.confirmed_count ?? 0})
            </Button>
            <Button
              size="sm"
              variant={filter === "candidates" ? "secondary" : "ghost"}
              className="h-6 text-xs px-2"
              onClick={() => setFilter("candidates")}
            >
              Candidates ({related?.candidate_count ?? 0})
            </Button>
          </div>
        </CardHeader>

        {/* Disclaimer banner */}
        <div className="px-4 py-2 bg-amber-50 dark:bg-amber-950/20 border-b border-amber-300 dark:border-amber-900/30 flex items-center gap-2 text-[11px] text-amber-600 dark:text-amber-300/80">
          <AlertCircle className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400 shrink-0" />
          <span>
            {related?.disclaimer ||
              "Attribution is probabilistic. The operator is responsible for verifying domain authorization prior to active scanning."}
          </span>
        </div>

        <CardContent className="p-0">
          {actionError && (
            <div
              role="alert"
              className="px-4 py-2 bg-rose-50 dark:bg-rose-950/30 border-b border-rose-300 dark:border-rose-900/40 flex items-center gap-2 text-[11px] text-rose-600 dark:text-rose-300"
            >
              <AlertCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400 shrink-0" />
              <span>{actionError}</span>
            </div>
          )}
          {filteredCandidates.length > 0 ? (
            <div className="divide-y divide-border">
              {filteredCandidates.map((cand) => (
                <CandidateRow
                  key={cand.domain}
                  candidate={cand}
                  isPromoted={promotedSet.has(cand.domain)}
                  onPromote={promote}
                  onWithdraw={withdraw}
                  isPromoting={scopeMutation.isPending}
                  canOperate={canOperate}
                />
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-muted-foreground text-xs">
              {t("prose.noRelatedDomainCandidatesMatch")}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
