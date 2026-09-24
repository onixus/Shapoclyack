"use client";

import Link from "next/link";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EntityList } from "@/components/run/entity-list";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { AssetServicesPanel } from "@/components/asset/asset-services-panel";
import { DevicePatchGapSection } from "@/components/endpoint/device-patch-gap-section";
import { SoftwareCvePanel } from "@/components/endpoint/software-cve-panel";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { useAssetContextEvents, useAssetDetail, useUpdateAsset } from "@/hooks/use-assets";
import { useTrackedVulnerabilities } from "@/hooks/use-vulnerabilities";
import {
  useAssetSoftware,
  useEndpointDeviceChanges,
  useEndpointDevicesForAsset,
} from "@/hooks/use-endpoint-inventory";
import { useAssetServices } from "@/hooks/use-retro-match";
import { useRunHosts, useRunPorts, useRuns, useRunVulns } from "@/hooks/use-runs";
import { useAuthStore } from "@/lib/auth-store";
import type {
  AssetContextEvent,
  AssetDataClassification,
  AssetDetail,
  AssetEnvironment,
  AssetExposureLevel,
  EndpointDeviceInfo,
  EndpointSoftwareItemInfo,
  TrackedVulnerability,
} from "@/lib/api";
import {
  ASSET_DATA_CLASSIFICATIONS,
  ASSET_ENVIRONMENTS,
  ASSET_EXPOSURE_LEVELS,
  assetRiskLabel,
  describeContextEvent,
} from "@/lib/asset-context";
import {
  ASSET_CONTEXT_SOURCE,
  ASSET_CRITICALITY,
  ASSET_DATA_CLASSIFICATION,
  ASSET_ENVIRONMENT,
  ASSET_EXPOSURE,
  ASSET_STATUS,
  ENDPOINT_RECONCILIATION_STATUS,
  RISK_LEVEL_STATUS,
  SEVERITY_STATUS,
  SOFTWARE_CHANGE_STATUS,
  VULN_LIFECYCLE_STATUS,
} from "@/lib/config/statuses";
import { formatLocation, normalizeSeverity, pickLatestRun } from "@/lib/run-data";
import {
  findingLabel,
  requiredAction,
  vulnDetailHref,
  vulnListHref,
} from "@/lib/vuln-lifecycle";

const CRIT_UNSET = "unset";
const CONTEXT_UNSET = "unset";

export default function AssetDetailPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading asset posture details…</p>}>
      <AssetDetailInner />
    </Suspense>
  );
}

function BackToAssets() {
  const t = useT();
  return (
    <Button asChild variant="ghost" size="sm" className="gap-2 px-0 text-muted-foreground hover:text-foreground hover:bg-transparent">
      <Link href="/assets">
        <ArrowLeft className="h-4 w-4 text-sky-600 dark:text-sky-400" />
        {t("asset.back")}
      </Link>
    </Button>
  );
}

function AssetDetailInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const assetId = (searchParams.get("assetId") || "").trim();
  const tenantId = searchParams.get("tenantId") || "default";
  const { canOperate } = useAuthStore();

  const detailQuery = useAssetDetail(assetId || null, tenantId);
  const asset = detailQuery.data;
  const ip = asset?.identifiers.find((i) => i.identifier_type === "ip")?.identifier_value ?? null;

  // Only the newest run is correlated against, so a single page suffices (P3.3).
  const runsQuery = useRuns(undefined, { limit: 20 });
  const latest = pickLatestRun(runsQuery.data?.items ?? []);
  const corrRunId = ip && latest ? latest.run_id : "";
  const vulnsQuery = useRunVulns(corrRunId, { host: ip });
  const hostsQuery = useRunHosts(corrRunId);
  const portsQuery = useRunPorts(corrRunId);

  const hostRow = (hostsQuery.data || []).find((h) => h.host === ip) || null;
  const assetPorts = (portsQuery.data || []).filter((p) => ip && p.hosts.includes(ip));
  const vulns = vulnsQuery.data || [];

  const trackedQuery = useTrackedVulnerabilities(
    { asset_id: assetId || undefined, open_only: true },
    { limit: 50, sort: "contextual_score", order: "desc" },
    Boolean(assetId),
  );
  const tracked = trackedQuery.data?.items ?? [];
  const trackedOpen = trackedQuery.data?.total ?? 0;

  const devicesQuery = useEndpointDevicesForAsset(assetId || null, tenantId);
  const devices = devicesQuery.data || [];
  const device = devices[0] || null;
  const softwareQuery = useAssetSoftware(assetId || null, tenantId);
  const software = softwareQuery.data || [];
  // The tab label's count; the panel reads the same cached query.
  const servicesQuery = useAssetServices(assetId || null, tenantId);
  const serviceCount = servicesQuery.data?.length ?? 0;

  if (!assetId) {
    return (
      <div className="space-y-4">
        <BackToAssets />
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200">
          <AlertDescription>{t("asset.missingParam")}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (detailQuery.isLoading || !asset) {
    if (detailQuery.error) {
      return (
        <div className="space-y-4">
          <BackToAssets />
          <Alert variant="destructive" className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200">
            <AlertDescription>{(detailQuery.error as Error).message}</AlertDescription>
          </Alert>
        </div>
      );
    }
    return <p className="text-sm text-muted-foreground">{t("asset.loadingView")}</p>;
  }

  const risk = asset.risk;
  // The name heads the page, as it heads the row in the list: "www.example.com"
  // says what is at risk where "203.0.113.10" is a lookup the operator has to
  // perform. An asset with neither -- an endpoint-derived one, which carries no
  // network identifiers at all -- keeps its id, because that is all it has.
  const primaryFqdn =
    asset.identifiers.find((i) => i.identifier_type === "fqdn")?.identifier_value ?? null;
  const primaryIp =
    asset.identifiers.find((i) => i.identifier_type === "ip")?.identifier_value ?? null;
  const headingName = primaryFqdn || primaryIp || asset.asset_id;
  const estateLevel = risk?.estate_risk && risk.estate_risk in RISK_LEVEL_STATUS ? risk.estate_risk : null;
  const unassigned = risk?.unassigned ?? 0;
  const breached = risk?.breached ?? 0;
  const untriaged = risk?.untriaged ?? 0;

  return (
    <div className="space-y-6">
      <div className="space-y-3 border-b border-border pb-5">
        <BackToAssets />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-extrabold font-mono tracking-tight text-foreground">
                {headingName}
              </h1>
              <StatusBadge value={asset.status} map={ASSET_STATUS} />
              {asset.asset_criticality != null ? (
                <StatusBadge value={String(asset.asset_criticality)} map={ASSET_CRITICALITY} />
              ) : (
                <Badge variant="outline" className="border-border bg-card text-muted-foreground">
                  {t("asset.criticalityUnset")}
                </Badge>
              )}
              {asset.environment ? (
                <StatusBadge value={asset.environment} map={ASSET_ENVIRONMENT} />
              ) : null}
              {asset.exposure_level ? (
                <StatusBadge value={asset.exposure_level} map={ASSET_EXPOSURE} />
              ) : null}
              {estateLevel ? <StatusBadge value={estateLevel} map={RISK_LEVEL_STATUS} /> : null}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {asset.business_service || t("asset.noBusinessService")}
              {" · "}
              {asset.owner_email || t("asset.noOwner")}
              {primaryIp && primaryIp !== headingName ? (
                <>
                  {" · "}
                  <span className="font-mono">{primaryIp}</span>
                </>
              ) : null}
              {" · "}
              <span className="font-mono">{asset.asset_id}</span>
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label={t("asset.kpi.risk")}
          value={t.label(assetRiskLabel(risk))}
          hint={t("asset.kpi.riskHint")}
          decorationColor={estateLevel === "very_high" || estateLevel === "high" ? "rose" : "sky"}
        />
        <KpiCard
          label={t("kpi.openFindings")}
          value={risk?.open_total ?? 0}
          hint={t("asset.kpi.untriagedHint", { count: untriaged })}
          href={vulnListHref({ assetId })}
        />
        <KpiCard
          label={t("asset.kpi.unassigned")}
          value={unassigned}
          hint={t("asset.kpi.unassignedHint")}
          href={unassigned ? vulnListHref({ assetId, unassigned: true }) : undefined}
          decorationColor={unassigned ? "amber" : "slate"}
        />
        <KpiCard
          label={t("kpi.slaBreached")}
          value={breached}
          hint={t("asset.kpi.breachedHint")}
          href={breached ? vulnListHref({ assetId, sla: "breached" }) : undefined}
          decorationColor={breached ? "rose" : "slate"}
        />
      </div>

      {unassigned > 0 || breached > 0 ? (
        <Alert className="border-amber-500/30 bg-amber-50 dark:bg-amber-950/20 text-amber-900 dark:text-amber-100">
          <AlertDescription className="text-xs">
            {t("asset.alert.requiredNow", {
              what: [
                breached > 0
                  ? t("asset.alert.breached", { count: breached.toLocaleString() })
                  : "",
                unassigned > 0
                  ? t("asset.alert.unassigned", { count: unassigned.toLocaleString() })
                  : "",
              ]
                .filter(Boolean)
                .join(t("asset.alert.and")),
              owner: asset.owner_email || t("asset.unassignedShort"),
            })}
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <OverviewCard asset={asset} />
          {devices.length > 0 ? (
            devices.map((d) => <EndpointCard key={d.device_id} device={d} />)
          ) : (
            <NoEndpointCard loading={devicesQuery.isLoading} />
          )}
          {canOperate ? <EditCard asset={asset} /> : null}
        </div>

        <div className="lg:col-span-2 space-y-4">
          <Tabs defaultValue="findings">
            <TabsList className="bg-card border border-border">
              <TabsTrigger value="findings" className="data-[state=active]:bg-muted data-[state=active]:text-sky-600 dark:text-sky-300">
                {t("asset.tab.findings", { count: trackedOpen })}
              </TabsTrigger>
              <TabsTrigger value="services" className="data-[state=active]:bg-muted data-[state=active]:text-sky-600 dark:text-sky-300">
                {t("asset.tab.services", { count: serviceCount })}
              </TabsTrigger>
              <TabsTrigger value="software" className="data-[state=active]:bg-muted data-[state=active]:text-sky-600 dark:text-sky-300">
                {t("asset.tab.software", { count: software.length })}
              </TabsTrigger>
              <TabsTrigger value="evidence" className="data-[state=active]:bg-muted data-[state=active]:text-sky-600 dark:text-sky-300">
                {t("asset.tab.evidence")}
              </TabsTrigger>
              <TabsTrigger value="history" className="data-[state=active]:bg-muted data-[state=active]:text-sky-600 dark:text-sky-300">
                {t("asset.tab.history")}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="space-y-3 pt-3">
              <TrackedFindingsPanel
                assetId={assetId}
                tenantId={tenantId}
                findings={tracked}
                total={trackedOpen}
                isLoading={trackedQuery.isLoading}
              />
            </TabsContent>

            {/* Stored listeners and the retro verdict on each: what the scans
                fingerprinted here, re-checked against current CVE data. */}
            <TabsContent value="services" className="space-y-3 pt-3">
              <AssetServicesPanel assetId={assetId} tenantId={tenantId} />
            </TabsContent>

            <TabsContent value="software" className="space-y-3 pt-3">
              {device ? (
                <>
                  {/* Vendor-advisory CVE matches for this endpoint's packages
                      (ROADMAP Track E M1) — above the raw inventory, since
                      "what is wrong here" outranks "what is installed here". */}
                  <SoftwareCvePanel
                    deviceId={device.device_id}
                    tenantId={tenantId}
                    canOperate={canOperate}
                  />
                  {/* And then what to run about it (ROADMAP Track E M2). */}
                  <DevicePatchGapSection
                    deviceId={device.device_id}
                    tenantId={tenantId}
                  />
                  <SoftwareTab
                    device={device}
                    software={software}
                    isLoading={softwareQuery.isLoading}
                    tenantId={tenantId}
                  />
                </>
              ) : (
                <EmptyNote>
                  No Lariska agent is correlated to this asset yet — software inventory appears
                  after the endpoint links here.
                </EmptyNote>
              )}
            </TabsContent>

            <TabsContent value="evidence" className="space-y-4 pt-3">
              <p className="text-xs text-muted-foreground">
                Last scan correlation
                {latest ? (
                  <>
                    {" "}
                    from run <code className="font-mono text-sky-600 dark:text-sky-400">{latest.run_id}</code>
                  </>
                ) : (
                  " — no run on disk"
                )}
                . Tracked findings above are the working set.
              </p>
              {!ip ? (
                <EmptyNote>{t("asset.empty.noIpIdentifier")}</EmptyNote>
              ) : vulnsQuery.isLoading ? (
                <EmptyNote>{t("asset.empty.correlating")}</EmptyNote>
              ) : vulns.length === 0 ? (
                <EmptyNote>{t("asset.empty.noScanFindings")}</EmptyNote>
              ) : (
                <div className="overflow-hidden rounded-xl border border-border bg-card shadow-lg backdrop-blur">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-border bg-muted text-muted-foreground font-bold uppercase tracking-wider">
                      <tr>
                        <th className="px-3.5 py-3">CVE / Script ID</th>
                        <th className="px-3.5 py-3">Port</th>
                        <th className="px-3.5 py-3">CVSS Score</th>
                        <th className="px-3.5 py-3">{t("col.severity")}</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {vulns.map((v, idx) => (
                        <tr
                          key={`${v.cve || v.script_id}-${v.port}-${idx}`}
                          className="hover:bg-muted transition-colors"
                        >
                          <td className="px-3.5 py-3 font-mono font-semibold text-sky-600 dark:text-sky-400">
                            {v.cve || v.script_id || "—"}
                          </td>
                          <td className="px-3.5 py-3 font-mono text-foreground">{v.port || "—"}</td>
                          <td className="px-3.5 py-3">
                            <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-bold tabular-nums text-rose-600 dark:text-rose-300 border border-rose-500/30">
                              {v.cvss4 ?? v.cvss ?? "—"}
                            </span>
                          </td>
                          <td className="px-3.5 py-3">
                            <StatusBadge
                              value={normalizeSeverity(v.severity)}
                              map={SEVERITY_STATUS}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <EntityList
                items={assetPorts.map((row) => ({
                  key: `${row.port}/${row.protocol || "tcp"}`,
                  title: `:${row.port}${row.protocol ? `/${row.protocol}` : ""}`,
                  subtitle: row.vulnerability_count
                    ? `${row.vulnerability_count} vulnerability findings`
                    : "clean",
                  meta: <span className="font-semibold text-foreground">{row.host_count} hosts</span>,
                }))}
                activeKey={null}
                onSelect={() => {}}
                emptyMessage={ip ? t("asset.empty.noPorts") : t("asset.empty.noIp")}
              />
              {hostRow ? (
                <div className="grid grid-cols-2 gap-4 rounded-xl border border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
                  <Field label={t("asset.field.hostname")} value={hostRow.hostname || hostRow.names[0] || "—"} />
                  <Field label={t("asset.field.geoip")} value={formatLocation(hostRow) || "—"} />
                  <Field
                    label={t("asset.field.detectedOs")}
                    value={
                      hostRow.os_name
                        ? `${hostRow.os_name}${hostRow.os_accuracy ? ` (${hostRow.os_accuracy}% accuracy)` : ""}`
                        : "—"
                    }
                  />
                  <Field label={t("asset.field.totalFindings")} value={String(hostRow.vulnerability_count)} />
                </div>
              ) : (
                <EmptyNote>
                  {ip ? t("asset.empty.notAlive") : t("asset.empty.noIp")}
                </EmptyNote>
              )}
            </TabsContent>

            <TabsContent value="history" className="pt-3">
              <ContextHistoryCard assetId={asset.asset_id} tenantId={tenantId} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}

function TrackedFindingsPanel({
  assetId,
  tenantId,
  findings,
  total,
  isLoading,
}: {
  assetId: string;
  tenantId: string;
  findings: TrackedVulnerability[];
  total: number;
  isLoading: boolean;
}) {
  const t = useT();
  if (isLoading) {
    return <EmptyNote>{t("asset.findings.loading")}</EmptyNote>;
  }
  if (findings.length === 0) {
    return (
      <EmptyNote>
        No open tracked findings on this asset. Closed history lives in the{" "}
        <Link href={vulnListHref({ assetId })} className="text-sky-600 dark:text-sky-400 underline underline-offset-2">
          Vulnerability Center
        </Link>
        .
      </EmptyNote>
    );
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-muted-foreground">
        {t("asset.findings.intro")}
        {total > findings.length
          ? ` ${t("asset.findings.showing", { shown: findings.length, total })}`
          : ""}{" "}
        <Link href={vulnListHref({ assetId })} className="text-sky-600 dark:text-sky-400 underline underline-offset-2">
          {t("asset.findings.openInCenter")}
        </Link>
        {" · "}
        <Link href="/remediation" className="text-sky-600 dark:text-sky-400 underline underline-offset-2">
          {t("asset.findings.remediationBoard")}
        </Link>
      </p>
      <div className="overflow-hidden rounded-xl border border-border bg-card shadow-lg backdrop-blur">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border bg-muted text-muted-foreground font-bold uppercase tracking-wider">
            <tr>
              <th className="px-3.5 py-3">{t("asset.col.finding")}</th>
              <th className="px-3.5 py-3">{t("col.severity")}</th>
              <th className="px-3.5 py-3">{t("col.lifecycle")}</th>
              <th className="px-3.5 py-3">SLA</th>
              <th className="px-3.5 py-3">{t("asset.col.required")}</th>
              <th className="px-3.5 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {findings.map((vuln) => (
              <tr key={vuln.vuln_id} className="hover:bg-muted transition-colors">
                <td className="px-3.5 py-3">
                  <Link
                    href={vulnDetailHref(vuln.vuln_id, tenantId)}
                    className="font-mono font-semibold text-sky-600 dark:text-sky-400 hover:underline"
                  >
                    {findingLabel(vuln)}
                  </Link>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    {vuln.port ? t("vulns.port", { port: vuln.port }) : t("asset.noPort")}
                    {vuln.assignee ? ` · ${vuln.assignee}` : ` · ${t("asset.unassignedShort")}`}
                  </p>
                </td>
                <td className="px-3.5 py-3">
                  <StatusBadge value={normalizeSeverity(vuln.severity)} map={SEVERITY_STATUS} />
                </td>
                <td className="px-3.5 py-3">
                  <StatusBadge value={vuln.state} map={VULN_LIFECYCLE_STATUS} />
                </td>
                <td className="px-3.5 py-3">
                  <SlaIndicator slaState={vuln.sla_state} dueAt={vuln.due_at} />
                </td>
                <td className="px-3.5 py-3 font-semibold text-foreground">{t.label(requiredAction(vuln))}</td>
                <td className="px-3.5 py-3 text-right">
                  <Button
                    asChild
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs border-border bg-card text-sky-600 dark:text-sky-400"
                  >
                    <Link href={vulnDetailHref(vuln.vuln_id, tenantId)}>{t("asset.act")}</Link>
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function OverviewCard({ asset }: { asset: AssetDetail }) {
  const t = useT();
  const when = useAbsoluteTime();
  return (
    <div className="space-y-4 rounded-xl border border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-foreground border-b border-border pb-2">{t("asset.businessContext")}</p>
      <div className="grid grid-cols-2 gap-3">
        <Field label={t("asset.field.firstDiscovered")} value={when(asset.first_seen)} />
        <Field label={t("asset.field.lastTelemetry")} value={when(asset.last_seen)} />
        <Field label={t("asset.field.ownerEmail")} value={asset.owner_email || t("common.unassigned")} />
        <Field label={t("asset.field.businessUnit")} value={asset.business_unit || t("common.unassigned")} />
        <Field label={t("asset.field.businessService")} value={asset.business_service || t("common.unassigned")} />
        <div>
          <p className="text-[11px] font-medium text-muted-foreground">{t("asset.field.environment")}</p>
          <div className="mt-0.5">
            {asset.environment ? (
              <StatusBadge value={asset.environment} map={ASSET_ENVIRONMENT} />
            ) : (
              <p className="text-xs font-semibold text-foreground">{t("common.unsetValue")}</p>
            )}
          </div>
        </div>
        <div>
          <p className="text-[11px] font-medium text-muted-foreground">{t("asset.field.dataClassification")}</p>
          <div className="mt-0.5">
            {asset.data_classification ? (
              <StatusBadge value={asset.data_classification} map={ASSET_DATA_CLASSIFICATION} />
            ) : (
              <p className="text-xs font-semibold text-foreground">{t("common.unsetValue")}</p>
            )}
          </div>
        </div>
        <div>
          <p className="text-[11px] font-medium text-muted-foreground">{t("asset.field.exposure")}</p>
          <div className="mt-0.5">
            {asset.exposure_level ? (
              <StatusBadge value={asset.exposure_level} map={ASSET_EXPOSURE} />
            ) : (
              <p className="text-xs font-semibold text-foreground">{t("common.unsetValue")}</p>
            )}
          </div>
        </div>
      </div>
      {asset.context_source ? (
        <p className="text-[11px] text-muted-foreground">
          {t("asset.contextWrittenBy", {
            // The badge is gone from this sentence: a pill in the middle of a
            // line of prose reads as a button. The word itself is vocabulary
            // the console already translates.
            source: t.label(
              ASSET_CONTEXT_SOURCE[asset.context_source as keyof typeof ASSET_CONTEXT_SOURCE]
                ?.label ?? asset.context_source ?? "",
            ),
          })}
        </p>
      ) : null}
      <div className="pt-2 border-t border-border">
        <p className="mb-2 text-xs font-semibold text-muted-foreground">
          {t("asset.field.identifiers", { count: asset.identifiers.length })}
        </p>
        <ul className="space-y-1.5">
          {asset.identifiers.map((identifier) => (
            <li
              key={`${identifier.identifier_type}:${identifier.identifier_value}`}
              className="flex items-center justify-between rounded-lg bg-muted p-2 border border-border"
            >
              <Badge variant="secondary" className="uppercase font-semibold text-[10px] bg-muted text-sky-600 dark:text-sky-400">
                {identifier.identifier_type}
              </Badge>
              <span className="font-mono font-bold text-foreground">{identifier.identifier_value}</span>
            </li>
          ))}
        </ul>
      </div>
      {Object.keys(asset.tags).length > 0 ? (
        <div className="pt-2 border-t border-border">
          <p className="mb-1.5 text-xs font-semibold text-muted-foreground">{t("asset.tags")}</p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(asset.tags).map(([key, value]) => (
              <Badge key={key} variant="outline" className="border-border bg-muted text-foreground text-[11px]">
                {key}={value}
              </Badge>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

function NoEndpointCard({ loading }: { loading: boolean }) {
  const t = useT();
  return (
    <div className="space-y-3 rounded-xl border border-dashed border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-foreground">
        {t("asset.endpointTitle")}
      </p>
      {loading ? (
        <p className="text-muted-foreground">{t("asset.endpointChecking")}</p>
      ) : (
        <>
          <p className="leading-relaxed text-muted-foreground">{t("asset.endpointNone")}</p>
          <Button asChild variant="outline" size="sm" className="h-7 border-border text-xs text-sky-600 dark:text-sky-400">
            <Link href="/endpoints">{t("asset.endpointBrowse")}</Link>
          </Button>
        </>
      )}
    </div>
  );
}

function EndpointCard({ device }: { device: EndpointDeviceInfo }) {
  const t = useT();
  const when = useAbsoluteTime();
  // Server-derived against OCTO_ENDPOINT_STALE_HOURS (Agent_plan.md S9) — the
  // threshold is enforced in the API, not recomputed here.
  const isStale = device.status === "stale" && device.last_inventory_at != null;

  return (
    <div className="space-y-4 rounded-xl border border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div>
          <p className="text-sm font-bold uppercase tracking-wider text-foreground">{t("asset.endpointTitle")}</p>
          <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">{device.hostname}</p>
        </div>
        <StatusBadge value={device.reconciliation_status} map={ENDPOINT_RECONCILIATION_STATUS} />
      </div>
      {device.reconciliation_status === "conflict" ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200">
          <AlertDescription>{t("asset.endpointConflict")}</AlertDescription>
        </Alert>
      ) : null}
      {isStale ? (
        <Alert className="border-amber-500/40 bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-200">
          <AlertDescription>{t("asset.endpointStale")}</AlertDescription>
        </Alert>
      ) : null}
      <div className="grid grid-cols-2 gap-3">
        <Field label="OS" value={[device.os_name, device.os_version].filter(Boolean).join(" ") || "—"} />
        <Field label={t("asset.field.architecture")} value={device.os_arch || "—"} />
        <Field label={t("asset.field.agentVersion")} value={device.agent_version || "—"} />
        <Field
          label={t("asset.field.lastInventory")}
          value={when(device.last_inventory_at, t("common.never"))}
        />
      </div>
    </div>
  );
}

function SoftwareTab({
  device,
  software,
  isLoading,
  tenantId,
}: {
  device: EndpointDeviceInfo;
  software: EndpointSoftwareItemInfo[];
  isLoading: boolean;
  tenantId: string;
}) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<"name" | "version" | "publisher" | "source">("name");
  const changesQuery = useEndpointDeviceChanges(device.device_id, tenantId);
  const recentChanges = (changesQuery.data || []).filter((c) => c.snapshot_id === device.latest_snapshot_id);

  const filtered = software
    .filter((item) => !query.trim() || item.name.toLowerCase().includes(query.trim().toLowerCase()))
    .slice()
    .sort((a, b) => (a[sortKey] || "").localeCompare(b[sortKey] || ""));

  return (
    <div className="space-y-3">
      {recentChanges.length > 0 ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-muted-foreground">Since previous snapshot:</span>
          {recentChanges.map((change, idx) => (
            <span key={`${change.event_type}-${change.display_name}-${idx}`} className="inline-flex items-center gap-1">
              <StatusBadge value={change.event_type} map={SOFTWARE_CHANGE_STATUS} />
              <span className="font-mono text-foreground">{change.display_name}</span>
            </span>
          ))}
        </div>
      ) : null}

      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder={t("asset.software.search")}
        className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
      />

      {isLoading ? (
        <EmptyNote>{t("asset.empty.loadingSoftware")}</EmptyNote>
      ) : filtered.length === 0 ? (
        <EmptyNote>{t("asset.noSoftware")}</EmptyNote>
      ) : (
        <div className="overflow-hidden rounded-xl border border-border bg-card shadow-lg backdrop-blur">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border bg-muted text-muted-foreground font-bold uppercase tracking-wider">
              <tr>
                {(["name", "version", "publisher", "source"] as const).map((col) => (
                  <th
                    key={col}
                    className="cursor-pointer px-3.5 py-3 hover:text-sky-600 dark:text-sky-300"
                    onClick={() => setSortKey(col)}
                  >
                    {col}
                  </th>
                ))}
                <th className="px-3.5 py-3">{t("asset.field.architecture")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((item, idx) => (
                <tr key={`${item.name}-${item.version}-${idx}`} className="hover:bg-muted transition-colors">
                  <td className="px-3.5 py-3 font-semibold text-foreground">{item.name}</td>
                  <td className="px-3.5 py-3 font-mono text-foreground">{item.version || "—"}</td>
                  <td className="px-3.5 py-3 text-foreground">{item.publisher || "—"}</td>
                  <td className="px-3.5 py-3 text-foreground">{item.source}</td>
                  <td className="px-3.5 py-3 text-foreground">{item.architecture || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function EditCard({ asset }: { asset: AssetDetail }) {
  const t = useT();
  const update = useUpdateAsset(asset.asset_id);
  const [owner, setOwner] = useState(asset.owner_email || "");
  const [unit, setUnit] = useState(asset.business_unit || "");
  const [service, setService] = useState(asset.business_service || "");
  const [environment, setEnvironment] = useState(asset.environment || CONTEXT_UNSET);
  const [classification, setClassification] = useState(asset.data_classification || CONTEXT_UNSET);
  const [exposure, setExposure] = useState(asset.exposure_level || CONTEXT_UNSET);
  const [crit, setCrit] = useState<string>(
    asset.asset_criticality == null ? CRIT_UNSET : String(asset.asset_criticality),
  );

  useEffect(() => {
    setOwner(asset.owner_email || "");
    setUnit(asset.business_unit || "");
    setService(asset.business_service || "");
    setEnvironment(asset.environment || CONTEXT_UNSET);
    setClassification(asset.data_classification || CONTEXT_UNSET);
    setExposure(asset.exposure_level || CONTEXT_UNSET);
    setCrit(asset.asset_criticality == null ? CRIT_UNSET : String(asset.asset_criticality));
  }, [
    asset.owner_email,
    asset.business_unit,
    asset.business_service,
    asset.environment,
    asset.data_classification,
    asset.exposure_level,
    asset.asset_criticality,
  ]);

  const decommissioned = asset.status === "decommissioned";

  function save() {
    update.mutate({
      owner_email: owner.trim() || null,
      business_unit: unit.trim() || null,
      business_service: service.trim() || null,
      environment: environment === CONTEXT_UNSET ? null : (environment as AssetEnvironment),
      data_classification:
        classification === CONTEXT_UNSET ? null : (classification as AssetDataClassification),
      exposure_level: exposure === CONTEXT_UNSET ? null : (exposure as AssetExposureLevel),
      asset_criticality: crit === CRIT_UNSET ? null : Number(crit),
    });
  }

  return (
    <div className="space-y-4 rounded-xl border border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-foreground border-b border-border pb-2">{t("asset.postureConfigurator")}</p>

      <div className="space-y-1.5">
        <Label htmlFor="owner" className="text-foreground font-semibold">{t("asset.field.ownerEmail")}</Label>
        <Input
          id="owner"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="sec-ops@enterprise.com"
          className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="unit" className="text-foreground font-semibold">{t("asset.field.businessUnit")}</Label>
        <Input
          id="unit"
          value={unit}
          onChange={(e) => setUnit(e.target.value)}
          placeholder="e.g. Core Infrastructure"
          className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="service" className="text-foreground font-semibold">{t("asset.field.businessService")}</Label>
        <Input
          id="service"
          value={service}
          onChange={(e) => setService(e.target.value)}
          placeholder="e.g. payments-api"
          className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
        />
      </div>

      <div className="space-y-1.5">
        <Label className="text-foreground font-semibold">{t("asset.field.environment")}</Label>
        <Select value={environment} onValueChange={setEnvironment}>
          <SelectTrigger className="bg-muted border-border text-foreground">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value={CONTEXT_UNSET}>{t("common.unsetValue")}</SelectItem>
            {ASSET_ENVIRONMENTS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_ENVIRONMENT[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1.5">
        <Label className="text-foreground font-semibold">{t("asset.field.dataClassification")}</Label>
        <Select value={classification} onValueChange={setClassification}>
          <SelectTrigger className="bg-muted border-border text-foreground">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value={CONTEXT_UNSET}>{t("common.unsetValue")}</SelectItem>
            {ASSET_DATA_CLASSIFICATIONS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_DATA_CLASSIFICATION[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1.5">
        <Label className="text-foreground font-semibold">{t("asset.field.exposure")}</Label>
        <Select value={exposure} onValueChange={setExposure}>
          <SelectTrigger className="bg-muted border-border text-foreground">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value={CONTEXT_UNSET}>{t("common.unsetValue")}</SelectItem>
            {ASSET_EXPOSURE_LEVELS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_EXPOSURE[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-[11px] text-muted-foreground">
          A decision about how this asset is treated — not inferred from scan IPs.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label className="text-foreground font-semibold">{t("asset.edit.criticality")}</Label>
        <Select value={crit} onValueChange={setCrit}>
          <SelectTrigger className="bg-muted border-border text-foreground">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-card border-border text-foreground">
            <SelectItem value={CRIT_UNSET}>{t("asset.edit.critUnset")}</SelectItem>
            {[0, 1, 2, 3, 4].map((n) => (
              <SelectItem key={n} value={String(n)}>
                L{n} — {ASSET_CRITICALITY[n].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-border">
        <Button onClick={save} disabled={update.isPending} size="sm" className="bg-sky-600 hover:bg-sky-500 text-foreground font-semibold">
          {update.isPending ? t("asset.edit.saving") : t("asset.edit.save")}
        </Button>

        {!decommissioned ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" size="sm" className="border-rose-500/40 text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:bg-rose-950/60">
                Decommission
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent className="bg-card border-border text-foreground">
              <AlertDialogHeader>
                <AlertDialogTitle className="text-foreground">{t("asset.decommissionTitle")}</AlertDialogTitle>
                <AlertDialogDescription className="text-muted-foreground text-xs">
                  {t("asset.decommissionBody")}
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel className="border-border bg-muted text-foreground hover:bg-muted">{t("common.cancel")}</AlertDialogCancel>
                <AlertDialogAction 
                  onClick={() => update.mutate({ status: "decommissioned" })}
                  className="bg-rose-600 text-foreground hover:bg-rose-500"
                >
                  {t("asset.decommissionConfirm")}
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : (
          <Badge variant="secondary" className="bg-muted text-muted-foreground">{t.label("decommissioned")}</Badge>
        )}
      </div>
    </div>
  );
}

function ContextHistoryCard({ assetId, tenantId }: { assetId: string; tenantId: string }) {
  const t = useT();
  const eventsQuery = useAssetContextEvents(assetId, tenantId);
  const events = eventsQuery.data?.items ?? [];

  return (
    <div className="space-y-3 rounded-xl border border-border bg-card p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-foreground border-b border-border pb-2">
        {t("asset.contextHistory")}
      </p>
      {eventsQuery.isLoading ? (
        <p className="text-muted-foreground">{t("asset.contextLoading")}</p>
      ) : events.length === 0 ? (
        <p className="text-muted-foreground">{t("asset.contextEmpty")}</p>
      ) : (
        <ol className="space-y-3" aria-label={t("asset.contextTrail")}>
          {events.map((event) => (
            <ContextHistoryItem key={event.id} event={event} />
          ))}
        </ol>
      )}
    </div>
  );
}

function ContextHistoryItem({ event }: { event: AssetContextEvent }) {
  return (
    <li className="relative border-l border-border pl-4 before:absolute before:-left-1 before:top-1.5 before:h-2 before:w-2 before:rounded-full before:bg-sky-500/70">
      <p className="font-semibold text-foreground">{describeContextEvent(event)}</p>
      <p className="mt-0.5 text-[11px] text-muted-foreground">
        {event.occurred_at ? new Date(event.occurred_at).toLocaleString() : "—"}
        {" · "}
        {event.actor ? <span className="font-mono text-foreground">{event.actor}</span> : <span>platform</span>}
        {event.source ? (
          <>
            {" · "}
            <StatusBadge value={event.source} map={ASSET_CONTEXT_SOURCE} />
          </>
        ) : null}
      </p>
    </li>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-[11px] font-medium text-muted-foreground">{label}</p>
      <p className="text-xs font-semibold text-foreground mt-0.5">{value}</p>
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card px-4 py-8 text-center text-xs text-muted-foreground backdrop-blur">
      {children}
    </div>
  );
}

