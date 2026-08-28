"use client";

import Link from "next/link";
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
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { useAssetContextEvents, useAssetDetail, useUpdateAsset } from "@/hooks/use-assets";
import { useTrackedVulnerabilities } from "@/hooks/use-vulnerabilities";
import {
  useAssetSoftware,
  useEndpointDeviceChanges,
  useEndpointDevicesForAsset,
} from "@/hooks/use-endpoint-inventory";
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
    <Suspense fallback={<p className="text-sm text-slate-400">Loading asset posture details…</p>}>
      <AssetDetailInner />
    </Suspense>
  );
}

function BackToAssets() {
  return (
    <Button asChild variant="ghost" size="sm" className="gap-2 px-0 text-slate-400 hover:text-slate-100 hover:bg-transparent">
      <Link href="/assets">
        <ArrowLeft className="h-4 w-4 text-sky-400" />
        Back to Assets
      </Link>
    </Button>
  );
}

function AssetDetailInner() {
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

  if (!assetId) {
    return (
      <div className="space-y-4">
        <BackToAssets />
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>Missing assetId query parameter.</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (detailQuery.isLoading || !asset) {
    if (detailQuery.error) {
      return (
        <div className="space-y-4">
          <BackToAssets />
          <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
            <AlertDescription>{(detailQuery.error as Error).message}</AlertDescription>
          </Alert>
        </div>
      );
    }
    return <p className="text-sm text-slate-400">Loading asset security view…</p>;
  }

  const risk = asset.risk;
  const estateLevel = risk?.estate_risk && risk.estate_risk in RISK_LEVEL_STATUS ? risk.estate_risk : null;
  const unassigned = risk?.unassigned ?? 0;
  const breached = risk?.breached ?? 0;
  const untriaged = risk?.untriaged ?? 0;

  return (
    <div className="space-y-6">
      <div className="space-y-3 border-b border-slate-800/80 pb-5">
        <BackToAssets />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-extrabold font-mono tracking-tight text-slate-100">
                {asset.identifiers.find((i) => i.identifier_type === "ip")?.identifier_value ||
                  asset.asset_id}
              </h1>
              <StatusBadge value={asset.status} map={ASSET_STATUS} />
              {asset.asset_criticality != null ? (
                <StatusBadge value={String(asset.asset_criticality)} map={ASSET_CRITICALITY} />
              ) : (
                <Badge variant="outline" className="border-slate-700 bg-slate-900 text-slate-400">
                  Criticality Unset
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
            <p className="mt-1 text-xs text-slate-400">
              {asset.business_service || "No business service"}
              {" · "}
              {asset.owner_email || "No owner"}
              {" · "}
              <span className="font-mono">{asset.asset_id}</span>
            </p>
          </div>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Asset risk"
          value={assetRiskLabel(risk)}
          hint="Worst open NIST level"
          decorationColor={estateLevel === "very_high" || estateLevel === "high" ? "rose" : "sky"}
        />
        <KpiCard
          label="Open findings"
          value={risk?.open_total ?? 0}
          hint={`${untriaged} untriaged`}
          href={vulnListHref({ assetId })}
        />
        <KpiCard
          label="Unassigned"
          value={unassigned}
          hint="Need a remediation owner"
          href={unassigned ? vulnListHref({ assetId, unassigned: true }) : undefined}
          decorationColor={unassigned ? "amber" : "slate"}
        />
        <KpiCard
          label="SLA breached"
          value={breached}
          hint="Act on these first"
          href={breached ? vulnListHref({ assetId, sla: "breached" }) : undefined}
          decorationColor={breached ? "rose" : "slate"}
        />
      </div>

      {unassigned > 0 || breached > 0 ? (
        <Alert className="border-amber-500/30 bg-amber-950/20 text-amber-100">
          <AlertDescription className="text-xs">
            Required now:{" "}
            {breached > 0 ? (
              <>
                {breached.toLocaleString()} SLA-breached finding{breached === 1 ? "" : "s"}
              </>
            ) : null}
            {breached > 0 && unassigned > 0 ? " and " : null}
            {unassigned > 0 ? (
              <>
                {unassigned.toLocaleString()} without a remediation owner
              </>
            ) : null}
            . Box owner is {asset.owner_email || "unassigned"} — assign or move the findings below.
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
            <TabsList className="bg-slate-900/90 border border-slate-800">
              <TabsTrigger value="findings" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Findings ({trackedOpen})
              </TabsTrigger>
              <TabsTrigger value="software" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Software ({software.length})
              </TabsTrigger>
              <TabsTrigger value="evidence" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Scan evidence
              </TabsTrigger>
              <TabsTrigger value="history" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                History
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

            <TabsContent value="software" className="space-y-3 pt-3">
              {device ? (
                <SoftwareTab
                  device={device}
                  software={software}
                  isLoading={softwareQuery.isLoading}
                  tenantId={tenantId}
                />
              ) : (
                <EmptyNote>
                  No Lariska agent is correlated to this asset yet — software inventory appears
                  after the endpoint links here.
                </EmptyNote>
              )}
            </TabsContent>

            <TabsContent value="evidence" className="space-y-4 pt-3">
              <p className="text-xs text-slate-400">
                Last scan correlation
                {latest ? (
                  <>
                    {" "}
                    from run <code className="font-mono text-sky-400">{latest.run_id}</code>
                  </>
                ) : (
                  " — no run on disk"
                )}
                . Tracked findings above are the working set.
              </p>
              {!ip ? (
                <EmptyNote>No IP identifier — cannot correlate scan findings.</EmptyNote>
              ) : vulnsQuery.isLoading ? (
                <EmptyNote>Correlating findings from scan stream…</EmptyNote>
              ) : vulns.length === 0 ? (
                <EmptyNote>No vulnerability findings detected for this asset in the latest scan run.</EmptyNote>
              ) : (
                <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg backdrop-blur">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-bold uppercase tracking-wider">
                      <tr>
                        <th className="px-3.5 py-3">CVE / Script ID</th>
                        <th className="px-3.5 py-3">Port</th>
                        <th className="px-3.5 py-3">CVSS Score</th>
                        <th className="px-3.5 py-3">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {vulns.map((v, idx) => (
                        <tr
                          key={`${v.cve || v.script_id}-${v.port}-${idx}`}
                          className="hover:bg-slate-800/40 transition-colors"
                        >
                          <td className="px-3.5 py-3 font-mono font-semibold text-sky-400">
                            {v.cve || v.script_id || "—"}
                          </td>
                          <td className="px-3.5 py-3 font-mono text-slate-300">{v.port || "—"}</td>
                          <td className="px-3.5 py-3">
                            <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-bold tabular-nums text-rose-300 border border-rose-500/30">
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
                  meta: <span className="font-semibold text-slate-200">{row.host_count} hosts</span>,
                }))}
                activeKey={null}
                onSelect={() => {}}
                emptyMessage={ip ? "No open ports recorded for this asset in the latest run." : "No IP to correlate."}
              />
              {hostRow ? (
                <div className="grid grid-cols-2 gap-4 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
                  <Field label="Hostname (Reverse PTR)" value={hostRow.hostname || hostRow.names[0] || "—"} />
                  <Field label="GeoIP Location" value={formatLocation(hostRow) || "—"} />
                  <Field
                    label="Detected OS"
                    value={
                      hostRow.os_name
                        ? `${hostRow.os_name}${hostRow.os_accuracy ? ` (${hostRow.os_accuracy}% accuracy)` : ""}`
                        : "—"
                    }
                  />
                  <Field label="Total Findings" value={String(hostRow.vulnerability_count)} />
                </div>
              ) : (
                <EmptyNote>
                  {ip ? "This asset was not detected as alive in the latest scan run." : "No IP to correlate."}
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
  if (isLoading) {
    return <EmptyNote>Loading tracked findings…</EmptyNote>;
  }
  if (findings.length === 0) {
    return (
      <EmptyNote>
        No open tracked findings on this asset. Closed history lives in the{" "}
        <Link href={vulnListHref({ assetId })} className="text-sky-400 underline underline-offset-2">
          Vulnerability Center
        </Link>
        .
      </EmptyNote>
    );
  }
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">
        Working set of tracked findings — lifecycle, owner and the next required action.
        {total > findings.length ? ` Showing ${findings.length} of ${total}.` : ""}{" "}
        <Link href={vulnListHref({ assetId })} className="text-sky-400 underline underline-offset-2">
          Open in Vulnerability Center
        </Link>
        {" · "}
        <Link href="/remediation" className="text-sky-400 underline underline-offset-2">
          Remediation board
        </Link>
      </p>
      <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg backdrop-blur">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-bold uppercase tracking-wider">
            <tr>
              <th className="px-3.5 py-3">Finding</th>
              <th className="px-3.5 py-3">Severity</th>
              <th className="px-3.5 py-3">Lifecycle</th>
              <th className="px-3.5 py-3">SLA</th>
              <th className="px-3.5 py-3">Required</th>
              <th className="px-3.5 py-3" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {findings.map((vuln) => (
              <tr key={vuln.vuln_id} className="hover:bg-slate-800/40 transition-colors">
                <td className="px-3.5 py-3">
                  <Link
                    href={vulnDetailHref(vuln.vuln_id, tenantId)}
                    className="font-mono font-semibold text-sky-400 hover:underline"
                  >
                    {findingLabel(vuln)}
                  </Link>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    {vuln.port ? `port ${vuln.port}` : "no port"}
                    {vuln.assignee ? ` · ${vuln.assignee}` : " · unassigned"}
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
                <td className="px-3.5 py-3 font-semibold text-slate-200">{requiredAction(vuln)}</td>
                <td className="px-3.5 py-3 text-right">
                  <Button
                    asChild
                    variant="outline"
                    size="sm"
                    className="h-7 text-xs border-slate-800 bg-slate-900 text-sky-400"
                  >
                    <Link href={vulnDetailHref(vuln.vuln_id, tenantId)}>Act</Link>
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
  return (
    <div className="space-y-4 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">Business context</p>
      <div className="grid grid-cols-2 gap-3">
        <Field label="First Discovered" value={new Date(asset.first_seen).toLocaleString()} />
        <Field label="Last Telemetry" value={new Date(asset.last_seen).toLocaleString()} />
        <Field label="Owner Email" value={asset.owner_email || "Unassigned"} />
        <Field label="Business Unit" value={asset.business_unit || "Unassigned"} />
        <Field label="Business Service" value={asset.business_service || "Unassigned"} />
        <div>
          <p className="text-[11px] font-medium text-slate-400">Environment</p>
          <div className="mt-0.5">
            {asset.environment ? (
              <StatusBadge value={asset.environment} map={ASSET_ENVIRONMENT} />
            ) : (
              <p className="text-xs font-semibold text-slate-200">Unset</p>
            )}
          </div>
        </div>
        <div>
          <p className="text-[11px] font-medium text-slate-400">Data Classification</p>
          <div className="mt-0.5">
            {asset.data_classification ? (
              <StatusBadge value={asset.data_classification} map={ASSET_DATA_CLASSIFICATION} />
            ) : (
              <p className="text-xs font-semibold text-slate-200">Unset</p>
            )}
          </div>
        </div>
        <div>
          <p className="text-[11px] font-medium text-slate-400">Exposure</p>
          <div className="mt-0.5">
            {asset.exposure_level ? (
              <StatusBadge value={asset.exposure_level} map={ASSET_EXPOSURE} />
            ) : (
              <p className="text-xs font-semibold text-slate-200">Unset</p>
            )}
          </div>
        </div>
      </div>
      {asset.context_source ? (
        <p className="text-[11px] text-slate-500">
          Context last written by{" "}
          <StatusBadge value={asset.context_source} map={ASSET_CONTEXT_SOURCE} />
          {" — "}
          exposure is an operator decision, not a scan measurement.
        </p>
      ) : null}
      <div className="pt-2 border-t border-slate-800">
        <p className="mb-2 text-xs font-semibold text-slate-400">
          Identifiers ({asset.identifiers.length})
        </p>
        <ul className="space-y-1.5">
          {asset.identifiers.map((identifier) => (
            <li
              key={`${identifier.identifier_type}:${identifier.identifier_value}`}
              className="flex items-center justify-between rounded-lg bg-slate-950/60 p-2 border border-slate-800/60"
            >
              <Badge variant="secondary" className="uppercase font-semibold text-[10px] bg-slate-800 text-sky-400">
                {identifier.identifier_type}
              </Badge>
              <span className="font-mono font-bold text-slate-200">{identifier.identifier_value}</span>
            </li>
          ))}
        </ul>
      </div>
      {Object.keys(asset.tags).length > 0 ? (
        <div className="pt-2 border-t border-slate-800">
          <p className="mb-1.5 text-xs font-semibold text-slate-400">Asset Tags</p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(asset.tags).map(([key, value]) => (
              <Badge key={key} variant="outline" className="border-slate-700 bg-slate-950 text-slate-300 text-[11px]">
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
  return (
    <div className="space-y-3 rounded-xl border border-dashed border-slate-700/80 bg-slate-900/40 p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-slate-300">Endpoint (Lariska)</p>
      {loading ? (
        <p className="text-slate-500">Checking for linked agent…</p>
      ) : (
        <>
          <p className="leading-relaxed text-slate-400">
            No Lariska agent is correlated to this network asset yet. Install the endpoint agent with a
            tenant provisioning key; inventory links here by hostname / platform identifiers.
          </p>
          <Button asChild variant="outline" size="sm" className="h-7 border-slate-700 text-xs text-sky-400">
            <Link href="/endpoints">Browse endpoints</Link>
          </Button>
        </>
      )}
    </div>
  );
}

function EndpointCard({ device }: { device: EndpointDeviceInfo }) {
  // Server-derived against OCTO_ENDPOINT_STALE_HOURS (Agent_plan.md S9) — the
  // threshold is enforced in the API, not recomputed here.
  const isStale = device.status === "stale" && device.last_inventory_at != null;

  return (
    <div className="space-y-4 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2">
        <div>
          <p className="text-sm font-bold uppercase tracking-wider text-slate-200">Endpoint (Lariska)</p>
          <p className="mt-0.5 font-mono text-[10px] text-slate-500">{device.hostname}</p>
        </div>
        <StatusBadge value={device.reconciliation_status} map={ENDPOINT_RECONCILIATION_STATUS} />
      </div>
      {device.reconciliation_status === "conflict" ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>
            A platform identifier on this device is already claimed by another endpoint in this
            tenant. Not auto-merged — review manually.
          </AlertDescription>
        </Alert>
      ) : null}
      {isStale ? (
        <Alert className="border-amber-500/40 bg-amber-950/30 text-amber-200">
          <AlertDescription>
            No inventory received within the configured staleness window — this endpoint may be
            offline.
          </AlertDescription>
        </Alert>
      ) : null}
      <div className="grid grid-cols-2 gap-3">
        <Field label="OS" value={[device.os_name, device.os_version].filter(Boolean).join(" ") || "—"} />
        <Field label="Architecture" value={device.os_arch || "—"} />
        <Field label="Agent Version" value={device.agent_version || "—"} />
        <Field
          label="Last Inventory"
          value={device.last_inventory_at ? new Date(device.last_inventory_at).toLocaleString() : "never"}
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
          <span className="text-xs font-semibold text-slate-400">Since previous snapshot:</span>
          {recentChanges.map((change, idx) => (
            <span key={`${change.event_type}-${change.display_name}-${idx}`} className="inline-flex items-center gap-1">
              <StatusBadge value={change.event_type} map={SOFTWARE_CHANGE_STATUS} />
              <span className="font-mono text-slate-300">{change.display_name}</span>
            </span>
          ))}
        </div>
      ) : null}

      <Input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search installed software…"
        className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
      />

      {isLoading ? (
        <EmptyNote>Loading installed software…</EmptyNote>
      ) : filtered.length === 0 ? (
        <EmptyNote>No installed software recorded for this endpoint.</EmptyNote>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg backdrop-blur">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 bg-slate-950/80 text-slate-400 font-bold uppercase tracking-wider">
              <tr>
                {(["name", "version", "publisher", "source"] as const).map((col) => (
                  <th
                    key={col}
                    className="cursor-pointer px-3.5 py-3 hover:text-sky-300"
                    onClick={() => setSortKey(col)}
                  >
                    {col}
                  </th>
                ))}
                <th className="px-3.5 py-3">Architecture</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.map((item, idx) => (
                <tr key={`${item.name}-${item.version}-${idx}`} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-3.5 py-3 font-semibold text-slate-200">{item.name}</td>
                  <td className="px-3.5 py-3 font-mono text-slate-300">{item.version || "—"}</td>
                  <td className="px-3.5 py-3 text-slate-300">{item.publisher || "—"}</td>
                  <td className="px-3.5 py-3 text-slate-300">{item.source}</td>
                  <td className="px-3.5 py-3 text-slate-300">{item.architecture || "—"}</td>
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
    <div className="space-y-4 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">Asset Posture Configurator</p>

      <div className="space-y-1.5">
        <Label htmlFor="owner" className="text-slate-300 font-semibold">Owner Email</Label>
        <Input
          id="owner"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="sec-ops@enterprise.com"
          className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="unit" className="text-slate-300 font-semibold">Business Unit</Label>
        <Input
          id="unit"
          value={unit}
          onChange={(e) => setUnit(e.target.value)}
          placeholder="e.g. Core Infrastructure"
          className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="service" className="text-slate-300 font-semibold">Business Service</Label>
        <Input
          id="service"
          value={service}
          onChange={(e) => setService(e.target.value)}
          placeholder="e.g. payments-api"
          className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
        />
      </div>

      <div className="space-y-1.5">
        <Label className="text-slate-300 font-semibold">Environment</Label>
        <Select value={environment} onValueChange={setEnvironment}>
          <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
            <SelectItem value={CONTEXT_UNSET}>Unset</SelectItem>
            {ASSET_ENVIRONMENTS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_ENVIRONMENT[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1.5">
        <Label className="text-slate-300 font-semibold">Data Classification</Label>
        <Select value={classification} onValueChange={setClassification}>
          <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
            <SelectItem value={CONTEXT_UNSET}>Unset</SelectItem>
            {ASSET_DATA_CLASSIFICATIONS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_DATA_CLASSIFICATION[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-1.5">
        <Label className="text-slate-300 font-semibold">Exposure</Label>
        <Select value={exposure} onValueChange={setExposure}>
          <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
            <SelectItem value={CONTEXT_UNSET}>Unset</SelectItem>
            {ASSET_EXPOSURE_LEVELS.map((value) => (
              <SelectItem key={value} value={value}>
                {ASSET_EXPOSURE[value].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-[11px] text-slate-500">
          A decision about how this asset is treated — not inferred from scan IPs.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label className="text-slate-300 font-semibold">Asset Criticality (0 - 4)</Label>
        <Select value={crit} onValueChange={setCrit}>
          <SelectTrigger className="bg-slate-950 border-slate-800 text-slate-200">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
            <SelectItem value={CRIT_UNSET}>Unset (Heuristic Evaluation)</SelectItem>
            {[0, 1, 2, 3, 4].map((n) => (
              <SelectItem key={n} value={String(n)}>
                L{n} — {ASSET_CRITICALITY[n].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-center justify-between pt-3 border-t border-slate-800">
        <Button onClick={save} disabled={update.isPending} size="sm" className="bg-sky-600 hover:bg-sky-500 text-white font-semibold">
          {update.isPending ? "Updating…" : "Save Changes"}
        </Button>

        {!decommissioned ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" size="sm" className="border-rose-500/40 text-rose-400 hover:bg-rose-950/60">
                Decommission
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent className="bg-slate-900 border-slate-800 text-slate-100">
              <AlertDialogHeader>
                <AlertDialogTitle className="text-slate-100">Decommission this asset?</AlertDialogTitle>
                <AlertDialogDescription className="text-slate-400 text-xs">
                  Marks the asset as decommissioned. Decommissioning is logged into Postgres state.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel className="border-slate-800 bg-slate-950 text-slate-300 hover:bg-slate-800">Cancel</AlertDialogCancel>
                <AlertDialogAction 
                  onClick={() => update.mutate({ status: "decommissioned" })}
                  className="bg-rose-600 text-white hover:bg-rose-500"
                >
                  Decommission Asset
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : (
          <Badge variant="secondary" className="bg-slate-800 text-slate-400">Decommissioned</Badge>
        )}
      </div>
    </div>
  );
}

function ContextHistoryCard({ assetId, tenantId }: { assetId: string; tenantId: string }) {
  const eventsQuery = useAssetContextEvents(assetId, tenantId);
  const events = eventsQuery.data?.items ?? [];

  return (
    <div className="space-y-3 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">
        Context history
      </p>
      {eventsQuery.isLoading ? (
        <p className="text-slate-500">Loading context changes…</p>
      ) : events.length === 0 ? (
        <p className="text-slate-500">No business-context changes recorded yet.</p>
      ) : (
        <ol className="space-y-3" aria-label="Asset context audit trail">
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
    <li className="relative border-l border-slate-800 pl-4 before:absolute before:-left-1 before:top-1.5 before:h-2 before:w-2 before:rounded-full before:bg-sky-500/70">
      <p className="font-semibold text-slate-200">{describeContextEvent(event)}</p>
      <p className="mt-0.5 text-[11px] text-slate-400">
        {event.occurred_at ? new Date(event.occurred_at).toLocaleString() : "—"}
        {" · "}
        {event.actor ? <span className="font-mono text-slate-300">{event.actor}</span> : <span>platform</span>}
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
      <p className="text-[11px] font-medium text-slate-400">{label}</p>
      <p className="text-xs font-semibold text-slate-200 mt-0.5">{value}</p>
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 px-4 py-8 text-center text-xs text-slate-400 backdrop-blur">
      {children}
    </div>
  );
}

