"use client";

import Link from "next/link";
import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft, Server, Shield, ShieldAlert, Cpu, Globe, Hash, Clock, User, Building } from "lucide-react";
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
import { StatusBadge } from "@/components/status-badge";
import { useAssetDetail, useUpdateAsset } from "@/hooks/use-assets";
import { useRunHosts, useRunPorts, useRuns, useRunVulns } from "@/hooks/use-runs";
import { useAuthStore } from "@/lib/auth-store";
import type { AssetDetail } from "@/lib/api";
import { ASSET_CRITICALITY, ASSET_STATUS, SEVERITY_STATUS } from "@/lib/config/statuses";
import { formatLocation, normalizeSeverity, pickLatestRun } from "@/lib/run-data";

const CRIT_UNSET = "unset";

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
        Back to Assets Inventory
      </Link>
    </Button>
  );
}

function AssetDetailInner() {
  const searchParams = useSearchParams();
  const assetId = (searchParams.get("assetId") || "").trim();
  const { canOperate } = useAuthStore();

  const detailQuery = useAssetDetail(assetId || null);
  const asset = detailQuery.data;
  const ip = asset?.identifiers.find((i) => i.identifier_type === "ip")?.identifier_value ?? null;

  const runsQuery = useRuns();
  const latest = pickLatestRun(runsQuery.data || []);
  const corrRunId = ip && latest ? latest.run_id : "";
  const vulnsQuery = useRunVulns(corrRunId, { host: ip });
  const hostsQuery = useRunHosts(corrRunId);
  const portsQuery = useRunPorts(corrRunId);

  const hostRow = (hostsQuery.data || []).find((h) => h.host === ip) || null;
  const assetPorts = (portsQuery.data || []).filter((p) => ip && p.hosts.includes(ip));
  const vulns = vulnsQuery.data || [];

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
    return <p className="text-sm text-slate-400">Loading asset telemetry data…</p>;
  }

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
            </div>
            <p className="mt-1 font-mono text-xs text-slate-400">UUID: {asset.asset_id}</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <OverviewCard asset={asset} />
          {canOperate ? <EditCard asset={asset} /> : null}
        </div>

        <div className="lg:col-span-2 space-y-4">
          <Tabs defaultValue="vulns">
            <TabsList className="bg-slate-900/90 border border-slate-800">
              <TabsTrigger value="vulns" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Vulnerabilities ({vulns.length})
              </TabsTrigger>
              <TabsTrigger value="ports" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Open Ports ({assetPorts.length})
              </TabsTrigger>
              <TabsTrigger value="host" className="data-[state=active]:bg-slate-800 data-[state=active]:text-sky-300">
                Host Telemetry
              </TabsTrigger>
            </TabsList>

            <TabsContent value="vulns" className="space-y-3 pt-3">
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
              <p className="text-xs text-slate-400">
                Findings correlated from active run{" "}
                {latest ? <code className="font-mono text-sky-400">{latest.run_id}</code> : ""}.
              </p>
            </TabsContent>

            <TabsContent value="ports" className="pt-3">
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
            </TabsContent>

            <TabsContent value="host" className="space-y-3 pt-3">
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
          </Tabs>
        </div>
      </div>
    </div>
  );
}

function OverviewCard({ asset }: { asset: AssetDetail }) {
  return (
    <div className="space-y-4 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 text-xs shadow-lg backdrop-blur">
      <p className="text-sm font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">Asset Telemetry Overview</p>
      <div className="grid grid-cols-2 gap-3">
        <Field label="First Discovered" value={new Date(asset.first_seen).toLocaleString()} />
        <Field label="Last Telemetry" value={new Date(asset.last_seen).toLocaleString()} />
        <Field label="Owner Email" value={asset.owner_email || "Unassigned"} />
        <Field label="Business Unit" value={asset.business_unit || "Unassigned"} />
      </div>
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

function EditCard({ asset }: { asset: AssetDetail }) {
  const update = useUpdateAsset(asset.asset_id);
  const [owner, setOwner] = useState(asset.owner_email || "");
  const [unit, setUnit] = useState(asset.business_unit || "");
  const [crit, setCrit] = useState<string>(
    asset.asset_criticality == null ? CRIT_UNSET : String(asset.asset_criticality),
  );

  useEffect(() => {
    setOwner(asset.owner_email || "");
    setUnit(asset.business_unit || "");
    setCrit(asset.asset_criticality == null ? CRIT_UNSET : String(asset.asset_criticality));
  }, [asset.owner_email, asset.business_unit, asset.asset_criticality]);

  const decommissioned = asset.status === "decommissioned";

  function save() {
    update.mutate({
      owner_email: owner.trim() || null,
      business_unit: unit.trim() || null,
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

