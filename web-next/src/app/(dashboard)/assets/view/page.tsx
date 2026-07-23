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
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading asset…</p>}>
      <AssetDetailInner />
    </Suspense>
  );
}

function BackToAssets() {
  return (
    <Button asChild variant="ghost" size="sm" className="gap-2 px-0">
      <Link href="/assets">
        <ArrowLeft className="h-4 w-4" />
        Assets
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

  // Correlate the cross-run asset with its most recent per-run observation
  // (vulnerabilities/ports/OS/geo) by its primary IP. Gated on the IP being
  // known so we never fetch a whole run's findings for nothing.
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
        <Alert variant="destructive">
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
          <Alert variant="destructive">
            <AlertDescription>{(detailQuery.error as Error).message}</AlertDescription>
          </Alert>
        </div>
      );
    }
    return <p className="text-sm text-muted-foreground">Loading asset…</p>;
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <BackToAssets />
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            {asset.identifiers.find((i) => i.identifier_type === "ip")?.identifier_value ||
              asset.asset_id}
          </h1>
          <StatusBadge value={asset.status} map={ASSET_STATUS} />
          {asset.asset_criticality != null ? (
            <StatusBadge value={String(asset.asset_criticality)} map={ASSET_CRITICALITY} />
          ) : (
            <Badge variant="outline">criticality unset</Badge>
          )}
        </div>
        <p className="font-mono text-xs text-muted-foreground">{asset.asset_id}</p>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <OverviewCard asset={asset} />
          {canOperate ? <EditCard asset={asset} /> : null}
        </div>

        <div className="lg:col-span-2">
          <Tabs defaultValue="vulns">
            <TabsList>
              <TabsTrigger value="vulns">Vulnerabilities ({vulns.length})</TabsTrigger>
              <TabsTrigger value="ports">Ports ({assetPorts.length})</TabsTrigger>
              <TabsTrigger value="host">Host</TabsTrigger>
            </TabsList>

            <TabsContent value="vulns" className="space-y-2">
              {!ip ? (
                <EmptyNote>No IP identifier — cannot correlate scan findings.</EmptyNote>
              ) : vulnsQuery.isLoading ? (
                <EmptyNote>Loading findings…</EmptyNote>
              ) : vulns.length === 0 ? (
                <EmptyNote>No findings for this asset in the latest run.</EmptyNote>
              ) : (
                <div className="overflow-hidden rounded-lg border bg-white">
                  <table className="w-full text-sm">
                    <thead className="bg-slate-50 text-xs uppercase text-muted-foreground">
                      <tr>
                        <th className="px-3 py-2 text-left">CVE / Script</th>
                        <th className="px-3 py-2 text-left">Port</th>
                        <th className="px-3 py-2 text-left">CVSS</th>
                        <th className="px-3 py-2 text-left">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vulns.map((v, idx) => (
                        <tr
                          key={`${v.cve || v.script_id}-${v.port}-${idx}`}
                          className="border-t border-slate-100"
                        >
                          <td className="px-3 py-2 font-mono text-xs">
                            {v.cve || v.script_id || "—"}
                          </td>
                          <td className="px-3 py-2 tabular-nums">{v.port || "—"}</td>
                          <td className="px-3 py-2 tabular-nums">
                            {v.cvss4 ?? v.cvss ?? "—"}
                          </td>
                          <td className="px-3 py-2">
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
              <p className="text-xs text-muted-foreground">
                Findings from the latest run
                {latest ? ` (${latest.run_id})` : ""} for this asset&apos;s IP.
              </p>
            </TabsContent>

            <TabsContent value="ports">
              <EntityList
                items={assetPorts.map((row) => ({
                  key: `${row.port}/${row.protocol || "tcp"}`,
                  title: `:${row.port}${row.protocol ? `/${row.protocol}` : ""}`,
                  subtitle: row.vulnerability_count
                    ? `${row.vulnerability_count} vulns`
                    : "no vulns",
                  meta: <span className="tabular-nums">{row.host_count}</span>,
                }))}
                activeKey={null}
                onSelect={() => {}}
                emptyMessage={ip ? "No open ports for this asset in the latest run." : "No IP to correlate."}
              />
            </TabsContent>

            <TabsContent value="host" className="space-y-3">
              {hostRow ? (
                <div className="grid grid-cols-2 gap-3 rounded-lg border bg-white p-4 text-sm">
                  <Field label="Hostname" value={hostRow.hostname || hostRow.names[0] || "—"} />
                  <Field label="Location" value={formatLocation(hostRow) || "—"} />
                  <Field
                    label="OS"
                    value={
                      hostRow.os_name
                        ? `${hostRow.os_name}${hostRow.os_accuracy ? ` (${hostRow.os_accuracy}%)` : ""}`
                        : "—"
                    }
                  />
                  <Field label="Findings" value={String(hostRow.vulnerability_count)} />
                </div>
              ) : (
                <EmptyNote>
                  {ip ? "This asset was not alive in the latest run." : "No IP to correlate."}
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
    <div className="space-y-4 rounded-lg border bg-white p-4 text-sm">
      <p className="font-medium text-slate-900">Overview</p>
      <div className="grid grid-cols-2 gap-3">
        <Field label="First seen" value={new Date(asset.first_seen).toLocaleString()} />
        <Field label="Last seen" value={new Date(asset.last_seen).toLocaleString()} />
        <Field label="Owner" value={asset.owner_email || "—"} />
        <Field label="Business unit" value={asset.business_unit || "—"} />
      </div>
      <div>
        <p className="mb-1 text-xs text-muted-foreground">
          Identifiers ({asset.identifiers.length})
        </p>
        <ul className="space-y-1">
          {asset.identifiers.map((identifier) => (
            <li
              key={`${identifier.identifier_type}:${identifier.identifier_value}`}
              className="flex items-center gap-2"
            >
              <Badge variant="secondary">{identifier.identifier_type}</Badge>
              <span className="font-mono text-xs">{identifier.identifier_value}</span>
            </li>
          ))}
        </ul>
      </div>
      {Object.keys(asset.tags).length > 0 ? (
        <div>
          <p className="mb-1 text-xs text-muted-foreground">Tags</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(asset.tags).map(([key, value]) => (
              <Badge key={key} variant="secondary">
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

  // Re-sync local form state if the asset is refetched/updated elsewhere.
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
    <div className="space-y-4 rounded-lg border bg-white p-4 text-sm">
      <p className="font-medium text-slate-900">Edit</p>

      <div className="space-y-1">
        <Label htmlFor="owner">Owner email</Label>
        <Input
          id="owner"
          value={owner}
          onChange={(e) => setOwner(e.target.value)}
          placeholder="team@example.com"
        />
      </div>

      <div className="space-y-1">
        <Label htmlFor="unit">Business unit</Label>
        <Input
          id="unit"
          value={unit}
          onChange={(e) => setUnit(e.target.value)}
          placeholder="e.g. Payments"
        />
      </div>

      <div className="space-y-1">
        <Label>Criticality</Label>
        <Select value={crit} onValueChange={setCrit}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={CRIT_UNSET}>Unset (heuristic)</SelectItem>
            {[0, 1, 2, 3, 4].map((n) => (
              <SelectItem key={n} value={String(n)}>
                {n} — {ASSET_CRITICALITY[n].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="flex items-center justify-between pt-2">
        <Button onClick={save} disabled={update.isPending}>
          {update.isPending ? "Saving…" : "Save"}
        </Button>

        {!decommissioned ? (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="outline" className="text-rose-700">
                Decommission
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Decommission this asset?</AlertDialogTitle>
                <AlertDialogDescription>
                  Marks the asset as decommissioned (logged as a Phase 10.1 event). Active/stale
                  are system-managed and cannot be set back manually.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={() => update.mutate({ status: "decommissioned" })}>
                  Decommission
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        ) : (
          <Badge variant="secondary">decommissioned</Badge>
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-slate-800">{value}</p>
    </div>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return (
    <p className="rounded-md border bg-white px-3 py-6 text-center text-sm text-muted-foreground">
      {children}
    </p>
  );
}
