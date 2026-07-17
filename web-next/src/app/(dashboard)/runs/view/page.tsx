"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  fetchHosts,
  fetchPorts,
  fetchRun,
  fetchVulns,
  type AliveHost,
  type PortAggregate,
  type Vulnerability,
} from "@/lib/api";
import { SEVERITIES, normalizeSeverity, type Severity } from "@/lib/run-data";

function formatLocation(item: {
  city?: string | null;
  country?: string | null;
  country_iso?: string | null;
}): string {
  const bits = [item.city, item.country].filter(Boolean);
  if (bits.length === 0 && item.country_iso) return item.country_iso;
  return bits.join(", ");
}

function severityClass(sev: Severity) {
  if (sev === "critical") return "bg-rose-700 hover:bg-rose-700";
  if (sev === "high") return "bg-orange-600 hover:bg-orange-600";
  if (sev === "medium") return "bg-amber-500 hover:bg-amber-500 text-slate-900";
  if (sev === "low") return "bg-sky-600 hover:bg-sky-600";
  return "";
}

export default function RunDetailPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading run…</p>}>
      <RunDetailInner />
    </Suspense>
  );
}

function RunDetailInner() {
  const searchParams = useSearchParams();
  const runId = (searchParams.get("runId") || "").trim();
  const [activeSeverity, setActiveSeverity] = useState<Severity | "all">("all");
  const [activeHost, setActiveHost] = useState<string | null>(null);
  const [activePort, setActivePort] = useState<string | null>(null);

  const detailQuery = useQuery({
    queryKey: ["run", runId],
    queryFn: () => fetchRun(runId),
    enabled: Boolean(runId),
  });
  const hostsQuery = useQuery({
    queryKey: ["run", runId, "hosts"],
    queryFn: () => fetchHosts(runId),
    enabled: Boolean(runId),
  });
  const portsQuery = useQuery({
    queryKey: ["run", runId, "ports"],
    queryFn: () => fetchPorts(runId),
    enabled: Boolean(runId),
  });
  const vulnsQuery = useQuery({
    queryKey: ["run", runId, "vulns"],
    queryFn: () => fetchVulns(runId, 5000),
    enabled: Boolean(runId),
  });

  const detail = detailQuery.data;
  const hosts = useMemo(() => hostsQuery.data || [], [hostsQuery.data]);
  const ports = useMemo(() => portsQuery.data || [], [portsQuery.data]);
  const vulns = useMemo(() => vulnsQuery.data || [], [vulnsQuery.data]);
  const summary = detail?.summary || {};
  const diffCounts = (detail?.diff?.counts || null) as Record<string, number> | null;

  const geoByHost = useMemo(() => {
    const map = new Map<string, AliveHost>();
    for (const host of hosts) map.set(host.host, host);
    return map;
  }, [hosts]);

  const enrichedVulns = useMemo(() => {
    return vulns
      .filter((item) => {
        if (activeHost && item.host !== activeHost) return false;
        if (activePort && item.port !== activePort) return false;
        return true;
      })
      .map((item) => {
        if (item.country || item.city || item.country_iso || !item.host) return item;
        const geo = geoByHost.get(item.host);
        if (!geo) return item;
        return {
          ...item,
          country: geo.country,
          city: geo.city,
          country_iso: geo.country_iso,
        };
      });
  }, [vulns, activeHost, activePort, geoByHost]);

  const severityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const item of enrichedVulns) {
      counts[normalizeSeverity(item.severity)] += 1;
    }
    return counts;
  }, [enrichedVulns]);

  const grouped = useMemo(() => {
    const groups: Record<Severity, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: [],
    };
    for (const item of enrichedVulns) {
      const sev = normalizeSeverity(item.severity);
      if (activeSeverity !== "all" && sev !== activeSeverity) continue;
      groups[sev].push(item);
    }
    return groups;
  }, [enrichedVulns, activeSeverity]);

  const loading =
    detailQuery.isLoading || hostsQuery.isLoading || portsQuery.isLoading || vulnsQuery.isLoading;
  const error =
    detailQuery.error || hostsQuery.error || portsQuery.error || vulnsQuery.error;

  if (!runId) {
    return (
      <div className="space-y-4">
        <Button asChild variant="ghost" size="sm" className="gap-2 px-0">
          <Link href="/runs">
            <ArrowLeft className="h-4 w-4" />
            Runs
          </Link>
        </Button>
        <p className="text-sm text-rose-600">Missing runId query parameter.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Button asChild variant="ghost" size="sm" className="gap-2 px-0">
          <Link href="/runs">
            <ArrowLeft className="h-4 w-4" />
            Runs
          </Link>
        </Button>
        <p className="text-sm text-rose-600">
          {error instanceof Error ? error.message : "Failed to load run"}
        </p>
      </div>
    );
  }

  if (loading || !detail) {
    return <p className="text-sm text-muted-foreground">Loading run…</p>;
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Button asChild variant="ghost" size="sm" className="gap-2 px-0">
          <Link href="/runs">
            <ArrowLeft className="h-4 w-4" />
            Runs
          </Link>
        </Button>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          <code className="text-xl">{detail.run_id}</code>
        </h1>
        <p className="text-sm text-muted-foreground">
          Explore hosts, open ports, and severity-grouped findings for this run.
          {(activeHost || activePort) && (
            <>
              {" "}
              Filter active
              {activeHost ? ` · host ${activeHost}` : ""}
              {activePort ? ` · port ${activePort}` : ""}.{" "}
              <button
                type="button"
                className="underline"
                onClick={() => {
                  setActiveHost(null);
                  setActivePort(null);
                }}
              >
                Clear
              </button>
            </>
          )}
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Metric
          label="Alive hosts"
          value={String(summary.alive_hosts ?? hosts.length ?? "—")}
          hint={hosts.filter((h) => h.country || h.city).length ? "GeoIP available" : undefined}
        />
        <Metric
          label="Open ports"
          value={String(
            summary.open_host_port_pairs ??
              ports.reduce((n, p) => n + p.host_count, 0) ??
              "—",
          )}
          hint={`${ports.length} distinct`}
        />
        <Metric
          label="Vulnerabilities"
          value={String(summary.potential_vulnerabilities ?? enrichedVulns.length ?? "—")}
        />
        <Metric label="OS detected" value={String(summary.os_detected_hosts ?? "—")} />
      </div>

      {diffCounts ? (
        <div className="rounded-lg border bg-white p-4 text-sm">
          <p className="font-medium text-slate-900">Diff vs previous</p>
          <p className="mt-1 text-muted-foreground">
            hosts +{diffCounts.hosts_added || 0}/-{diffCounts.hosts_removed || 0}
            {" · "}
            ports +{diffCounts.ports_added || 0}/-{diffCounts.ports_removed || 0}
            {" · "}
            vulns +{diffCounts.vulns_added || 0}/-{diffCounts.vulns_removed || 0}
          </p>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-2">
        <Button
          type="button"
          size="sm"
          variant={activeSeverity === "all" ? "default" : "outline"}
          onClick={() => setActiveSeverity("all")}
        >
          All ({enrichedVulns.length})
        </Button>
        {SEVERITIES.map((sev) => (
          <Button
            key={sev}
            type="button"
            size="sm"
            variant={activeSeverity === sev ? "default" : "outline"}
            onClick={() => setActiveSeverity(sev)}
            disabled={severityCounts[sev] === 0}
          >
            {sev} ({severityCounts[sev]})
          </Button>
        ))}
      </div>

      <Tabs defaultValue="vulns">
        <TabsList>
          <TabsTrigger value="vulns">Findings</TabsTrigger>
          <TabsTrigger value="hosts">Hosts ({hosts.length})</TabsTrigger>
          <TabsTrigger value="ports">Ports ({ports.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="vulns" className="space-y-4">
          {SEVERITIES.filter((sev) => grouped[sev].length > 0).map((sev) => (
            <section key={sev} className="rounded-lg border bg-white">
              <div className="flex items-center justify-between border-b px-4 py-3">
                <div className="flex items-center gap-2">
                  <Badge className={severityClass(sev)} variant={sev === "unknown" ? "secondary" : "default"}>
                    {sev}
                  </Badge>
                  <span className="text-sm text-muted-foreground">{grouped[sev].length} findings</span>
                </div>
              </div>
              <ul className="divide-y">
                {grouped[sev].slice(0, 200).map((item, index) => (
                  <li key={`${item.host}-${item.port}-${item.cve}-${index}`} className="px-4 py-3 text-sm">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <p className="font-medium text-slate-900">
                          {item.cve || item.script_id || "finding"}
                          {item.port ? (
                            <span className="ml-2 text-muted-foreground">:{item.port}</span>
                          ) : null}
                        </p>
                        <p className="text-muted-foreground">
                          {item.host || "unknown host"}
                          {formatLocation(item) ? ` · ${formatLocation(item)}` : ""}
                        </p>
                      </div>
                      <span className="text-xs tabular-nums text-muted-foreground">
                        {item.cvss4 != null
                          ? `CVSS4 ${item.cvss4}`
                          : item.cvss != null
                            ? `CVSS ${item.cvss}`
                            : sev.toUpperCase()}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          {enrichedVulns.length === 0 ? (
            <p className="text-sm text-muted-foreground">No findings for the current filters.</p>
          ) : null}
        </TabsContent>

        <TabsContent value="hosts" className="space-y-2">
          <HostList
            hosts={hosts}
            activeHost={activeHost}
            onSelect={(host) => {
              setActiveHost((prev) => (prev === host ? null : host));
              setActivePort(null);
            }}
          />
          {hosts.some((h) => h.country || h.city) ? (
            <p className="text-xs text-muted-foreground">
              <a
                href="https://db-ip.com"
                target="_blank"
                rel="noreferrer"
                className="underline-offset-2 hover:underline"
              >
                IP Geolocation by DB-IP
              </a>
            </p>
          ) : null}
        </TabsContent>

        <TabsContent value="ports">
          <PortList
            ports={ports}
            activePort={activePort}
            onSelect={(port) => {
              setActivePort((prev) => (prev === port ? null : port));
              setActiveHost(null);
            }}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Metric({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-lg border bg-white p-4">
      <p className="text-2xl font-semibold tabular-nums text-slate-900">{value}</p>
      <p className="text-sm text-muted-foreground">{label}</p>
      {hint ? <p className="mt-1 text-xs text-muted-foreground">{hint}</p> : null}
    </div>
  );
}

function HostList({
  hosts,
  activeHost,
  onSelect,
}: {
  hosts: AliveHost[];
  activeHost: string | null;
  onSelect: (host: string) => void;
}) {
  if (hosts.length === 0) {
    return <p className="text-sm text-muted-foreground">No alive hosts recorded for this run.</p>;
  }
  return (
    <div className="max-h-[28rem] overflow-auto rounded-lg border bg-white">
      <ul className="divide-y">
        {hosts.map((host) => {
          const location = formatLocation(host);
          return (
            <li key={host.host}>
              <button
                type="button"
                className={`flex w-full items-start justify-between gap-3 px-4 py-3 text-left text-sm hover:bg-slate-50 ${
                  activeHost === host.host ? "bg-slate-100" : ""
                }`}
                onClick={() => onSelect(host.host)}
              >
                <span>
                  <strong className="text-slate-900">{host.host}</strong>
                  <span className="mt-0.5 block text-muted-foreground">
                    {host.hostname || host.names[0] || "no hostname"}
                    {host.vulnerability_count
                      ? ` · ${host.vulnerability_count} vulns`
                      : " · no vulns"}
                  </span>
                </span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {location || "No GeoIP"}
                </span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function PortList({
  ports,
  activePort,
  onSelect,
}: {
  ports: PortAggregate[];
  activePort: string | null;
  onSelect: (port: string) => void;
}) {
  if (ports.length === 0) {
    return <p className="text-sm text-muted-foreground">No open ports recorded for this run.</p>;
  }
  return (
    <div className="max-h-[28rem] overflow-auto rounded-lg border bg-white">
      <ul className="divide-y">
        {ports.map((row) => (
          <li key={`${row.port}/${row.protocol || "tcp"}`}>
            <button
              type="button"
              className={`flex w-full items-start justify-between gap-3 px-4 py-3 text-left text-sm hover:bg-slate-50 ${
                activePort === row.port ? "bg-slate-100" : ""
              }`}
              onClick={() => onSelect(row.port)}
            >
              <span>
                <strong className="text-slate-900">
                  :{row.port}
                  {row.protocol ? `/${row.protocol}` : ""}
                </strong>
                <span className="mt-0.5 block text-muted-foreground">
                  {row.host_count} hosts
                  {row.vulnerability_count ? ` · ${row.vulnerability_count} vulns` : ""}
                </span>
              </span>
              <span className="shrink-0 tabular-nums text-xs text-muted-foreground">
                {row.host_count}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
