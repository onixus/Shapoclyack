"use client";

import { useMemo, useState } from "react";
import { useRunDetail, useRunHosts, useRunPorts, useRunVulns } from "@/hooks/use-runs";
import type { AliveHost, Vulnerability } from "@/lib/api";
import { VULN_FETCH_LIMIT } from "@/lib/config/constants";
import { normalizeSeverity, type Severity } from "@/lib/run-data";

export type RunReportFilters = {
  severity: Severity | "all";
  host: string | null;
  port: string | null;
};

export type RunReportTruncation = {
  shown: number;
  /** Total findings per the run summary; null while a host/port filter is active. */
  total: number | null;
  isTruncated: boolean;
};

/**
 * All data + derivation for the run report page. Host/port filters re-query
 * the API (server-side filtering); severity filtering and counting stay
 * client-side since the API has no severity parameter.
 */
export function useRunReport(runId: string) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [host, setHost] = useState<string | null>(null);
  const [port, setPort] = useState<string | null>(null);

  const detailQuery = useRunDetail(runId);
  const hostsQuery = useRunHosts(runId);
  const portsQuery = useRunPorts(runId);
  const vulnsQuery = useRunVulns(runId, { host, port });

  const detail = detailQuery.data;
  const hosts = useMemo(() => hostsQuery.data || [], [hostsQuery.data]);
  const ports = useMemo(() => portsQuery.data || [], [portsQuery.data]);
  const vulns = useMemo(() => vulnsQuery.data || [], [vulnsQuery.data]);
  const summary = detail?.summary || {};
  const diffCounts = (detail?.diff?.counts || null) as Record<string, number> | null;

  const geoByHost = useMemo(() => {
    const map = new Map<string, AliveHost>();
    for (const item of hosts) map.set(item.host, item);
    return map;
  }, [hosts]);

  const enrichedVulns = useMemo(() => {
    return vulns.map((item) => {
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
  }, [vulns, geoByHost]);

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
      if (severity !== "all" && sev !== severity) continue;
      groups[sev].push(item);
    }
    return groups;
  }, [enrichedVulns, severity]);

  const truncation = useMemo<RunReportTruncation>(() => {
    const shown = vulns.length;
    const summaryTotal = summary.potential_vulnerabilities;
    const total = !host && !port && typeof summaryTotal === "number" ? summaryTotal : null;
    return {
      shown,
      total,
      isTruncated: shown >= VULN_FETCH_LIMIT || (total != null && total > shown),
    };
  }, [vulns.length, summary.potential_vulnerabilities, host, port]);

  return {
    detail,
    hosts,
    ports,
    vulns: enrichedVulns,
    summary,
    diffCounts,
    severityCounts,
    grouped,
    truncation,
    filters: { severity, host, port } satisfies RunReportFilters,
    setSeverity,
    toggleHost: (value: string) => {
      setHost((prev) => (prev === value ? null : value));
      setPort(null);
    },
    togglePort: (value: string) => {
      setPort((prev) => (prev === value ? null : value));
      setHost(null);
    },
    clearFilters: () => {
      setHost(null);
      setPort(null);
    },
    isLoading:
      detailQuery.isLoading || hostsQuery.isLoading || portsQuery.isLoading || vulnsQuery.isLoading,
    isFilterFetching: vulnsQuery.isFetching && !vulnsQuery.isLoading,
    error: detailQuery.error || hostsQuery.error || portsQuery.error || vulnsQuery.error,
  };
}
