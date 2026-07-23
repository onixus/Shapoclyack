"use client";

import { useMemo } from "react";
import type { AliveHost, PortAggregate } from "@/lib/api";

// Lightweight dependency-free attack-surface view: a three-column layered
// graph (hostnames → IPs → ports) drawn as plain SVG. IP nodes are colored by
// GeoIP country (the only clustering dimension currently available via the API
// — ASN/org needs the opt-in asn_discovery stage). Node counts are capped so a
// 50k-asset fleet stays legible; the caller states what was shown vs. total.

const COL_X = { host: 16, ip: 232, port: 448, service: 664 } as const;
const NODE_W = 140;
const NODE_H = 22;
const V_GAP = 8;
const ROW = NODE_H + V_GAP;
const TOP_PAD = 16;
const SVG_W = 820;

const COUNTRY_PALETTE = [
  "#2563eb", "#0891b2", "#7c3aed", "#db2777", "#ea580c",
  "#16a34a", "#ca8a04", "#4f46e5", "#0d9488", "#9333ea",
];
const NO_GEO = "#94a3b8";

export type AttackSurfaceCaps = {
  maxIps: number;
  maxHostnames: number;
  maxPorts: number;
  maxServices: number;
};

function truncate(text: string, max = 22): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function AttackSurfaceGraph({
  hosts,
  ports,
  caps = { maxIps: 40, maxHostnames: 40, maxPorts: 30, maxServices: 24 },
}: {
  hosts: AliveHost[];
  ports: PortAggregate[];
  caps?: AttackSurfaceCaps;
}) {
  const model = useMemo(() => {
    // Cluster by ASN/org when the run has ASN enrichment, else by GeoIP country.
    const clusterMode: "asn" | "geo" = hosts.some((h) => h.asn_org) ? "asn" : "geo";
    const clusterValue = (h: AliveHost): string =>
      clusterMode === "asn" ? h.asn_org || h.asn || "" : h.country || "";

    // Prioritize the most interesting IPs (most findings first) when capping.
    const rankedHosts = [...hosts].sort(
      (a, b) => (b.vulnerability_count || 0) - (a.vulnerability_count || 0),
    );
    const ipHosts = rankedHosts.slice(0, caps.maxIps);
    const ipSet = new Set(ipHosts.map((h) => h.host));

    // Cluster value → color, and per-IP color for rendering.
    const clusters = Array.from(
      new Set(ipHosts.map(clusterValue).filter((c): c is string => Boolean(c))),
    );
    const clusterColor = new Map<string, string>();
    clusters.forEach((c, i) => clusterColor.set(c, COUNTRY_PALETTE[i % COUNTRY_PALETTE.length]));
    const ipColor = new Map(
      ipHosts.map((h) => {
        const cv = clusterValue(h);
        return [h.host, cv ? clusterColor.get(cv) || NO_GEO : NO_GEO] as const;
      }),
    );

    // Hostnames attached to the selected IPs.
    const hostnameToIps = new Map<string, string[]>();
    for (const h of ipHosts) {
      const names = h.names?.length ? h.names : h.hostname ? [h.hostname] : [];
      for (const name of names) {
        if (!name) continue;
        const list = hostnameToIps.get(name) || [];
        list.push(h.host);
        hostnameToIps.set(name, list);
      }
    }
    const hostnames = Array.from(hostnameToIps.keys()).slice(0, caps.maxHostnames);
    const hostnameSet = new Set(hostnames);

    // Ports touching the selected IPs, ranked by findings then fan-out.
    const rankedPorts = [...ports]
      .map((p) => ({ ...p, ipsHere: p.hosts.filter((ip) => ipSet.has(ip)) }))
      .filter((p) => p.ipsHere.length > 0)
      .sort(
        (a, b) =>
          (b.vulnerability_count || 0) - (a.vulnerability_count || 0) ||
          b.ipsHere.length - a.ipsHere.length,
      )
      .slice(0, caps.maxPorts);

    // Services touching the selected ports (port → service edges), capped.
    const portKey = (p: PortAggregate) => `${p.port}/${p.protocol || "tcp"}`;
    const serviceToPorts = new Map<string, string[]>();
    for (const p of rankedPorts) {
      for (const svc of p.services || []) {
        if (!svc) continue;
        const list = serviceToPorts.get(svc) || [];
        list.push(portKey(p));
        serviceToPorts.set(svc, list);
      }
    }
    const services = Array.from(serviceToPorts.keys())
      .sort((a, b) => (serviceToPorts.get(b)!.length - serviceToPorts.get(a)!.length))
      .slice(0, caps.maxServices);

    // Y positions per column.
    const yOf = (idx: number) => TOP_PAD + idx * ROW;
    const hostY = new Map(hostnames.map((n, i) => [n, yOf(i)]));
    const ipY = new Map(ipHosts.map((h, i) => [h.host, yOf(i)]));
    const portY = new Map(rankedPorts.map((p, i) => [portKey(p), yOf(i)]));
    const serviceY = new Map(services.map((s, i) => [s, yOf(i)]));

    const edgesHostIp: { x1: number; y1: number; x2: number; y2: number }[] = [];
    for (const name of hostnames) {
      const y1 = hostY.get(name)!;
      for (const ip of hostnameToIps.get(name) || []) {
        const y2 = ipY.get(ip);
        if (y2 == null) continue;
        edgesHostIp.push({ x1: COL_X.host + NODE_W, y1: y1 + NODE_H / 2, x2: COL_X.ip, y2: y2 + NODE_H / 2 });
      }
    }
    const edgesIpPort: { x1: number; y1: number; x2: number; y2: number }[] = [];
    for (const p of rankedPorts) {
      const y2 = portY.get(portKey(p))!;
      for (const ip of p.ipsHere) {
        const y1 = ipY.get(ip);
        if (y1 == null) continue;
        edgesIpPort.push({ x1: COL_X.ip + NODE_W, y1: y1 + NODE_H / 2, x2: COL_X.port, y2: y2 + NODE_H / 2 });
      }
    }
    const edgesPortService: { x1: number; y1: number; x2: number; y2: number }[] = [];
    for (const svc of services) {
      const y2 = serviceY.get(svc)!;
      for (const pk of serviceToPorts.get(svc) || []) {
        const y1 = portY.get(pk);
        if (y1 == null) continue;
        edgesPortService.push({ x1: COL_X.port + NODE_W, y1: y1 + NODE_H / 2, x2: COL_X.service, y2: y2 + NODE_H / 2 });
      }
    }

    const rows = Math.max(hostnames.length, ipHosts.length, rankedPorts.length, services.length, 1);
    const height = TOP_PAD * 2 + rows * ROW;

    return {
      ipHosts,
      hostnames,
      hostY,
      ipY,
      ports: rankedPorts.map((p) => ({ key: portKey(p), label: portKey(p), y: portY.get(portKey(p))!, vulns: p.vulnerability_count })),
      services: services.map((s) => ({ name: s, y: serviceY.get(s)! })),
      clusterMode,
      clusterColor,
      ipColor,
      edgesHostIp,
      edgesIpPort,
      edgesPortService,
      height,
      hostnameSet,
      totals: {
        hosts: hosts.length,
        hostnames: hostnameToIps.size,
        ports: ports.length,
        services: serviceToPorts.size,
      },
    };
  }, [hosts, ports, caps]);

  if (hosts.length === 0) {
    return (
      <p className="rounded-md border bg-white px-3 py-6 text-center text-sm text-muted-foreground">
        No alive hosts in this run — nothing to graph.
      </p>
    );
  }

  const legend = Array.from(model.clusterColor.entries());

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span className="font-medium text-slate-700">
          {model.clusterMode === "asn" ? "Networks (ASN):" : "Countries:"}
        </span>
        {legend.length === 0 ? (
          <span>{model.clusterMode === "asn" ? "no ASN data" : "no GeoIP data"}</span>
        ) : (
          legend.map(([cluster, color]) => (
            <span key={cluster} className="flex items-center gap-1">
              <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: color }} />
              {truncate(cluster, 28)}
            </span>
          ))
        )}
        <span className="flex items-center gap-1">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ backgroundColor: NO_GEO }} />
          unknown
        </span>
      </div>

      <div className="max-h-[70vh] overflow-auto rounded-lg border bg-white">
        <svg
          viewBox={`0 0 ${SVG_W} ${model.height}`}
          width="100%"
          preserveAspectRatio="xMidYMin meet"
          className="min-w-[820px]"
          role="img"
          aria-label="Attack surface graph: hostnames to IPs to ports to services"
        >
          {/* Column headers */}
          <text x={COL_X.host} y={10} className="fill-slate-400" fontSize={10} fontWeight={600}>
            HOSTNAMES
          </text>
          <text x={COL_X.ip} y={10} className="fill-slate-400" fontSize={10} fontWeight={600}>
            IPs
          </text>
          <text x={COL_X.port} y={10} className="fill-slate-400" fontSize={10} fontWeight={600}>
            PORTS
          </text>
          <text x={COL_X.service} y={10} className="fill-slate-400" fontSize={10} fontWeight={600}>
            SERVICES
          </text>

          {/* Edges (drawn first, under nodes) */}
          <g stroke="#cbd5e1" strokeWidth={1} fill="none">
            {model.edgesHostIp.map((e, i) => (
              <path key={`he-${i}`} d={`M${e.x1},${e.y1} C${e.x1 + 40},${e.y1} ${e.x2 - 40},${e.y2} ${e.x2},${e.y2}`} />
            ))}
          </g>
          <g stroke="#fca5a5" strokeWidth={1} fill="none">
            {model.edgesIpPort.map((e, i) => (
              <path key={`pe-${i}`} d={`M${e.x1},${e.y1} C${e.x1 + 40},${e.y1} ${e.x2 - 40},${e.y2} ${e.x2},${e.y2}`} />
            ))}
          </g>
          <g stroke="#a5b4fc" strokeWidth={1} fill="none">
            {model.edgesPortService.map((e, i) => (
              <path key={`se-${i}`} d={`M${e.x1},${e.y1} C${e.x1 + 40},${e.y1} ${e.x2 - 40},${e.y2} ${e.x2},${e.y2}`} />
            ))}
          </g>

          {/* Hostname nodes */}
          {model.hostnames.map((name) => (
            <g key={`h-${name}`}>
              <rect
                x={COL_X.host}
                y={model.hostY.get(name)}
                width={NODE_W}
                height={NODE_H}
                rx={4}
                className="fill-slate-100 stroke-slate-300"
              />
              <text
                x={COL_X.host + 8}
                y={(model.hostY.get(name) || 0) + 15}
                fontSize={11}
                className="fill-slate-700"
              >
                {truncate(name)}
              </text>
            </g>
          ))}

          {/* IP nodes (colored by ASN/org or country cluster) */}
          {model.ipHosts.map((h) => {
            const color = model.ipColor.get(h.host) || NO_GEO;
            const y = model.ipY.get(h.host)!;
            return (
              <g key={`ip-${h.host}`}>
                <rect x={COL_X.ip} y={y} width={NODE_W} height={NODE_H} rx={4} fill={color} opacity={0.9} />
                <text x={COL_X.ip + 8} y={y + 15} fontSize={11} fill="#ffffff" fontFamily="monospace">
                  {truncate(h.host, 18)}
                  {h.vulnerability_count ? ` ⚠${h.vulnerability_count}` : ""}
                </text>
              </g>
            );
          })}

          {/* Port nodes */}
          {model.ports.map((p) => (
            <g key={`p-${p.key}`}>
              <rect
                x={COL_X.port}
                y={p.y}
                width={NODE_W}
                height={NODE_H}
                rx={4}
                className={p.vulns ? "fill-rose-100 stroke-rose-300" : "fill-slate-100 stroke-slate-300"}
              />
              <text x={COL_X.port + 8} y={p.y + 15} fontSize={11} className="fill-slate-700" fontFamily="monospace">
                {p.label}
                {p.vulns ? ` ⚠${p.vulns}` : ""}
              </text>
            </g>
          ))}

          {/* Service nodes */}
          {model.services.map((s) => (
            <g key={`svc-${s.name}`}>
              <rect
                x={COL_X.service}
                y={s.y}
                width={NODE_W}
                height={NODE_H}
                rx={4}
                className="fill-indigo-50 stroke-indigo-200"
              />
              <text x={COL_X.service + 8} y={s.y + 15} fontSize={11} className="fill-slate-700">
                {truncate(s.name, 18)}
              </text>
            </g>
          ))}
        </svg>
      </div>

      <p className="text-xs text-muted-foreground">
        Showing {model.hostnames.length}/{model.totals.hostnames} hostnames · {model.ipHosts.length}/
        {model.totals.hosts} IPs · {model.ports.length}/{model.totals.ports} ports ·{" "}
        {model.services.length}/{model.totals.services} services (capped for legibility, IPs ranked
        by finding count).
      </p>
    </div>
  );
}
