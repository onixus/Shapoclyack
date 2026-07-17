export type Tenant = {
  id: string;
  name: string;
  status: "active" | "paused" | "provisioning";
  agentCount: number;
  assetCount: number;
  createdAt: string;
};

export type AssetRow = {
  id: string;
  host: string;
  tenant: string;
  openPorts: number;
  criticality: "critical" | "high" | "medium" | "low" | "info";
  lastScanned: string;
  diff?: { kind: "port" | "cve"; label: string };
};

export const MOCK_TENANTS: Tenant[] = [
  {
    id: "ten_acme",
    name: "Acme Security Ops",
    status: "active",
    agentCount: 12,
    assetCount: 18420,
    createdAt: "2026-03-12T10:00:00Z",
  },
  {
    id: "ten_north",
    name: "Northwind MSSP",
    status: "active",
    agentCount: 28,
    assetCount: 42110,
    createdAt: "2025-11-02T08:30:00Z",
  },
  {
    id: "ten_globex",
    name: "Globex External",
    status: "paused",
    agentCount: 3,
    assetCount: 920,
    createdAt: "2026-06-01T14:15:00Z",
  },
  {
    id: "ten_initech",
    name: "Initech Labs",
    status: "provisioning",
    agentCount: 0,
    assetCount: 0,
    createdAt: "2026-07-16T09:00:00Z",
  },
];

export const VULN_TREND = Array.from({ length: 30 }, (_, index) => {
  const day = index + 1;
  return {
    date: `Jul ${day}`,
    Critical: Math.max(4, Math.round(18 + Math.sin(day / 3) * 6 + (day % 5))),
    High: Math.max(10, Math.round(42 + Math.cos(day / 4) * 10 + (day % 7))),
  };
});

export const TOP_PORTS = [
  { name: "443/tcp", value: 12840 },
  { name: "80/tcp", value: 11220 },
  { name: "22/tcp", value: 8340 },
  { name: "3389/tcp", value: 2105 },
  { name: "445/tcp", value: 1760 },
];

const HOSTS = [
  "10.0.",
  "10.1.",
  "172.16.",
  "192.168.",
  "edge-",
  "api.",
  "vpn.",
  "db-",
];

const TENANT_NAMES = MOCK_TENANTS.map((t) => t.name);
const CRITICALITY: AssetRow["criticality"][] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Deterministic mock inventory sized for 50k+ table demos (virtualization later). */
export function buildMockAssets(count = 250): AssetRow[] {
  return Array.from({ length: count }, (_, i) => {
    const criticality = CRITICALITY[i % CRITICALITY.length];
    const hostBase = HOSTS[i % HOSTS.length];
    const host =
      hostBase.endsWith(".")
        ? `${hostBase}${Math.floor(i / 4) % 255}.${(i % 250) + 1}`
        : `${hostBase}${i % 97}.example.net`;
    const diff =
      i % 11 === 0
        ? { kind: "cve" as const, label: "CVE detected" }
        : i % 7 === 0
          ? { kind: "port" as const, label: "+1 new port" }
          : undefined;
    return {
      id: `asset_${i}`,
      host,
      tenant: TENANT_NAMES[i % TENANT_NAMES.length],
      openPorts: (i % 17) + 1,
      criticality,
      lastScanned: new Date(Date.UTC(2026, 6, 1 + (i % 16), 8 + (i % 10))).toISOString(),
      diff,
    };
  });
}

export const MOCK_ASSETS = buildMockAssets(250);
export const TOTAL_ASSETS_SCANNED = 52_480;
