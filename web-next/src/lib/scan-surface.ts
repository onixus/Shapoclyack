import type { JobInfo, RunSummary, ScanSchedule } from "@/lib/api";
import type { StatusStyle } from "@/lib/config/statuses";

/**
 * Which side of the perimeter a scan looks at.
 *
 * `external` — internet-facing targets: domains / FQDNs and public address
 * space. `internal` — private address space (RFC 1918, loopback, link-local,
 * CGNAT, IPv6 ULA). `mixed` — a job that carried both. The server derives the
 * value from the targets when the operator does not declare one and persists
 * it on the job (`scan_options.surface`) and on the run's tenant marker; a
 * job started before the field existed reads as *unknown* — not as internal.
 */
export type ScanSurface = "external" | "internal" | "mixed";
export type SurfaceFilter = ScanSurface | "unknown";

export const SCAN_SURFACES: readonly ScanSurface[] = ["external", "internal", "mixed"] as const;

const INFO_SKY =
  "bg-sky-500/10 text-sky-800 dark:bg-sky-500/20 dark:text-sky-300 border border-sky-500/30 font-semibold";
const INFO_VIOLET =
  "bg-violet-500/10 text-violet-800 dark:bg-violet-500/20 dark:text-violet-300 border border-violet-500/30 font-semibold";
const INFO_AMBER =
  "bg-amber-500/10 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300 border border-amber-500/30 font-semibold";
const MUTED = "bg-muted text-muted-foreground border border-border font-medium";

export const SCAN_SURFACE_STATUS: Record<SurfaceFilter, StatusStyle> = {
  external: { label: "external", className: INFO_SKY },
  internal: { label: "internal", className: INFO_VIOLET },
  mixed: { label: "mixed", className: INFO_AMBER },
  unknown: { label: "unknown surface", variant: "secondary", className: MUTED },
};

function asSurface(value: unknown): ScanSurface | null {
  return value === "external" || value === "internal" || value === "mixed" ? value : null;
}

/** The job's surface: the top-level mirror first, then the persisted option
 * (an API a release older than the mirror still carries the option). */
export function jobSurface(job: Pick<JobInfo, "surface" | "scan_options">): ScanSurface | null {
  return asSurface(job.surface) ?? asSurface(job.scan_options?.surface);
}

export function runSurface(run: Pick<RunSummary, "surface">): ScanSurface | null {
  return asSurface(run.surface);
}

export function scheduleSurface(schedule: Pick<ScanSchedule, "scan_options">): ScanSurface | null {
  return asSurface(schedule.scan_options?.surface);
}

/** Route of the operations page that owns a surface. */
export function surfaceHref(surface: ScanSurface | "all" | null | undefined): string {
  if (surface === "external") return "/scans/external";
  if (surface === "internal") return "/scans/internal";
  return "/scans";
}

const PRIVATE_V4: Array<[number, number]> = [
  // [network, prefix] — the same list as api/services/scan_surface.py:
  // RFC 1918, loopback, link-local, CGNAT (RFC 6598).
  [ipv4ToInt("10.0.0.0"), 8],
  [ipv4ToInt("172.16.0.0"), 12],
  [ipv4ToInt("192.168.0.0"), 16],
  [ipv4ToInt("127.0.0.0"), 8],
  [ipv4ToInt("169.254.0.0"), 16],
  [ipv4ToInt("100.64.0.0"), 10],
];

function ipv4ToInt(ip: string): number {
  const parts = ip.split(".");
  if (parts.length !== 4) return NaN;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return NaN;
    const n = Number(part);
    if (n > 255) return NaN;
    out = out * 256 + n;
  }
  return out;
}

function inCidrV4(ip: number, network: number, prefix: number): boolean {
  if (prefix === 0) return true;
  const shift = 32 - prefix;
  return Math.floor(ip / 2 ** shift) === Math.floor(network / 2 ** shift);
}

/** Containment, not overlap — like the server: `192.168.0.0/8` is *not*
 * inside 192.168/16, so it reads as external there and must here too. */
function isPrivateV4(ip: number, prefix: number): boolean {
  return PRIVATE_V4.some(
    ([network, netPrefix]) => prefix >= netPrefix && inCidrV4(ip, network, netPrefix),
  );
}

function isPrivateV6(address: string, prefix: number): boolean {
  const lower = address.toLowerCase();
  if ((lower === "::1" || lower === "::") && prefix >= 128) return true;
  // ULA fc00::/7 and link-local fe80::/10.
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return prefix >= 7;
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return prefix >= 10;
  return false;
}

/** Roughly what the server's `is_fqdn` accepts: dotted labels, not an IP. */
export function looksLikeFqdn(value: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(":")) return false;
  return /^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}\.?$/i.test(
    value,
  );
}

/** Mirrors the server's `split_target_lines`: a `#` line is a comment, and
 * within a line commas, semicolons and blanks separate targets. */
export function splitTargetLines(text: string | null | undefined): string[] {
  const out: string[] = [];
  for (const raw of (text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    for (const token of line.split(/[,;\s]+/)) if (token) out.push(token);
  }
  return out;
}

/** One range/IP line → its address-space class. `null` for garbage the
 * server will reject anyway (the launcher only wants a hint, not a verdict). */
export function classifyRange(entry: string): "internal" | "external" | null {
  const [address, prefixText] = entry.split("/");
  if (!address) return null;
  const v6 = address.includes(":");
  const full = v6 ? 128 : 32;
  const prefix = prefixText === undefined ? full : Number(prefixText);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > full) return null;
  if (v6) return isPrivateV6(address, prefix) ? "internal" : "external";
  const ip = ipv4ToInt(address.replace(/-.*$/, ""));
  if (Number.isNaN(ip)) return null;
  return isPrivateV4(ip, prefix) ? "internal" : "external";
}

/**
 * Client-side mirror of the server's derivation, used for the live hint in
 * the launcher ("these targets look internal"). The server's answer wins once
 * the job exists; this only tells the operator *before* they press Start.
 */
export function classifyTargets(
  rangesText: string | null | undefined,
  domainsText: string | null | undefined,
): ScanSurface | null {
  let external = splitTargetLines(domainsText).some(looksLikeFqdn);
  let internal = false;
  for (const entry of splitTargetLines(rangesText)) {
    const kind = classifyRange(entry);
    if (kind === "internal") internal = true;
    if (kind === "external") external = true;
  }
  if (external && internal) return "mixed";
  if (external) return "external";
  if (internal) return "internal";
  return null;
}
