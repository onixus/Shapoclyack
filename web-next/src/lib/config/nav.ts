import {
  BookText,
  Building2,
  CircleGauge,
  ClipboardCheck,
  Database,
  FileText,
  Gauge,
  Globe2,
  Home,
  KeyRound,
  Laptop,
  Layers,
  Network,
  Play,
  Radar,
  ScrollText,
  Server,
  Share2,
  ShieldAlert,
  Siren,
  SlidersHorizontal,
  SquareKanban,
  Timer,
  UserCog,
  Users,
  Webhook,
  type LucideIcon,
} from "lucide-react";
import type { MsgKey } from "@/lib/i18n/messages";
import type { Role } from "@/lib/api";

/**
 * Minimum role a menu entry is *shown* for. This is presentation only — the
 * API enforces access on every request — but a viewer should not be handed
 * eleven doors that all open onto "operator role required".
 */
export type NavItem = {
  href: string;
  labelKey: MsgKey;
  icon: LucideIcon;
  minRole?: Exclude<Role, "viewer">;
  /** Short hint shown in the command palette. */
  hintKey?: MsgKey;
};

export type NavGroup = {
  id: string;
  labelKey: MsgKey;
  items: readonly NavItem[];
};

/**
 * Information architecture (docs/ui-ux-redesign-roadmap.md, "Navigation"):
 * security workflows first, then the two scanning surfaces — what faces the
 * internet and what lives inside the perimeter — then the operations that
 * serve both, insights, and administration.
 */
export const NAV_GROUPS: readonly NavGroup[] = [
  {
    id: "overview",
    labelKey: "nav.group.overview",
    items: [{ href: "/", labelKey: "nav.dashboard", icon: Home, hintKey: "nav.hint.dashboard" }],
  },
  {
    id: "risk",
    labelKey: "nav.group.risk",
    items: [
      {
        href: "/vulnerabilities",
        labelKey: "nav.vulnerabilities",
        icon: ShieldAlert,
        hintKey: "nav.hint.vulnerabilities",
      },
      {
        href: "/remediation",
        labelKey: "nav.remediation",
        icon: SquareKanban,
        hintKey: "nav.hint.remediation",
      },
      { href: "/assets", labelKey: "nav.assets", icon: Database, hintKey: "nav.hint.assets" },
      { href: "/threats", labelKey: "nav.threats", icon: Siren, hintKey: "nav.hint.threats" },
      {
        href: "/compliance",
        labelKey: "nav.compliance",
        icon: ClipboardCheck,
        hintKey: "nav.hint.compliance",
      },
    ],
  },
  {
    id: "external",
    labelKey: "nav.group.external",
    items: [
      {
        href: "/scans/external",
        labelKey: "nav.externalScans",
        icon: Globe2,
        minRole: "operator",
        hintKey: "nav.hint.externalScans",
      },
      { href: "/exposure", labelKey: "nav.exposure", icon: Radar, hintKey: "nav.hint.exposure" },
      {
        href: "/attack-surface",
        labelKey: "nav.attackSurface",
        icon: Share2,
        hintKey: "nav.hint.attackSurface",
      },
      {
        href: "/org-profile",
        labelKey: "nav.orgProfile",
        icon: Building2,
        hintKey: "nav.hint.orgProfile",
      },
      { href: "/geo", labelKey: "nav.geo", icon: Network, hintKey: "nav.hint.geo" },
    ],
  },
  {
    id: "internal",
    labelKey: "nav.group.internal",
    items: [
      {
        href: "/scans/internal",
        labelKey: "nav.internalScans",
        icon: Layers,
        minRole: "operator",
        hintKey: "nav.hint.internalScans",
      },
      {
        href: "/endpoints",
        labelKey: "nav.endpoints",
        icon: Laptop,
        hintKey: "nav.hint.endpoints",
      },
      {
        href: "/agents",
        labelKey: "nav.agents",
        icon: Server,
        minRole: "operator",
        hintKey: "nav.hint.agents",
      },
    ],
  },
  {
    id: "operations",
    labelKey: "nav.group.operations",
    items: [
      {
        href: "/scans",
        labelKey: "nav.jobs",
        icon: Play,
        minRole: "operator",
        hintKey: "nav.hint.jobs",
      },
      { href: "/runs", labelKey: "nav.runs", icon: FileText, hintKey: "nav.hint.runs" },
      {
        href: "/schedules",
        labelKey: "nav.schedules",
        icon: Timer,
        minRole: "operator",
        hintKey: "nav.hint.schedules",
      },
      { href: "/reports", labelKey: "nav.reports", icon: BookText, hintKey: "nav.hint.reports" },
      {
        href: "/wordlists",
        labelKey: "nav.wordlists",
        icon: Database,
        minRole: "operator",
        hintKey: "nav.hint.wordlists",
      },
    ],
  },
  {
    id: "insights",
    labelKey: "nav.group.insights",
    items: [
      { href: "/adoption", labelKey: "nav.adoption", icon: Gauge, hintKey: "nav.hint.adoption" },
      { href: "/usage", labelKey: "nav.usage", icon: CircleGauge, hintKey: "nav.hint.usage" },
    ],
  },
  {
    id: "admin",
    labelKey: "nav.group.admin",
    items: [
      {
        href: "/tenants",
        labelKey: "nav.tenants",
        icon: Users,
        minRole: "operator",
        hintKey: "nav.hint.tenants",
      },
      {
        href: "/users",
        labelKey: "nav.users",
        icon: UserCog,
        minRole: "admin",
        hintKey: "nav.hint.users",
      },
      {
        // No minRole, unlike /users next door: "admin" on GET /api/audit means
        // admin *in the tenant*, which the JWT does not carry, so filtering on
        // the global role would hide the page from exactly the tenant admin
        // it is for. The API is the boundary; the page renders its 403.
        href: "/audit",
        labelKey: "nav.audit",
        icon: ScrollText,
        hintKey: "nav.hint.audit",
      },
      {
        href: "/integrations",
        labelKey: "nav.integrations",
        icon: Webhook,
        minRole: "operator",
        hintKey: "nav.hint.integrations",
      },
      {
        href: "/service-tokens",
        labelKey: "nav.serviceTokens",
        icon: KeyRound,
        minRole: "admin",
        hintKey: "nav.hint.serviceTokens",
      },
      {
        href: "/system",
        labelKey: "nav.system",
        icon: SlidersHorizontal,
        hintKey: "nav.hint.system",
      },
    ],
  },
] as const;

/** Flat list, in menu order — for the command palette and tests. */
export const NAV: readonly NavItem[] = NAV_GROUPS.flatMap((group) => group.items);

const ROLE_RANK: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 };

export function canSee(item: Pick<NavItem, "minRole">, role: Role | undefined): boolean {
  if (!item.minRole) return true;
  return ROLE_RANK[role ?? "viewer"] >= ROLE_RANK[item.minRole];
}

/** Groups with the entries this role may see; a group left empty disappears. */
export function visibleNavGroups(role: Role | undefined): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => canSee(item, role)),
  })).filter((group) => group.items.length > 0);
}

/**
 * The single active entry for a path: the longest href that is the path or
 * one of its ancestors, so `/scans/external` lights "External scans" and not
 * also "Scan jobs" at `/scans`.
 */
export function activeNavHref(pathname: string, items: readonly NavItem[] = NAV): string | null {
  let best: string | null = null;
  for (const item of items) {
    const matches =
      item.href === "/"
        ? pathname === "/"
        : pathname === item.href || pathname.startsWith(`${item.href}/`);
    if (matches && (best === null || item.href.length > best.length)) best = item.href;
  }
  // Legacy `/jobs` deep links land on the scan-jobs entry.
  if (best === null && (pathname === "/jobs" || pathname.startsWith("/jobs/"))) return "/scans";
  return best;
}
