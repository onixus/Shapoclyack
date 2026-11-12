import {
  Archive,
  BookText,
  Bot,
  CircleGauge,
  ClipboardCheck,
  Database,
  Eye,
  FileText,
  Gauge,
  Home,
  KeyRound,
  Laptop,
  Library,
  Play,
  ScrollText,
  Server,
  ShieldAlert,
  SlidersHorizontal,
  Timer,
  UserCheck,
  UserCog,
  Users,
  Webhook,
  type LucideIcon,
} from "lucide-react";
import type { MsgKey } from "@/lib/i18n/messages";
import { can, type Principal, type Requirement } from "@/lib/authz";

/**
 * What a menu entry is *shown* for. This is presentation only — the API
 * enforces access on every request — but a viewer should not be handed eleven
 * doors that all open onto "operator role required".
 *
 * The three ways to say it are `Requirement` from `@/lib/authz`, the same
 * question every page gate asks, and each mirrors the dependency the route
 * behind it is written with:
 *
 * - `permission` — `require_permission`, a named authority in the active
 *   tenant;
 * - `minRole` — `require_tenant(Role.x)`, the rank held **in that tenant**.
 *   This used to compare against the account's global role, which is what hid
 *   Scan jobs, both scanning surfaces, Agents and Schedules from every account
 *   whose operator role came from a membership (#318);
 * - `globalMinRole` — `require_role(Role.x)` on the `TokenUser`, for the two
 *   entries whose routes are not tenant-scoped at all (the cross-tenant tenant
 *   list, and platform user administration). Asking the tenant role for those
 *   would show a door the API refuses.
 *
 * `anyOf` lists two of these for a page whose routes take either — the
 * sensors page, for an operator or for whoever mints provisioning keys (#504).
 */
export type NavItem = Requirement & {
  href: string;
  labelKey: MsgKey;
  icon: LucideIcon;
  /** Short hint shown in the command palette. */
  hintKey?: MsgKey;
};

export type NavGroup = {
  id: string;
  labelKey: MsgKey;
  items: readonly NavItem[];
};

/**
 * Information architecture: one menu entry per distinct question. A second
 * view of the same question is a tab on that page, not another door.
 * Quick launch (external / internal) still sets the perimeter on `/scans`.
 * Own MFA lives in the account menu (`/security`), not here.
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
        href: "/compliance",
        labelKey: "nav.compliance",
        icon: ClipboardCheck,
        hintKey: "nav.hint.compliance",
      },
      {
        // Viewer-visible, same gate as Runs: no minRole. Lookalike domains are
        // not a scan surface — candidates are never launched as jobs.
        href: "/brand-watch",
        labelKey: "nav.brandWatch",
        icon: Eye,
        hintKey: "nav.hint.brandWatch",
      },
    ],
  },
  {
    id: "inventory",
    labelKey: "nav.group.inventory",
    items: [
      { href: "/assets", labelKey: "nav.assets", icon: Database, hintKey: "nav.hint.assets" },
      {
        href: "/endpoints",
        labelKey: "nav.endpoints",
        icon: Laptop,
        hintKey: "nav.hint.endpoints",
      },
    ],
  },
  {
    id: "scanning",
    labelKey: "nav.group.scanning",
    items: [
      {
        href: "/scans",
        labelKey: "nav.jobs",
        icon: Play,
        minRole: "operator",
        hintKey: "nav.hint.jobs",
      },
      { href: "/runs", labelKey: "nav.runs", icon: FileText, hintKey: "nav.hint.runs" },
      { href: "/operator", labelKey: "nav.operator", icon: Bot, hintKey: "nav.hint.operator" },
      {
        href: "/schedules",
        labelKey: "nav.schedules",
        icon: Timer,
        minRole: "operator",
        hintKey: "nav.hint.schedules",
      },
      {
        // The fleet is operator's; the **Deploy Agent** dialog on the same page
        // mints a provisioning key, which is `tenant.credential.manage` (#504),
        // so a `token-admin` comes here for the dialog alone.
        href: "/agents",
        labelKey: "nav.agents",
        icon: Server,
        anyOf: [{ minRole: "operator" }, { permission: "tenant.credential.manage" }],
        hintKey: "nav.hint.agents",
      },
      {
        href: "/wordlists",
        labelKey: "nav.wordlists",
        icon: Library,
        minRole: "operator",
        hintKey: "nav.hint.wordlists",
      },
      { href: "/reports", labelKey: "nav.reports", icon: BookText, hintKey: "nav.hint.reports" },
    ],
  },
  {
    id: "program",
    labelKey: "nav.group.program",
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
        // `globalMinRole`, not `minRole`: GET /api/auth/tenants resolves its
        // own tenant set from the account and hangs off `require_role`, so a
        // tenant operator whose global role is viewer is answered 403 — and
        // the switcher this page feeds is the platform's, not one tenant's.
        href: "/tenants",
        labelKey: "nav.tenants",
        icon: Users,
        globalMinRole: "operator",
        hintKey: "nav.hint.tenants",
      },
      {
        // Same reason: /api/users is platform account administration, refused
        // to anybody whose *account* is not an admin. Tenant membership is
        // edited from this page too, but the accounts behind it are not.
        href: "/users",
        labelKey: "nav.users",
        icon: UserCog,
        globalMinRole: "admin",
        hintKey: "nav.hint.users",
      },
      {
        // The tenant's own counterpart of /users (#318): its members and the
        // roles it defined, in the tenant the switcher is on. A permission
        // there, not the global role — the tenant admin who holds
        // `tenant.member.read` is globally whatever it is, and gating this on
        // the account's role is exactly how the membership screen used to be
        // the platform admin's alone.
        href: "/access",
        labelKey: "nav.access",
        icon: UserCheck,
        permission: "tenant.member.read",
        hintKey: "nav.hint.access",
      },
      {
        // `audit.read` in the active tenant, the same dependency as
        // GET /api/audit. Showing the door and then rendering 403 was the
        // previous compromise, because the JWT does not carry the tenant role.
        // `/auth/me` now does, as `permissions`.
        href: "/audit",
        labelKey: "nav.audit",
        icon: ScrollText,
        permission: "audit.read",
        hintKey: "nav.hint.audit",
      },
      {
        // A permission in the active tenant (#332): the tenant's admin and
        // auditor hold `tenant.retention.read`, and gating on the global role
        // would hide the page from both of them.
        href: "/retention",
        labelKey: "nav.retention",
        icon: Archive,
        permission: "tenant.retention.read",
        hintKey: "nav.hint.retention",
      },
      {
        href: "/integrations",
        labelKey: "nav.integrations",
        icon: Webhook,
        minRole: "operator",
        hintKey: "nav.hint.integrations",
      },
      {
        // A permission, not `minRole: "admin"`: since #318 the tenant's own
        // admin and a `token-admin` hold `tenant.credential.manage` while
        // their global role is whatever it is, and gating on the global role
        // hid this page from both of them — the one thing docs/ui.md promises
        // it for.
        href: "/service-tokens",
        labelKey: "nav.serviceTokens",
        icon: KeyRound,
        permission: "tenant.credential.manage",
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

/** Whether this principal is shown one entry. Delegates to the one gate in
 * `@/lib/authz`, so the menu and the page behind it cannot disagree. */
export function canSee(item: Requirement, user: Principal): boolean {
  return can(user, item);
}

/** Groups with the entries this principal may see; a group left empty disappears. */
export function visibleNavGroups(user: Principal): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => canSee(item, user)),
  })).filter((group) => group.items.length > 0);
}

/**
 * Pages that used to be their own menu entries. They stay at the old address
 * and light the entry that now owns the question.
 */
const NAV_ALIASES: readonly { prefix: string; href: string }[] = [
  { prefix: "/jobs", href: "/scans" },
  { prefix: "/remediation", href: "/vulnerabilities" },
  { prefix: "/campaigns", href: "/vulnerabilities" },
  { prefix: "/threats", href: "/vulnerabilities" },
  { prefix: "/exposure", href: "/assets" },
  { prefix: "/attack-surface", href: "/runs" },
  { prefix: "/org-profile", href: "/runs" },
  { prefix: "/geo", href: "/runs" },
];

function aliasHref(pathname: string): string | null {
  for (const alias of NAV_ALIASES) {
    if (pathname === alias.prefix || pathname.startsWith(`${alias.prefix}/`)) return alias.href;
  }
  return null;
}

/**
 * The single active entry for a path: the longest href that is the path or
 * one of its ancestors. `/scans/external` therefore lights "Scans" at
 * `/scans`, the only scans entry left in the menu.
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
  if (best === null) return aliasHref(pathname);
  return best;
}
